package inference

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"seal-verify/internal/attestorhttp"
)

// RouteHash binds the credential to the recipient, independently of mutable
// model metadata. This fixed field order also lives in SDK Providers.ts.
func (r *Registry) RouteHash(id string) (string, error) {
	p, ok := r.providers[id]
	if !ok {
		return "", fmt.Errorf("UNSUPPORTED_INFERENCE_PROVIDER: %q", id)
	}
	formats := make([]string, len(p.Formats))
	for i, f := range p.Formats {
		formats[i] = string(f)
	}
	sort.Strings(formats)
	native := "0"
	if p.Native {
		native = "1"
	}
	preimage := strings.Join([]string{"AgentDNA.InferenceRoute.v1", p.ID, native,
		strings.Join(formats, ","), string(p.DefaultFormat), p.Endpoints[WireOpenAI], p.Endpoints[WireAnthropic], ""}, "\n")
	sum := sha256.Sum256([]byte(preimage))
	return "0x" + hex.EncodeToString(sum[:]), nil
}

func fetchRegistryJSON(ctx context.Context, client *http.Client, address string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("provider registry HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (512<<10)+1))
	if err != nil {
		return err
	}
	if len(body) > 512<<10 {
		return fmt.Errorf("provider registry too large")
	}
	return json.Unmarshal(body, out)
}

// LoadRemoteRegistry discovers the latest accepted registry. New credentials
// authorize a specific version; running containers use LoadPinnedRegistry.
func LoadRemoteRegistry(ctx context.Context, base string, chainID uint64, contract string) (*Registry, error) {
	return loadRegistry(ctx, base, chainID, contract, nil)
}

// LoadPinnedRegistry reads the historical version authorized by the owner,
// including after stop/start or a publication between signing and first boot.
// Failure never substitutes the latest registry or a different endpoint.
func LoadPinnedRegistry(ctx context.Context, base string, chainID uint64, contract string, credential ProviderCredential) (*Registry, error) {
	if credential.Registry == nil || credential.Registry.Version < 0 || credential.RouteHash == "" {
		return nil, fmt.Errorf("missing credential registry binding")
	}
	r, err := loadRegistry(ctx, base, chainID, contract, credential.Registry)
	if err != nil {
		return nil, err
	}
	hash, err := r.RouteHash(credential.Provider)
	if err != nil {
		return nil, err
	}
	if hash != credential.RouteHash {
		return nil, fmt.Errorf("CREDENTIAL_ROUTE_MISMATCH: pinned registry does not match the authorized route")
	}
	return r, nil
}

func loadRegistry(ctx context.Context, base string, chainID uint64, contract string, pin *RegistryPin) (*Registry, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	base = strings.TrimRight(base, "/")
	var config struct {
		AppID        string `json:"attestor_app_id"`
		TappRegistry string `json:"tapp_registry_addr"`
		Schema       int    `json:"provider_registry_schema"`
		Version      int64  `json:"provider_registry_version"`
		Digest       string `json:"provider_registry_digest"`
	}
	client, err := attestorhttp.Client(base)
	if err != nil {
		return nil, fmt.Errorf("provider registry attestor client: %w", err)
	}
	if err := fetchRegistryJSON(ctx, client, base+"/config", &config); err != nil {
		return nil, err
	}
	if config.Schema != 1 {
		return nil, fmt.Errorf("dynamic provider registry unavailable")
	}
	version, digest := config.Version, config.Digest
	address := base + "/inference/providers"
	if pin != nil {
		if config.Version < pin.Version {
			return nil, fmt.Errorf("provider registry is older than the authorized version")
		}
		version, digest = pin.Version, pin.Digest
		address = fmt.Sprintf("%s?version=%d", address, version)
	}
	var snapshot struct {
		Version   int64           `json:"version"`
		Providers json.RawMessage `json:"providers"`
		Document  string          `json:"document"`
		Signature string          `json:"signature"`
	}
	if err := fetchRegistryJSON(ctx, client, address, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Version != version {
		return nil, fmt.Errorf("provider registry version mismatch")
	}
	if snapshot.Version == 0 {
		var got, builtin any
		if json.Unmarshal(snapshot.Providers, &got) != nil || json.Unmarshal(providerDefinitions, &builtin) != nil || !reflect.DeepEqual(got, builtin) {
			return nil, fmt.Errorf("unsigned provider registry differs from built-in definitions")
		}
		return NewRegistry(snapshot.Providers)
	}
	var document struct {
		AppID        string          `json:"attestor_app_id"`
		TappRegistry string          `json:"tapp_registry_addr"`
		Schema       int             `json:"schema"`
		ChainID      uint64          `json:"chain_id"`
		Contract     string          `json:"agentic_id_addr"`
		BaseVersion  int64           `json:"base_version"`
		Providers    json.RawMessage `json:"providers"`
	}
	if len(snapshot.Document) > 256<<10 || json.Unmarshal([]byte(snapshot.Document), &document) != nil {
		return nil, fmt.Errorf("invalid signed provider document")
	}
	if document.Schema != 1 || document.BaseVersion < 0 || snapshot.Version <= 0 || document.BaseVersion != snapshot.Version-1 ||
		document.ChainID != chainID || document.AppID != config.AppID ||
		!common.IsHexAddress(config.TappRegistry) || !common.IsHexAddress(document.TappRegistry) ||
		common.HexToAddress(config.TappRegistry) != common.HexToAddress(document.TappRegistry) || !common.IsHexAddress(contract) || !common.IsHexAddress(document.Contract) ||
		common.HexToAddress(document.Contract) != common.HexToAddress(contract) {
		return nil, fmt.Errorf("provider registry environment/version mismatch")
	}
	documentHash := sha256.Sum256([]byte(snapshot.Document))
	accepted := fmt.Sprintf("AgentDNA.ProviderRegistryAccepted.v1:%x:%s", documentHash, snapshot.Signature)
	actualDigest := sha256.Sum256([]byte(accepted))
	if "0x"+hex.EncodeToString(actualDigest[:]) != strings.ToLower(digest) {
		return nil, fmt.Errorf("provider registry acceptance digest mismatch")
	}
	// Use the exact signed definitions, never a separate unsigned providers field.
	return NewRegistry(document.Providers)
}
