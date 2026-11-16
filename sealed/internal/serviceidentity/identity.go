// Package serviceidentity reserves identities inside the provider's 65536-ID
// user-namespace mapping for sealed's service processes only. Every sandbox on
// a runner shares that mapping, and the kernel counts RLIMIT_NPROC per UID
// across all of them (measured on the dev runner, 2026-11-13). sealed therefore
// draws each identity at random from this range instead of fixed slots, so
// sandboxes rarely meet on one count, and no service can choose to.
package serviceidentity

const (
	Base  = 20000
	Count = 45000 // 20000..64999: clear of the agent account and of nobody (65534)
	// Probe is the identity of sealed's confinement probe. Tasks never draw
	// it, so reaping a task's identity cannot kill a running probe.
	Probe = Base
)

// Draw maps a random number onto the task identities, Base+1..Base+Count-1.
func Draw(r uint32) uint32 {
	return Base + 1 + r%(Count-1)
}

func Valid(uid int) bool {
	return uid >= Base && uid < Base+Count
}
