package framework

import (
	"reflect"
	"strings"
	"testing"
)

// Every Cred* field startCredentials fills reaches the adapters: a field
// added to RuntimeContext and not to WithCredentials fails here (the
// inference key once stayed with the framework that way).
func TestWithCredentialsCopiesEveryCredField(t *testing.T) {
	var c RuntimeContext
	cv := reflect.ValueOf(&c).Elem()
	held := false
	for i := 0; i < cv.NumField(); i++ {
		f := cv.Type().Field(i)
		if !strings.HasPrefix(f.Name, "Cred") {
			continue
		}
		switch f.Type.Kind() {
		case reflect.String:
			cv.Field(i).SetString("set-" + f.Name)
		case reflect.Func:
			cv.Field(i).Set(reflect.ValueOf(func(string, string, map[string]string, []byte) (string, string, error) {
				held = true
				return "", "", nil
			}))
		default:
			t.Fatalf("field %s of kind %s: teach this test how to set it", f.Name, f.Type.Kind())
		}
	}
	got := RuntimeContext{AgentID: "7"}.WithCredentials(c)
	gv := reflect.ValueOf(got)
	for i := 0; i < gv.NumField(); i++ {
		f := gv.Type().Field(i)
		if !strings.HasPrefix(f.Name, "Cred") {
			continue
		}
		switch f.Type.Kind() {
		case reflect.String:
			if gv.Field(i).String() != "set-"+f.Name {
				t.Errorf("%s not copied", f.Name)
			}
		case reflect.Func:
			if gv.Field(i).IsNil() {
				t.Errorf("%s not copied", f.Name)
			}
		}
	}
	if got.AgentID != "7" {
		t.Fatal("WithCredentials changed a field it does not own")
	}
	if _, _, _ = got.CredHold("x", "https://a.example", nil, nil); !held {
		t.Fatal("CredHold is not the one passed in")
	}
}
