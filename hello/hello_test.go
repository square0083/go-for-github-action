package hello

import "testing"

func TestGreet(t *testing.T) {
	result := Greet()
	if result != "Hello Github Actions" {
		t.Errorf("Greet() = %s; Expected Hello Github actions", result)
	}
}
