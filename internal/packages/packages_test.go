package packages

import (
	"slices"
	"testing"
)

func TestResolve(t *testing.T) {
	p, err := Resolve([]string{"docker", "rust"}, []string{"python", "git"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"base", "openssh", "git", "cronie", "docker", "rustup", "python"} {
		if !slices.Contains(p.Packages, want) {
			t.Errorf("missing package %s", want)
		}
	}
	for _, not := range []string{"go", "neovim", "clang"} {
		if slices.Contains(p.Packages, not) {
			t.Errorf("unselected package %s included", not)
		}
	}
	if n := count(p.Packages, "git"); n != 1 {
		t.Errorf("git listed %d times", n)
	}
	for _, s := range []string{"sshd", "cronie", "docker"} {
		if !slices.Contains(p.Services, s) {
			t.Errorf("missing service %s", s)
		}
	}
	if !slices.Equal(p.Groups, []string{"docker"}) {
		t.Errorf("groups = %v", p.Groups)
	}
	if !slices.Equal(p.UserCommands, []string{"rustup default stable"}) {
		t.Errorf("user commands = %v", p.UserCommands)
	}
}

func TestResolveRejects(t *testing.T) {
	if _, err := Resolve([]string{"cobol"}, nil); err == nil {
		t.Error("unknown tool accepted")
	}
	if _, err := Resolve(nil, []string{"rm -rf /"}); err == nil {
		t.Error("bad package name accepted")
	}
}

func TestSortTools(t *testing.T) {
	got := SortTools([]string{"neovim", "docker", "go"})
	if !slices.Equal(got, []string{"docker", "go", "neovim"}) {
		t.Fatalf("got %v", got)
	}
}

func count(list []string, s string) int {
	n := 0
	for _, x := range list {
		if x == s {
			n++
		}
	}
	return n
}
