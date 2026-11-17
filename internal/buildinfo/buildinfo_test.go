package buildinfo

import "testing"

func TestGetUsesLinkTimeValues(t *testing.T) {
	Version, Commit, Date = "1.2.3", "abc", "2026-01-01T00:00:00Z"
	t.Cleanup(func() { Version, Commit, Date = "", "", "" })
	got := Get()
	if got.Version != "1.2.3" || got.Commit != "abc" || got.BuildDate != "2026-01-01T00:00:00Z" {
		t.Errorf("Get() = %+v", got)
	}
	if got.GoVersion == "" || got.OS == "" || got.Arch == "" {
		t.Errorf("platform fields missing: %+v", got)
	}
}

func TestGetFallsBackToDev(t *testing.T) {
	Version = ""
	if got := Get().Version; got == "" {
		t.Error("Version must never be empty")
	}
}
