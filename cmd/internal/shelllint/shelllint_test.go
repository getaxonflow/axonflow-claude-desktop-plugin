// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package shelllint

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// expectLines returns the line numbers marked "# EXPECT" in code (not in a
// whole-line comment).
func expectLines(t *testing.T, path string) []int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []int
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		text := sc.Text()
		if strings.Contains(text, "# EXPECT") && !strings.HasPrefix(strings.TrimSpace(text), "#") {
			lines = append(lines, n)
		}
	}
	return lines
}

func findingLinesOf(res Result) []int {
	var out []int
	for _, f := range res.Findings {
		out = append(out, f.Line)
	}
	return out
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSpellings_EachReportedOnceAtItsLine(t *testing.T) {
	path := filepath.Join("testdata", "positive", "spellings.sh")
	want := expectLines(t, path)
	if len(want) < 10 {
		t.Fatalf("the spellings fixture marks only %d EXPECT lines", len(want))
	}
	res, err := Scan(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := findingLinesOf(res); !equalInts(got, want) {
		t.Fatalf("findings at %v, want exactly %v\n%+v", got, want, res.Findings)
	}
}

func TestControls(t *testing.T) {
	cases := []struct {
		dir          string
		wantInScope  int
		wantFindings []string // "file:line" suffixes
	}{
		{"suite", 1, nil},
		{"no-pipefail", 0, nil},
		{"lib", 1, []string{"helper.sh:6"}},
		{"sourced", 2, []string{"helpers.sh:5"}},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			res, err := Scan(filepath.Join("testdata", "control", tc.dir))
			if err != nil {
				t.Fatal(err)
			}
			if len(res.InScope) != tc.wantInScope {
				t.Fatalf("in scope %v, want %d", res.InScope, tc.wantInScope)
			}
			if len(res.Findings) != len(tc.wantFindings) {
				t.Fatalf("findings %+v, want %v", res.Findings, tc.wantFindings)
			}
			for i, f := range res.Findings {
				got := filepath.Base(f.File) + ":" + itoa(f.Line)
				if got != tc.wantFindings[i] {
					t.Fatalf("finding %d = %s, want %s", i, got, tc.wantFindings[i])
				}
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A planted `producer | grep -q` in an otherwise clean pipefail script is
// reported: the scanner that passes the real tree is one that can fail.
func TestPlantedPositive(t *testing.T) {
	dir := t.TempDir()
	script := "#!/usr/bin/env bash\nset -euo pipefail\nV=x\nif docker ps | grep -q axonflow; then :; fi\n"
	if err := os.WriteFile(filepath.Join(dir, "planted.sh"), []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Line != 4 {
		t.Fatalf("planted grep -q not reported at line 4: %+v", res.Findings)
	}
}

// The repository's own shell: every script in scope, and no finding.
func TestRepositoryShellHasNoGrepQUnderPipefail(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(here), "..", "..", "..")
	var roots []string
	for _, r := range []string{"build.sh", "scripts", "runtime-e2e"} {
		p := filepath.Join(root, r)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("scan root missing: %s (a missing root is not a clean root)", p)
		}
		roots = append(roots, p)
	}
	res, err := Scan(roots...)
	if err != nil {
		t.Fatal(err)
	}
	// Census floor: build.sh, scripts/validate-version-alignment.sh,
	// runtime-e2e/run.sh and the three cli-harness scripts set pipefail.
	if len(res.InScope) < 6 {
		t.Fatalf("only %d scripts in scope (%v); a scanner that reads nothing cannot pass", len(res.InScope), res.InScope)
	}
	for _, f := range res.Findings {
		t.Errorf("%s:%d: %s", f.File, f.Line, f.Text)
	}
}
