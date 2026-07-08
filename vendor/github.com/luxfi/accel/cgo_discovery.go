// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package accel

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Provenance reports how the GPU substrate (libluxgpu*.a and the
// lux/gpu/*.h headers) was located at build / runtime. It exists for
// debugging "which install am I using" questions — the accel CGO
// directives in ops/code/code_cpu.go enumerate every standard prefix,
// so the actual compiler search resolves silently. This type lets
// callers see what the same search WOULD find if they re-ran it.
type Provenance struct{}

// Source identifies how a path was resolved.
type Source string

const (
	// SourceEnv: explicit LUX_GPU_PREFIX (or back-compat LUX_MLX_PREFIX)
	// environment variable.
	SourceEnv Source = "env-prefix"

	// SourceCgoEnv: CGO_CFLAGS / CGO_LDFLAGS supplied at build time.
	// Only detectable via the live environment; reported when the
	// variables are non-empty at the call time of GPUPaths().
	SourceCgoEnv Source = "cgo-env"

	// SourcePkgConfig: pkg-config reports a `lux-gpu` package.
	// Detected by running `pkg-config --variable=prefix lux-gpu`.
	SourcePkgConfig Source = "pkg-config"

	// SourceHomebrewARM: /opt/homebrew (Apple Silicon).
	SourceHomebrewARM Source = "homebrew-arm"

	// SourceHomebrewKeg: /opt/homebrew/opt/lux-gpu (keg-only formula).
	SourceHomebrewKeg Source = "homebrew-keg"

	// SourceHomebrewIntel: /usr/local/opt/lux-gpu (Intel Mac Homebrew).
	SourceHomebrewIntel Source = "homebrew-intel"

	// SourceSystem: /usr/local install (canonical POSIX).
	SourceSystem Source = "system"

	// SourceLuxPrefix: /opt/lux install (Lux canonical prefix).
	SourceLuxPrefix Source = "lux-prefix"

	// SourceModuleRelative: ${SRCDIR}/../../../mlx/{include,build} —
	// in-tree dev fallback, only valid when accel is in a Go workspace
	// next to luxfi/mlx (NOT when accel is in the Go module cache).
	SourceModuleRelative Source = "module-relative"

	// SourceMissing: no candidate prefix on this host has the headers
	// or the library. cgo builds will fail to link unless the caller
	// provides CGO_CFLAGS/CGO_LDFLAGS at build time.
	SourceMissing Source = "missing"
)

// PathReport names the resolved GPU substrate location.
type PathReport struct {
	// IncludeDir is the path that contains `lux/gpu/hqc.h`.
	IncludeDir string

	// LibDir is the path that contains `libluxgpu_hqc.a` (or `.so`
	// / `.dylib` for shared installs).
	LibDir string

	// Library is the static library file the linker would use.
	// Empty when SourceMissing.
	Library string

	// Source tags which prefix in the fallback chain resolved.
	Source Source

	// Candidates lists every prefix that was probed, in order. The
	// first entry whose include + lib are both present is the
	// resolved one; callers can show this slice in diagnostics to
	// explain why a particular install was chosen.
	Candidates []Candidate
}

// Candidate is one entry in the discovery search list.
type Candidate struct {
	Source     Source
	IncludeDir string
	LibDir     string
	IncludeOK  bool // true if hqc.h is readable at IncludeDir/lux/gpu/hqc.h
	LibOK      bool // true if libluxgpu_hqc.a is readable at LibDir
}

// GPUPaths returns the resolved GPU substrate location for this host.
// It probes every fallback prefix the cgo build also probes, in the
// same priority order, and returns the first one that has BOTH the
// header and the static library.
//
// Returns a PathReport with Source = SourceMissing (and Candidates
// populated for diagnostics) when no install can be found. Callers
// that need a hard error can check Library == "" or Source == SourceMissing.
func (Provenance) GPUPaths() PathReport {
	candidates := buildCandidates()
	for i := range candidates {
		c := &candidates[i]
		c.IncludeOK = fileExists(filepath.Join(c.IncludeDir, "lux", "gpu", "hqc.h"))
		c.LibOK = fileExists(filepath.Join(c.LibDir, staticLibName()))
		if c.IncludeOK && c.LibOK {
			return PathReport{
				IncludeDir: c.IncludeDir,
				LibDir:     c.LibDir,
				Library:    filepath.Join(c.LibDir, staticLibName()),
				Source:     c.Source,
				Candidates: candidates,
			}
		}
	}
	return PathReport{
		Source:     SourceMissing,
		Candidates: candidates,
	}
}

// GPUPaths is a package-level convenience that calls Provenance{}.GPUPaths().
func GPUPaths() PathReport {
	return Provenance{}.GPUPaths()
}

// staticLibName returns the canonical filename for the HQC static
// library on the current platform. POSIX uses libluxgpu_hqc.a;
// Windows would use luxgpu_hqc.lib, but Windows is not a supported
// target for the cgo build path today.
func staticLibName() string {
	if runtime.GOOS == "windows" {
		return "luxgpu_hqc.lib"
	}
	return "libluxgpu_hqc.a"
}

// buildCandidates assembles the discovery list. Order MUST match the
// fallback chain in ops/code/code_cpu.go so the documented behaviour
// is faithful.
func buildCandidates() []Candidate {
	out := make([]Candidate, 0, 16)

	// 1. Env var override.
	if prefix := envPrefix(); prefix != "" {
		out = append(out, Candidate{
			Source:     SourceEnv,
			IncludeDir: filepath.Join(prefix, "include"),
			LibDir:     filepath.Join(prefix, "lib"),
		})
		// Also probe `prefix/build` to support an unbundled checkout
		// (cmake build dir = library dir, source/include = headers).
		out = append(out, Candidate{
			Source:     SourceEnv,
			IncludeDir: filepath.Join(prefix, "include"),
			LibDir:     filepath.Join(prefix, "build"),
		})
	}

	// 2. CGO_CFLAGS / CGO_LDFLAGS at runtime (informational; cgo also
	// honors these at build time, this entry just exposes what's
	// CURRENTLY in env so debugging shows it).
	if cflags := strings.TrimSpace(os.Getenv("CGO_CFLAGS")); cflags != "" {
		if inc := firstFlagPath(cflags, "-I"); inc != "" {
			ldflags := strings.TrimSpace(os.Getenv("CGO_LDFLAGS"))
			out = append(out, Candidate{
				Source:     SourceCgoEnv,
				IncludeDir: inc,
				LibDir:     firstFlagPath(ldflags, "-L"),
			})
		}
	}

	// 3. pkg-config discovery — runs the binary and parses output.
	if pc := pkgConfigLookup(); pc.IncludeDir != "" {
		out = append(out, pc)
	}

	// 4-7. Standard prefixes.
	out = append(out,
		Candidate{
			Source:     SourceHomebrewKeg,
			IncludeDir: "/opt/homebrew/opt/lux-gpu/include",
			LibDir:     "/opt/homebrew/opt/lux-gpu/lib",
		},
		Candidate{
			Source:     SourceHomebrewIntel,
			IncludeDir: "/usr/local/opt/lux-gpu/include",
			LibDir:     "/usr/local/opt/lux-gpu/lib",
		},
		Candidate{
			Source:     SourceHomebrewARM,
			IncludeDir: "/opt/homebrew/include",
			LibDir:     "/opt/homebrew/lib",
		},
		Candidate{
			Source:     SourceSystem,
			IncludeDir: "/usr/local/include",
			LibDir:     "/usr/local/lib",
		},
		Candidate{
			Source:     SourceLuxPrefix,
			IncludeDir: "/opt/lux/include",
			LibDir:     "/opt/lux/lib",
		},
	)

	// 8. Module-relative fallback — only resolves outside the Go
	// module cache (i.e. in a workspace next to luxfi/mlx).
	//
	// cgo_discovery.go lives at the root of github.com/luxfi/accel,
	// and luxfi/mlx is a SIBLING repo, so the path is `../mlx`. The
	// equivalent in ops/code/code_cpu.go is `../../../mlx`. Both
	// resolve to the same on-disk directory in the canonical dev
	// layout.
	if srcDir, ok := packageSrcDir(); ok {
		mlxRoot := filepath.Join(srcDir, "..", "mlx")
		out = append(out, Candidate{
			Source:     SourceModuleRelative,
			IncludeDir: filepath.Join(mlxRoot, "include"),
			LibDir:     filepath.Join(mlxRoot, "build"),
		})
	}

	return out
}

// envPrefix returns the override prefix from LUX_GPU_PREFIX (or the
// back-compat LUX_MLX_PREFIX). Returns "" when neither is set.
func envPrefix() string {
	if v := strings.TrimSpace(os.Getenv("LUX_GPU_PREFIX")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("LUX_MLX_PREFIX")); v != "" {
		return v
	}
	return ""
}

// firstFlagPath extracts the first `-X<path>` (e.g. `-I/foo` or
// `-L/bar`) from a space-separated flag string.
func firstFlagPath(flags, prefix string) string {
	for _, tok := range strings.Fields(flags) {
		if strings.HasPrefix(tok, prefix) {
			return strings.TrimPrefix(tok, prefix)
		}
	}
	return ""
}

// fileExists reports whether the given path can be stat'd as a
// regular file or symlink target (i.e. a header or library we can
// actually open).
func fileExists(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !st.IsDir()
}

// packageSrcDir returns the directory of THIS source file, used as
// the anchor for the module-relative fallback. It mirrors how cgo
// resolves ${SRCDIR} so the Go discovery matches the C build.
//
// Returns ("", false) when the caller's frame can't be determined
// (e.g. in a stripped binary or unusual runtime layout).
func packageSrcDir() (string, bool) {
	_, file, _, ok := runtime.Caller(0)
	if !ok || file == "" {
		return "", false
	}
	return filepath.Dir(file), true
}

// pkgConfigLookup queries pkg-config for the `lux-gpu` package and
// returns a Candidate with the resolved include/lib dirs. Returns a
// zero Candidate (IncludeDir == "") when pkg-config is unavailable
// or doesn't know about lux-gpu — callers skip such entries.
//
// Honours PKG_CONFIG_PATH from env, so users with non-standard
// install prefixes (CMAKE_INSTALL_PREFIX=/foo) can extend search via
// PKG_CONFIG_PATH=/foo/lib/pkgconfig:$PKG_CONFIG_PATH.
func pkgConfigLookup() Candidate {
	out, err := exec.Command("pkg-config", "--cflags", "--libs", "lux-gpu").Output()
	if err != nil {
		return Candidate{}
	}
	c := Candidate{Source: SourcePkgConfig}
	for _, tok := range strings.Fields(string(out)) {
		switch {
		case strings.HasPrefix(tok, "-I"):
			if c.IncludeDir == "" {
				c.IncludeDir = strings.TrimPrefix(tok, "-I")
			}
		case strings.HasPrefix(tok, "-L"):
			if c.LibDir == "" {
				c.LibDir = strings.TrimPrefix(tok, "-L")
			}
		}
	}
	return c
}
