package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/linuxchaos/infraseal-cli/internal/config"
)

func TestResolveScanPathsDiscoversTargetConfig(t *testing.T) {
	root := t.TempDir()
	if _, err := config.Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(old); err != nil {
			t.Fatal(err)
		}
	}()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	paths, err := resolveScanPaths(&cobra.Command{}, config.DefaultPath, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, filepath.FromSlash(config.DefaultPath))
	if paths.configPath != want {
		t.Fatalf("configPath = %q, want %q", paths.configPath, want)
	}
	if paths.projectRoot != "" {
		t.Fatalf("projectRoot = %q, want empty because config was discovered", paths.projectRoot)
	}
	if len(paths.targets) != 1 || paths.targets[0] != root {
		t.Fatalf("targets = %#v, want %q", paths.targets, root)
	}
}

func TestResolveScanPathsFallsBackToTargetRoot(t *testing.T) {
	root := t.TempDir()
	paths, err := resolveScanPaths(&cobra.Command{}, config.DefaultPath, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if paths.projectRoot != root {
		t.Fatalf("projectRoot = %q, want %q", paths.projectRoot, root)
	}
	if len(paths.targets) != 1 || paths.targets[0] != root {
		t.Fatalf("targets = %#v, want %q", paths.targets, root)
	}
}

func TestResolveScanPathsResolvesTargetsFromExplicitConfigRoot(t *testing.T) {
	root := t.TempDir()
	if _, err := config.Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(old); err != nil {
			t.Fatal(err)
		}
	}()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, filepath.FromSlash(config.DefaultPath))
	paths, err := resolveScanPaths(&cobra.Command{}, configPath, []string{"app"})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "app")
	if len(paths.targets) != 1 || paths.targets[0] != want {
		t.Fatalf("targets = %#v, want %q", paths.targets, want)
	}
}
