package build

import (
	"archive/tar"
	"compress/gzip"
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:generate go run ../../cmd/gen-build-assets

//go:embed build_assets.tar.gz
var buildAssetsTarGz []byte

// extractBuildAssets extracts the embedded build assets archive to dstDir.
// Creates subdirectories: wazero/, hostmod/, runtime/, names/, and go.sum.
func extractBuildAssets(dstDir string) error {
	gr, err := gzip.NewReader(bytes.NewReader(buildAssetsTarGz))
	if err != nil {
		return fmt.Errorf("opening gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		dst := filepath.Join(dstDir, filepath.FromSlash(hdr.Name))
		if !strings.HasPrefix(filepath.Clean(dst)+string(os.PathSeparator), filepath.Clean(dstDir)+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry %q would escape destination directory", hdr.Name)
		}

		// Ensure parent directory exists.
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return fmt.Errorf("creating dir for %s: %w", hdr.Name, err)
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("reading %s: %w", hdr.Name, err)
		}

		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", hdr.Name, err)
		}
	}
	return nil
}
