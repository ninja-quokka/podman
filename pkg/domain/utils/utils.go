package utils

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/containers/podman/v5/pkg/domain/entities"
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// DeepCopy does a deep copy of a structure
// Error checking of parameters delegated to json engine
var DeepCopy = func(dst interface{}, src interface{}) error {
	payload, err := json.Marshal(src)
	if err != nil {
		return err
	}

	err = json.Unmarshal(payload, dst)
	if err != nil {
		return err
	}
	return nil
}

func ToLibpodFilters(f url.Values) (filters []string) {
	for k, v := range f {
		filters = append(filters, k+"="+v[0])
	}
	return
}

func ToURLValues(f []string) (filters url.Values) {
	filters = make(url.Values)
	for _, v := range f {
		key, val, _ := strings.Cut(v, "=")
		filters.Add(key, val)
	}
	return
}

// ParseAnnotations takes a string slice of options, expected to be "key=val" and returns
// a string map where the map index is the key and points to the value
func ParseAnnotations(options []string) (map[string]string, error) {
	annotations := make(map[string]string)
	for _, annotationSpec := range options {
		key, val, hasVal := strings.Cut(annotationSpec, "=")
		if !hasVal {
			return nil, fmt.Errorf("no value given for annotation %q", key)
		}
		annotations[key] = val
	}
	return annotations, nil
}

// ParseBlobs takes a string slice of paths to blobs, validates them and
// returns a list of ArtifactBlobs which contain the io.Reader of the blob
// and the filename.
// WARNING: Files closing is not handled by this function
func ParseBlobs(blobPaths []string) ([]entities.ArtifactBlob, error) {
	artifactBlobs := make([]entities.ArtifactBlob, 0, len(blobPaths))

	for _, blobPath := range blobPaths {
		b, err := os.Open(blobPath)
		if err != nil {
			return nil, fmt.Errorf("error opening path %s: %w", blobPath, err)
		}

		artifactBlob := entities.ArtifactBlob{
			Blob:     b,
			Filename: filepath.Base(blobPath),
		}
		artifactBlobs = append(artifactBlobs, artifactBlob)
	}

	return artifactBlobs, nil
}
