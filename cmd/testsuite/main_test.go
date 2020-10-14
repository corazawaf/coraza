package main

import (
	"testing"
)

func TestYaml(t *testing.T) {
	files, err := getYamlFromDir("../../test/data/engine/")
	if len(files) == 0 || err != nil {
		t.Error("Failed to load yaml files")
	}
}
