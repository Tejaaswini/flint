package trace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"flint/engine/session"
)

type TraceFile struct {
	Name        string                `json:"name"`
	Description string                `json:"description"`
	SessionID   string                `json:"session_id"`
	Events      []session.SessionEvent `json:"events"`
}

func Load(path string) (TraceFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TraceFile{}, err
	}
	var tf TraceFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return TraceFile{}, err
	}
	return tf, nil
}

func LoadDir(dir string) ([]TraceFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	var traces []TraceFile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		tf, err := Load(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", entry.Name(), err)
		}
		traces = append(traces, tf)
	}

	if len(traces) == 0 {
		return nil, fmt.Errorf("no .json files found in %s", dir)
	}
	return traces, nil
}
