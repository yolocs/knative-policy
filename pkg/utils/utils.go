package utils

import (
	"context"
	"fmt"
	"io/ioutil"
	"time"

	"knative.dev/pkg/logging"
)

type applyDataFunc func([]byte) error

type FileCache struct {
	filePath        string
	refreshInterval time.Duration
	applyFunc       applyDataFunc
}

func NewFileCache(filePath string, refreshInterval time.Duration, applyFunc applyDataFunc) (*FileCache, error) {
	fc := &FileCache{filePath: filePath, refreshInterval: refreshInterval, applyFunc: applyFunc}
	if err := fc.load(); err != nil {
		return nil, err
	}
	return fc, nil
}

func (fc *FileCache) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-time.After(fc.refreshInterval):
				if err := fc.load(); err != nil {
					logging.FromContext(ctx).Errorf("%v", err)
				} else {
					logging.FromContext(ctx).Debugf("file %q refreshed", fc.filePath)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (fc *FileCache) load() error {
	b, err := ioutil.ReadFile(fc.filePath)
	if err != nil {
		return fmt.Errorf("failed to refresh file %q: %w", fc.filePath, err)
	}

	if err := fc.applyFunc(b); err != nil {
		return fmt.Errorf("failed to apply data from file %q: %w", fc.filePath, err)
	}

	return nil
}
