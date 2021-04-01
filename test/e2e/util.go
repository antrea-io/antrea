package e2e

import (
	"io"
	"os"
	"time"

	"k8s.io/klog"
)

// IsDirEmpty checks whether a directory is empty or not.
func IsDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

func timeCost() func(string) {
	start := time.Now()
	return func(status string) {
		tc := time.Since(start)
		klog.Infof("Confirming %s status costs %v", status, tc)
	}
}
