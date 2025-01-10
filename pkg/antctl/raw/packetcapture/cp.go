package packetcapture

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path/filepath"
	_ "unsafe"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

func initCoreV1Client(restConfig *rest.Config) (*corev1client.CoreV1Client, error) {
	return corev1client.NewForConfig(restConfig)
}

type podFile struct {
	namespace     string
	name          string
	containerName string

	restConfig *rest.Config
	coreClient *corev1client.CoreV1Client
}

func (i *podFile) copyFromPod(ctx context.Context, srcPath string, destPath string) error {
	reader, outStream := io.Pipe()
	cmdArr := []string{"tar", "cf", "-", srcPath}
	req := i.coreClient.RESTClient().
		Get().
		Namespace(i.namespace).
		Resource("pods").
		Name(i.name).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: i.containerName,
			Command:   cmdArr,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(i.restConfig, "POST", req.URL())
	if err != nil {
		return err
	}
	go func() {
		defer outStream.Close()
		err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdin:  os.Stdin,
			Stdout: outStream,
			Stderr: os.Stderr,
			Tty:    false,
		})
		if err != nil {
			panic(err)
		}
	}()
	err = untarAll(reader)
	return err
}

func untarAll(reader io.Reader) error {
	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		outFile, err := os.Create(filepath.Base(header.Name))
		if err != nil {
			return err
		}
		defer outFile.Close()
		if _, err := io.Copy(outFile, tarReader); err != nil {
			return err
		}
	}
	return nil
}
