# Syscall

The code from Package syscall is used for wrapping syscall functions from different platforms that the standard syscall library does not provide.

Steps to produce files in the directory:

1. Clone the repo  [golang/sys](https://github.com/golang/sys/) and put your types and const definitions in the `linux/types.go`.
2. Run `GOOS=linux GOARCH=amd64 ./mkall.sh` from [golang/sys/internal-branch.go1.17-vendor](https://github.com/golang/sys/tree/internal-branch.go1.17-vendor).
   Don't worry about `GOARCH`, it will generate the required files for all possible Linux architectures.
3. Copy the generated code `ztypes_linux.go` and hand-writing code `types.go` to this directory.
4. Add your syscall functions in `syscall_unix.go`.
