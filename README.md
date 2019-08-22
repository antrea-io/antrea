# OKN

## Building and testing

The OKN project uses the [Go modules
support](https://github.com/golang/go/wiki/Modules) which was introduced in Go
1.11. It facilitates dependency tracking and no longer requires projects to live
inside the `$GOPATH`.

To develop locally, you can follow these steps:

 1. [Install Go 1.12](https://golang.org/doc/install)

 2. Clone this repository anywhere on your machine and `cd` into it

 3. To build all Go files and install them under `bin`, run `make dev`

 4. To run all Go unit tests, run `make test-unit`
