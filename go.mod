module github.com/appscode-cloud/bpf-opa-demo

go 1.12

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/iovisor/gobpf v0.0.0-20190717135640-14e20c7d794b
)

replace github.com/iovisor/gobpf => github.com/tahsinrahman/gobpf v0.0.0-20190828103435-4226291af08b
