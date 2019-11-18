module go.kubeshield.dev/bpf-opa-demo

go 1.12

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/fatih/color v1.7.0 // indirect
	github.com/hokaccha/go-prettyjson v0.0.0-20190818114111-108c894c2c0e // indirect
	github.com/iovisor/gobpf v0.0.0-20190717135640-14e20c7d794b
	github.com/mattn/go-colorable v0.1.4 // indirect
	github.com/mattn/go-isatty v0.0.10 // indirect
	github.com/pkg/errors v0.8.1
	github.com/prometheus/procfs v0.0.5
	github.com/the-redback/go-oneliners v0.0.0-20190417084731-74f7694e6dae
	k8s.io/klog v0.4.0
)

replace github.com/iovisor/gobpf => github.com/kubeshield/gobpf v0.0.0-20191118042735-39e19283713a
