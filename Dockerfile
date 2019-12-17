FROM ubuntu:18.04

COPY bpf-opa-demo /bin/bpf-opa-demo

ENTRYPOINT /bin/bpf-opa-demo
