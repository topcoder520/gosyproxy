FROM golang:alpine as build

WORKDIR /github.com/topcoder520/gosyproxy

COPY . /github.com/topcoder520/gosyproxy/

RUN go build -o gosyproxy ./cmd/main.go

FROM golang:alpine

WORKDIR /work

COPY --from=build /github.com/topcoder520/gosyproxy/gosyproxy /work/

EXPOSE 8888

ENTRYPOINT ./gosyproxy -L :8888 -P http://admin:123456@192.168.2.10:8889
#ENTRYPOINT ./gosyproxy -L admin:123456@localhost:8889
# ENTRYPOINT ./gosyproxy -L admin:123456@localhost:8889 -P http://admin:123456@127.0.0.1:8890
#ENTRYPOINT ./gosyproxy -L admin:123456@localhost:8890


