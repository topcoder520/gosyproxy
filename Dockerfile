FROM golang:alpine as build

WORKDIR /github.com/topcoder520/gosyproxy

COPY . /github.com/topcoder520/gosyproxy/

RUN go build -o gosyproxy ./cmd/main.go

FROM golang:alpine

ENV PORT=8888

WORKDIR /work

COPY --from=build /github.com/topcoder520/gosyproxy/gosyproxy /work/

EXPOSE 8888

ENTRYPOINT ./gosyproxy -p 8888 -log


