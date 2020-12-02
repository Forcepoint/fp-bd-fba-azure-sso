FROM golang:alpine as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor  -a -installsuffix cgo -ldflags '-extldflags "-static"' -o azure-fba .
FROM scratch
FROM microsoft/azure-cli
COPY --from=builder /build/azure-fba $GOPATH/bin
WORKDIR /app
CMD ["azure-fba", "run", "--config", "/app/configs/config.yml"]
