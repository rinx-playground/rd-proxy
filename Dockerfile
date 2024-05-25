FROM golang:1.22 AS builder

ENV ORG rinx
ENV REPO rd-proxy

WORKDIR ${GOPATH}/src/github.com/${ORG}/${REPO}
COPY go.mod .
COPY go.sum .

WORKDIR ${GOPATH}/src/github.com/${ORG}/${REPO}/cmd
COPY cmd .

WORKDIR ${GOPATH}/src/github.com/${ORG}/${REPO}/pkg
COPY pkg .

WORKDIR ${GOPATH}/src/github.com/${ORG}/${REPO}

ENV CGO_ENABLED=0
RUN go build -o /proxy ./cmd/proxy/main.go

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /proxy /proxy

ENTRYPOINT ["/proxy"]
CMD ["proxy"]
