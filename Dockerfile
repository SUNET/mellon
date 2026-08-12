FROM golang:1.26.5 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mellon ./cmd/mellon

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /mellon /mellon

EXPOSE 8080 8443
ENTRYPOINT ["/mellon"]
