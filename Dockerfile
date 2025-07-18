FROM golang:1.24-alpine AS builder
WORKDIR /app


COPY ./ ./
RUN go mod download

RUN go build -o /offa github.com/go-oidfed/offa

FROM debian:stable
RUN apt-get update && apt-get install -y ca-certificates && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

COPY --from=builder /offa .

CMD bash -c "update-ca-certificates && /offa"
