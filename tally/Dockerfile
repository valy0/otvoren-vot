# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy shared modules (dependencies)
COPY crypto/ crypto/
COPY pkg/ pkg/

# Copy tally module
COPY tally/ tally/

WORKDIR /build/tally
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /tally .

# Runtime stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates
COPY --from=builder /tally /usr/local/bin/tally

EXPOSE 8081

ENTRYPOINT ["tally"]
