# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy crypto module first (dependency)
COPY crypto/ crypto/

# Copy bulletin-board module
COPY bulletin-board/ bulletin-board/

WORKDIR /build/bulletin-board
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /bulletin-board .

# Runtime stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates
COPY --from=builder /bulletin-board /usr/local/bin/bulletin-board

EXPOSE 8080

ENTRYPOINT ["bulletin-board"]
