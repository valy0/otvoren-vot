# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy shared modules (dependencies)
COPY crypto/ crypto/
COPY pkg/ pkg/

# Copy verification module
COPY verification/ verification/

WORKDIR /build/verification
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /verification .

# Runtime stage
FROM alpine:3.20

RUN addgroup -S app && adduser -S app -G app
RUN apk --no-cache add ca-certificates
COPY --from=builder /verification /usr/local/bin/verification

USER app

EXPOSE 8084

ENTRYPOINT ["verification"]
