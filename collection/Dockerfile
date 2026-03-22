# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy shared modules (dependencies)
COPY crypto/ crypto/
COPY pkg/ pkg/

# Copy collection module
COPY collection/ collection/

WORKDIR /build/collection
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /collection .

# Runtime stage
FROM alpine:3.20

RUN addgroup -S app && adduser -S app -G app
RUN apk --no-cache add ca-certificates
COPY --from=builder /collection /usr/local/bin/collection

USER app

EXPOSE 8083

ENTRYPOINT ["collection"]
