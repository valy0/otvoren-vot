# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy shared packages (dependencies)
COPY pkg/ pkg/

# Copy auth module
COPY auth/ auth/

WORKDIR /build/auth
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /auth .

# Runtime stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates
COPY --from=builder /auth /usr/local/bin/auth

EXPOSE 8082

ENTRYPOINT ["auth"]
