FROM golang:1.21-alpine AS builder

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app cmd/app/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

RUN mkdir /data

ENV DB_PATH=/data/db.sqlite
ENV HISTORY_PATH=/data/.cli_history
ENV LOCKOUT_THRESHOLD=5
ENV LOCKOUT_DURATION_MINS=15
ENV SESSION_TIMEOUT_MINS=30

VOLUME /data

COPY --from=builder /app /app

ENTRYPOINT ["/app"]
