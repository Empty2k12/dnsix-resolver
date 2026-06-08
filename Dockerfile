# syntax=docker/dockerfile:1

FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /src
COPY . .
RUN cargo build --release --locked --target x86_64-unknown-linux-musl

FROM alpine:3.20

RUN apk add --no-cache alpine-base

COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/dnsix /usr/local/bin/dnsix

COPY config.example.toml /etc/dnsix/config.toml

COPY docker/dnsix.openrc /etc/init.d/dnsix
RUN chmod +x /etc/init.d/dnsix \
    && rc-update add networking boot \
    && rc-update add bootmisc boot \
    && rc-update add hostname boot \
    && rc-update add syslog boot \
    && rc-update add dnsix default

EXPOSE 53/udp 53/tcp 9153/tcp

CMD ["/usr/local/bin/dnsix", "--config", "/etc/dnsix/config.toml"]
