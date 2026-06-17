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

# Proxmox attaches the LXC console to /dev/console; Alpine's default
# inittab only spawns gettys on tty1/tty2, so add a console getty to get
# boot output and a login prompt on the Proxmox console.
RUN echo 'console::respawn:/sbin/getty -L 38400 console vt100' >> /etc/inittab

EXPOSE 53/udp 53/tcp 9153/tcp

# When this image is imported as a Proxmox LXC template the image CMD
# becomes lxc.init.cmd, so PID 1 must be the init system (which boots
# OpenRC -> networking + the dnsix service) rather than the application
# itself. Running dnsix directly as PID 1 skips OpenRC entirely and
# leaves the console with no getty attached.
CMD ["/sbin/init"]
