FROM alpine:3.21
LABEL org.opencontainers.image.source="https://github.com/limrun-inc/limguard"
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache \
    wireguard-tools \
    iproute2 \
    iptables \
    ca-certificates

COPY .work/bin/limguard-${TARGETOS}-${TARGETARCH} /usr/local/bin/limguard

ENTRYPOINT ["/usr/local/bin/limguard"]
