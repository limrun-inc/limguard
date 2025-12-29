FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/limrun-inc/limguard"
ARG TARGETOS
ARG TARGETARCH

USER root

COPY .work/bin/limguard-${TARGETOS}-${TARGETARCH} /usr/local/bin/limguard

ENTRYPOINT ["/usr/local/bin/limguard"]
