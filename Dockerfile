FROM ghcr.io/wntrtech/scratch:latest

EXPOSE 8080/tcp
COPY publish/ /

ENTRYPOINT ["/server", "web"]
HEALTHCHECK --start-period=30s --start-interval=5s --interval=1m --timeout=10s --retries=5 CMD ["/server", "health"]
