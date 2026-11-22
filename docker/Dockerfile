# Minimal build context: Dockerfile and both release executables.
# Fleet normally extracts these binaries for its independent systemd services.
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates docker.io \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 shim
COPY --chmod=755 trusted-shim-runtime trusted-shim-socket /usr/local/bin/
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/trusted-shim-runtime"]
CMD ["--capabilities"]
