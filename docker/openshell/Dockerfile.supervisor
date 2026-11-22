# Compose a pinned stock supervisor with the shim's local stdio adapter. Neither
# the upstream supervisor binary/entrypoint nor the workload image is changed.
# Build context contains a static trusted-shim-socket binary for the node arch.
ARG SUPERVISOR_IMAGE
FROM ${SUPERVISOR_IMAGE}
COPY --chmod=0555 trusted-shim-socket /opt/trusted-shim/socket
