# Build context is a private directory produced by bundle.mjs context.
# INFERENCE_IMAGE must be an approved Ubuntu 24.04 NIM or TensorRT-LLM image.
ARG TOOLS_IMAGE
ARG INFERENCE_IMAGE
ARG NODE_IMAGE
FROM ${NODE_IMAGE} AS dependencies
WORKDIR /deps
COPY veil/inference/package.json veil/inference/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
FROM ${TOOLS_IMAGE} AS tools
FROM ${INFERENCE_IMAGE}
USER root
COPY --from=tools /usr/local/bin/node /usr/local/bin/node
COPY --from=tools /opt/nvat /opt/nvat
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libcurl4t64 libssl3t64 libxml2 libxmlsec1t64 libxmlsec1t64-openssl zlib1g mount && rm -rf /var/lib/apt/lists/*
COPY veil /opt/veil
COPY --from=dependencies /deps/node_modules /opt/veil/inference/node_modules
COPY model /opt/veil/model
ENV LD_LIBRARY_PATH=/opt/nvat/lib:/opt/nvat/lib64:${LD_LIBRARY_PATH}
WORKDIR /opt/veil
RUN /opt/nvat/bin/nvattest --help >/dev/null && /opt/nvat/bin/evidence_getter --help >/dev/null && node inference/deploy/check-image.mjs
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/node", "/opt/veil/inference/deploy/launch.mjs"]
CMD []
