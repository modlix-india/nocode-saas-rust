# One image per binary: docker build -f deploy/Dockerfile --build-arg BIN=gateway-rust -t gateway-rust .
# BIN: gateway-rust | files-serve | files-manage | ui-engine | ... (any [[bin]] in the workspace)
# For local use. CI compiles the workspace once and packages each binary with
# deploy/Dockerfile.prebuilt; keep the runtime half of the two files alike.

FROM rust:1.94-bookworm AS build
ARG BIN
# The commit /metrics reports in build_info: --build-arg GIT_SHA=$(git rev-parse HEAD).
ARG GIT_SHA
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin "${BIN}" && cp "target/release/${BIN}" /app

# glibc + CA certificates, no shell, no package manager.
FROM gcr.io/distroless/cc-debian12:nonroot
ARG BIN
COPY --from=build /app /app
USER nonroot
# Configuration: /etc/modlix/<BIN>.toml (mount it) plus MODLIX__* environment for secrets.
ENTRYPOINT ["/app"]
HEALTHCHECK --interval=10s --timeout=4s --start-period=10s --retries=3 CMD ["/app", "healthcheck"]
