# Build stage. SQLX_OFFLINE makes sqlx check queries against the committed .sqlx/
# metadata instead of a live database (refresh it with `mise run db:prepare`).
FROM rust:1.99.1-slim-trixie AS build
WORKDIR /src
ENV SQLX_OFFLINE=true
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/tocsin /tocsin

FROM debian:trixie-slim
# CA certificates: needed for outbound HTTPS (vulnerability feeds, webhooks)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /tocsin /usr/local/bin/tocsin
USER 65534:65534
ENV BIND_ADDR=0.0.0.0:3000
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/tocsin"]
