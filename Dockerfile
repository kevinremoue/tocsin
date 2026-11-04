# Build stage. SQLX_OFFLINE makes sqlx check queries against the committed .sqlx/
# metadata instead of a live database (refresh it with `mise run db:prepare`).
FROM rust:1.99.1-slim-trixie AS build
WORKDIR /src
ENV SQLX_OFFLINE=true
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/tocsin /tocsin

# Distroless: glibc and CA certificates (outbound HTTPS to OSV, CISA, webhooks), no shell,
# runs as an unprivileged user. Small images start faster on serverless platforms.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /tocsin /usr/local/bin/tocsin
ENV BIND_ADDR=0.0.0.0:3000
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/tocsin"]
