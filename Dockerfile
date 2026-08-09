FROM rust:1.88-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin square-protect \
    && install -d -o square-protect -g square-protect -m 0700 /data /opt/square-protect/static
COPY --from=builder /build/target/release/square-unifi-protect /usr/local/bin/square-unifi-protect
COPY --chown=square-protect:square-protect app/static /opt/square-protect/static
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENV SPI_DATA_DIR=/data \
    SPI_STATIC_DIR=/opt/square-protect/static \
    SPI_HOST=0.0.0.0 \
    SPI_PORT=3546 \
    SPI_TLS=1
VOLUME /data
EXPOSE 3546
HEALTHCHECK --interval=60s --timeout=5s CMD ["gosu", "square-protect", "square-unifi-protect", "--healthcheck"]
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["square-unifi-protect"]
