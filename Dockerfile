# syntax=docker/dockerfile:1.7
FROM rust:1.99.1-slim-bookworm AS rust-build
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config ca-certificates && rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo install wasm-bindgen-cli --version 0.2.130 --locked
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
ENV CARGO_BUILD_JOBS=2
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target cargo build --release --locked -p nightbuoy && cp target/release/nightbuoy /usr/local/bin/nightbuoy
RUN rustup target add wasm32-unknown-unknown
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target cargo build --release --locked --target wasm32-unknown-unknown -p nightbuoy-proof && mkdir -p /out && cp target/wasm32-unknown-unknown/release/nightbuoy_proof.wasm /out/
RUN wasm-bindgen /out/nightbuoy_proof.wasm --target web --out-dir /out/proof

FROM node:26.13.0-bookworm-slim AS web-build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY web ./web
COPY --from=rust-build /out/proof ./web/src/generated-proof
RUN npx vite build --config web/vite.config.ts

FROM golang:1.27.3-bookworm AS consensus-build
ENV GOBIN=/out CGO_ENABLED=0
RUN go install github.com/cometbft/cometbft/cmd/cometbft@v0.38.26

FROM rust-build AS portable-build
COPY --from=web-build /src/web/dist /src/web/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target cargo build --release --locked -p nightbuoy && cp target/release/nightbuoy /usr/local/bin/nightbuoy

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tini curl && rm -rf /var/lib/apt/lists/* && groupadd --gid 10001 nightbuoy && useradd --uid 10001 --gid 10001 --no-create-home nightbuoy
COPY --from=portable-build /usr/local/bin/nightbuoy /usr/local/bin/nightbuoy
COPY LICENSE THIRD_PARTY_NOTICES.md /app/
USER 10001:10001
WORKDIR /app
ENV NIGHTBUOY_LISTEN=127.0.0.1:8080
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["nightbuoy", "portable"]

FROM runtime AS legacy
USER root
RUN mkdir -p /data/app /app/web && chmod 700 /data/app && chown -R 10001:10001 /data /app
COPY --from=consensus-build /out/cometbft /usr/local/bin/cometbft
COPY --from=web-build /src/web/dist /app/web
COPY docker/init-testnet.sh /usr/local/bin/nightbuoy-init-testnet
USER 10001:10001
ENV NIGHTBUOY_DATA=/data/app NIGHTBUOY_WEB=/app/web NIGHTBUOY_LISTEN=0.0.0.0:3000
EXPOSE 3000
CMD ["nightbuoy"]

FROM runtime AS portable
