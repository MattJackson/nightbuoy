# syntax=docker/dockerfile:1.7
FROM rust:1.98.1-slim-bookworm AS rust-build
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

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tini curl && rm -rf /var/lib/apt/lists/* && groupadd --gid 10001 nightbuoy && useradd --uid 10001 --gid 10001 --no-create-home nightbuoy && mkdir -p /data/app /app/web && chmod 700 /data/app && chown -R 10001:10001 /data /app
COPY --from=rust-build /usr/local/bin/nightbuoy /usr/local/bin/nightbuoy
COPY --from=consensus-build /out/cometbft /usr/local/bin/cometbft
COPY --from=web-build /src/web/dist /app/web
COPY LICENSE THIRD_PARTY_NOTICES.md /app/
COPY docker/init-testnet.sh /usr/local/bin/nightbuoy-init-testnet
USER 10001:10001
WORKDIR /app
ENV NIGHTBUOY_DATA=/data/app NIGHTBUOY_WEB=/app/web NIGHTBUOY_LISTEN=0.0.0.0:3000
EXPOSE 3000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["nightbuoy"]
