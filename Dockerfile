FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/dnsgate /dnsgate
WORKDIR /data
ENTRYPOINT ["/dnsgate"]
