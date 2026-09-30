# Setup runtime images
FROM node:24 AS base

# Setup build image
FROM node:24 AS build

# Copy files over
COPY . ./app

# Install the packages
WORKDIR /app
RUN npm ci

# Build the app
RUN npm run build

# Build runtime image
FROM base AS final

# Copy the package.json for the final image.
COPY ./docker-app /app
WORKDIR /app

# Install serve, to serve the created frontend files with.
RUN npm ci

# Copy the created files over to the final image.
COPY --from=build /app/dist /app/build

ENTRYPOINT ["npx", "serve", "/app/build"]

# Rust application
FROM rust:1.98.1 AS server-build
COPY Cargo.toml /app/Cargo.toml
COPY Cargo.lock /app/Cargo.lock
COPY src /app/src
WORKDIR /app
RUN mkdir dist
RUN --mount=type=cache,id=cargo,target=/app/target cargo build --release && cp /app/target/release/passkeys-demo /app/dist/passkeys-demo

# Run tests (once written)
# RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
# RUN cargo binstall cargo-nextest --secure -y
# RUN cargo nextest run

FROM debian:trixie-slim AS server
WORKDIR /app
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=server-build /app/dist/passkeys-demo .
EXPOSE 8080
CMD ["./passkeys-demo"]
