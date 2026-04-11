# E2E Test Environment for Snapfzz Seal
# Builds and tests all backends in an Alpine Linux container

FROM rust:1.88-alpine AS builder

RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    git \
    python3 \
    py3-pip \
    go \
    gcc

WORKDIR /build
COPY . .

ARG BUILD_ID=e2e-default-build-id
ENV BUILD_ID=${BUILD_ID}

RUN cargo build --release

FROM alpine:3.21

RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-virtualenv \
    python3-dev \
    go \
    gcc \
    g++ \
    musl-dev \
    openssl \
    curl \
    bash \
    patchelf \
    binutils

WORKDIR /app

COPY --from=builder /build/target/release/seal /usr/local/bin/
COPY --from=builder /build/target/release/seal-launcher /usr/local/bin/
COPY --from=builder /build/examples /app/examples
COPY --from=builder /build/e2e-tests/run_tests.sh /app/
COPY --from=builder /build/e2e-tests/full_interaction_test.sh /app/

RUN chmod +x /app/run_tests.sh

ARG BUILD_ID=e2e-default-build-id
ENV BUILD_ID=${BUILD_ID}

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip && \
    pip install pyinstaller nuitka

ENV SNAPFZZ_SEAL_API_KEY=""
ENV SNAPFZZ_SEAL_API_BASE=""
ENV SNAPFZZ_SEAL_MODEL=""

CMD ["/app/run_tests.sh"]