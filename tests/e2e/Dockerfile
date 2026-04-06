FROM rust:1.94-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    zlib1g-dev \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . /workspace

RUN cd upstream && make
RUN cargo build --release

ENV PATH="/workspace/upstream/bin:/workspace/target/release:${PATH}"
