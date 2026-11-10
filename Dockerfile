# syntax=docker/dockerfile:1

# -- Build
FROM ubuntu:latest AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    libboost-dev \
    libfmt-dev \
    gdb \
    ca-certificates \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# build and install quill (can't install directly using apt)
RUN git clone --depth 1 https://github.com/odygrd/quill.git /tmp/quill && \
    cmake -S /tmp/quill -B /tmp/quill/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DQUILL_BUILD_TESTS=OFF \
        -DQUILL_BUILD_EXAMPLES=OFF \
        -DQUILL_ENABLE_INSTALL=ON && \
    cmake --build /tmp/quill/build --target install && \
    rm -rf /tmp/quill

WORKDIR /src

COPY CMakeLists.txt ./
COPY src/ ./src/

RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Debug && \
    cmake --build build --target node_app


# -- Runtime
FROM ubuntu:latest AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    iputils-ping \
    curl \
    tcpdump \
    dnsutils \
    ca-certificates \
    gdb \
    gdbserver \
    rsync \
    libasan8 \
    libubsan1 \
    libfmt10 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/build/node /usr/local/bin/node

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /app

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["node", "--help"]
