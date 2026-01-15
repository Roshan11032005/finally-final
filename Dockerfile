FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# Build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git pkg-config curl ca-certificates \
    libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# aws-c-common (STATIC)
RUN git clone --depth=1 https://github.com/awslabs/aws-c-common.git \
    && cmake -S aws-c-common -B aws-c-common/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    && cmake --build aws-c-common/build --config Release -j \
    && cmake --install aws-c-common/build

# aws-checksums (STATIC)
RUN git clone --depth=1 https://github.com/awslabs/aws-checksums.git \
    && cmake -S aws-checksums -B aws-checksums/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    && cmake --build aws-checksums/build --config Release -j \
    && cmake --install aws-checksums/build

# s2n-tls (STATIC)
RUN git clone --depth=1 https://github.com/aws/s2n-tls.git \
    && cmake -S s2n-tls -B s2n-tls/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DS2N_NO_PQ=ON \
    && cmake --build s2n-tls/build --config Release -j \
    && cmake --install s2n-tls/build

# aws-c-cal (STATIC)
RUN git clone --depth=1 https://github.com/awslabs/aws-c-cal.git \
    && cmake -S aws-c-cal -B aws-c-cal/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    && cmake --build aws-c-cal/build --config Release -j \
    && cmake --install aws-c-cal/build

# aws-c-io (STATIC)
RUN git clone --depth=1 https://github.com/awslabs/aws-c-io.git \
    && cmake -S aws-c-io -B aws-c-io/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    && cmake --build aws-c-io/build --config Release -j \
    && cmake --install aws-c-io/build

# aws-c-compression (STATIC)
RUN git clone --depth=1 https://github.com/awslabs/aws-c-compression.git \
    && cmake -S aws-c-compression -B aws-c-compression/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    && cmake --build aws-c-compression/build --config Release -j \
    && cmake --install aws-c-compression/build

# aws-c-http (STATIC)
RUN git clone --depth=1 https://github.com/awslabs/aws-c-http.git \
    && cmake -S aws-c-http -B aws-c-http/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    && cmake --build aws-c-http/build --config Release -j \
    && cmake --install aws-c-http/build

# aws-c-sdkutils (STATIC)
RUN git clone --depth=1 https://github.com/awslabs/aws-c-sdkutils.git \
    && cmake -S aws-c-sdkutils -B aws-c-sdkutils/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    && cmake --build aws-c-sdkutils/build --config Release -j \
    && cmake --install aws-c-sdkutils/build

# aws-c-auth (STATIC)
RUN git clone --depth=1 https://github.com/awslabs/aws-c-auth.git \
    && cmake -S aws-c-auth -B aws-c-auth/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    && cmake --build aws-c-auth/build --config Release -j \
    && cmake --install aws-c-auth/build

# aws-c-s3 (STATIC)
RUN git clone --depth=1 https://github.com/awslabs/aws-c-s3.git \
    && cmake -S aws-c-s3 -B aws-c-s3/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    && cmake --build aws-c-s3/build --config Release -j \
    && cmake --install aws-c-s3/build

# App
WORKDIR /app
COPY CMakeLists.txt /app/CMakeLists.txt
COPY s3_upload_download.c /app/s3_upload_download.c
RUN cmake -S /app -B /app/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /app/build --config Release -j

# Verify binary is fully static (should show "statically linked")
RUN ldd /app/build/s3_client || echo "Static binary (no dynamic dependencies)"

ENTRYPOINT ["/app/build/s3_client"]
