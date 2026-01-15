cmake_minimum_required(VERSION 3.16)
project(s3_client_minio C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Force static linking
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

# Link statically to system libraries
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")

# Find the AWS C libraries (will find .a versions)
find_package(aws-c-common REQUIRED)
find_package(aws-c-io REQUIRED)
find_package(aws-c-http REQUIRED)
find_package(aws-c-auth REQUIRED)
find_package(aws-c-s3 REQUIRED)

add_executable(s3_client s3_upload_download.c)

# Link all dependencies statically (order matters!)
target_link_libraries(s3_client
    PRIVATE
    aws-c-s3
    aws-c-auth
    aws-c-http
    aws-c-compression
    aws-c-sdkutils
    aws-c-io
    aws-c-cal
    aws-checksums
    s2n
    aws-c-common
    # System dependencies (must be linked for static builds)
    ssl
    crypto
    z
    pthread
    m
    dl
    rt
)

# Strip the binary to reduce size (optional)
add_custom_command(TARGET s3_client POST_BUILD
    COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:s3_client>
    COMMENT "Stripping binary"
)
