cmake_minimum_required(VERSION 3.16)
project(s3_client_minio C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find the AWS C libraries we use
find_package(aws-c-common REQUIRED)
find_package(aws-c-io REQUIRED)
find_package(aws-c-http REQUIRED)
find_package(aws-c-auth REQUIRED)
find_package(aws-c-s3 REQUIRED)

add_executable(s3_client s3_upload_download.c)

# Link explicitly to avoid DSO issues
target_link_libraries(s3_client
    PRIVATE
    aws-c-s3
    aws-c-auth
    aws-c-http
    aws-c-io
    aws-c-common
)
