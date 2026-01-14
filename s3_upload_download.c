#include <aws/common/common.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/byte_buf.h>
#include <aws/io/io.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/uri.h>
#include <aws/http/http.h>
#include <aws/http/request_response.h>
#include <aws/auth/credentials.h>
#include <aws/auth/signing.h>
#include <aws/s3/s3.h>
#include <aws/s3/s3_client.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>

struct app_ctx {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *elg;
    struct aws_host_resolver *resolver;
    struct aws_client_bootstrap *bootstrap;
    struct aws_credentials_provider *provider;
    struct aws_s3_client *client;
    struct aws_signing_config_aws signing_config;
    struct aws_uri endpoint_uri;
    struct aws_mutex mutex;
    struct aws_condition_variable cvar;
    size_t outstanding_shutdowns;
    bool operation_finished;
    int operation_error_code;
    const char *bucket;

    /* Benchmark (upload) */
    uint64_t upload_start_ns;
    uint64_t upload_end_ns;
    int upload_http_status;
    size_t upload_bytes;
};

struct request_ctx {
    struct app_ctx *app;
    int index;
    uint64_t start_ns;
    uint64_t end_ns;
    bool finished;
    int error_code;
    int response_status;
};

/* Portable monotonic-ish clock */
static uint64_t now_ns(void) {
#if defined(CLOCK_MONOTONIC)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000000ull + (uint64_t)tv.tv_usec * 1000ull;
#endif
}
static double ns_to_s(uint64_t ns) { return (double)ns / 1e9; }
static double bytes_to_mib(size_t bytes) { return (double)bytes / (1024.0 * 1024.0); }
static double mib_per_s(size_t bytes, double seconds) {
    return seconds > 0.0 ? bytes_to_mib(bytes) / seconds : 0.0;
}
static double mbps(size_t bytes, double seconds) {
    /* Mbps (decimal megabits) */
    return seconds > 0.0 ? ((double)bytes * 8.0) / 1e6 / seconds : 0.0;
}

/* Upload callbacks */
static void s_on_put_finish(struct aws_s3_meta_request *meta_request, const struct aws_s3_meta_request_result *result, void *user_data) {
    (void)meta_request;
    struct app_ctx *ctx = (struct app_ctx *)user_data;
    aws_mutex_lock(&ctx->mutex);
    ctx->upload_end_ns = now_ns();
    if (result) {
        ctx->upload_http_status = result->response_status;
        if (result->error_code != 0) {
            ctx->operation_error_code = result->error_code;
            fprintf(stderr, "Upload operation error: %s (code %d)\n", aws_error_debug_str(result->error_code), result->error_code);
            if (result->error_response_body) {
                fprintf(stderr, "Response body: %.*s\n",
                        (int)result->error_response_body->len,
                        (char *)result->error_response_body->buffer);
            }
        }
    }
    ctx->operation_finished = true;
    aws_condition_variable_notify_one(&ctx->cvar);
    aws_mutex_unlock(&ctx->mutex);
}

static void s_on_request_shutdown(void *user_data) {
    struct app_ctx *ctx = (struct app_ctx *)user_data;
    aws_mutex_lock(&ctx->mutex);
    if (ctx->outstanding_shutdowns > 0) {
        ctx->outstanding_shutdowns--;
    }
    aws_condition_variable_notify_one(&ctx->cvar);
    aws_mutex_unlock(&ctx->mutex);
}

/* GET callbacks with per-request context */
static void s_on_get_finish(struct aws_s3_meta_request *meta_request, const struct aws_s3_meta_request_result *result, void *user_data) {
    (void)meta_request;
    struct request_ctx *r = (struct request_ctx *)user_data;
    r->end_ns = now_ns();
    r->finished = true;
    if (result) {
        r->error_code = result->error_code;
        r->response_status = result->response_status;
        if (result->error_code != 0) {
            fprintf(stderr, "GET[%d] error: %s (code %d)\n", r->index, aws_error_debug_str(result->error_code), result->error_code);
            if (result->error_response_body) {
                fprintf(stderr, "GET[%d] response body: %.*s\n",
                        r->index,
                        (int)result->error_response_body->len,
                        (char *)result->error_response_body->buffer);
            }
        }
    }
}

static void s_on_get_shutdown(void *user_data) {
    struct request_ctx *r = (struct request_ctx *)user_data;
    struct app_ctx *ctx = r->app;
    aws_mutex_lock(&ctx->mutex);
    if (ctx->outstanding_shutdowns > 0) {
        ctx->outstanding_shutdowns--;
    }
    aws_condition_variable_notify_one(&ctx->cvar);
    aws_mutex_unlock(&ctx->mutex);
}

static bool s_wait_shutdown_pred(void *user_data) {
    struct app_ctx *ctx = (struct app_ctx *)user_data;
    return ctx->outstanding_shutdowns == 0;
}

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(2);
}

static void write_1mb_file(const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) die("Failed to open upload file");
    const size_t total = 1024 * 1024;
    char buf[4096];
    memset(buf, 0, sizeof(buf));
    size_t written = 0;
    while (written < total) {
        size_t remaining = total - written;
        size_t to_write = remaining < sizeof(buf) ? remaining : sizeof(buf);
        if (fwrite(buf, 1, to_write, f) != to_write) {
            fclose(f);
            die("Failed writing upload file");
        }
        written += to_write;
    }
    fclose(f);
}

static size_t get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return (size_t)st.st_size;
}

/* Percentile helper (nearest-rank on sorted data) */
static double percentile_sorted(const double *sorted, size_t n, double p) {
    if (n == 0) return 0.0;
    if (p <= 0.0) return sorted[0];
    if (p >= 100.0) return sorted[n - 1];
    double rank = p / 100.0 * (double)n;
    size_t idx = (size_t)rank;
    if (idx == 0) idx = 1;
    if (idx > n) idx = n;
    return sorted[idx - 1];
}

static int cmp_double_asc(const void *a, const void *b) {
    const double da = *(const double *)a;
    const double db = *(const double *)b;
    return (da > db) - (da < db);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    const char *endpoint = getenv("ENDPOINT");            /* e.g. http://localhost:9000 */
    const char *region = getenv("REGION");                /* e.g. us-east-1 */
    const char *akid = getenv("AWS_ACCESS_KEY_ID");
    const char *secret = getenv("AWS_SECRET_ACCESS_KEY");
    const char *session = getenv("AWS_SESSION_TOKEN");    /* optional */
    const char *bucket = getenv("S3_BUCKET");
    const char *key = getenv("S3_KEY");
    const char *n_env = getenv("N");

    if (!endpoint || !bucket || !key) {
        fprintf(stderr, "Required env: ENDPOINT, S3_BUCKET, S3_KEY. Optional: REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, N\n");
        return 1;
    }
    if (!region) region = "us-east-1";
    int n = n_env ? atoi(n_env) : 5;
    if (n < 1) n = 1;

    struct aws_allocator *allocator = aws_default_allocator();
    aws_common_library_init(allocator);
    aws_io_library_init(allocator);
    aws_http_library_init(allocator);
    aws_auth_library_init(allocator);
    aws_s3_library_init(allocator);

    struct app_ctx ctx;
    AWS_ZERO_STRUCT(ctx);
    ctx.allocator = allocator;
    ctx.bucket = bucket;
    aws_mutex_init(&ctx.mutex);
    ctx.cvar = (struct aws_condition_variable)AWS_CONDITION_VARIABLE_INIT;

    /* event loop and bootstrap */
    ctx.elg = aws_event_loop_group_new_default(allocator, 1, NULL);
    if (!ctx.elg) die("Failed to create event loop group");

    struct aws_host_resolver_default_options hr_opts = {
        .el_group = ctx.elg,
        .max_entries = 8,
    };
    ctx.resolver = aws_host_resolver_new_default(allocator, &hr_opts);
    if (!ctx.resolver) die("Failed to create host resolver");

    struct aws_client_bootstrap_options bs_opts = {
        .event_loop_group = ctx.elg,
        .host_resolver = ctx.resolver,
    };
    ctx.bootstrap = aws_client_bootstrap_new(allocator, &bs_opts);
    if (!ctx.bootstrap) die("Failed to create client bootstrap");

    /* credentials provider (static or empty for anonymous) */
    if (akid && secret) {
        struct aws_credentials_provider_static_options sopts;
        AWS_ZERO_STRUCT(sopts);
        sopts.access_key_id = aws_byte_cursor_from_c_str(akid);
        sopts.secret_access_key = aws_byte_cursor_from_c_str(secret);
        if (session && session[0]) {
            sopts.session_token = aws_byte_cursor_from_c_str(session);
        }
        ctx.provider = aws_credentials_provider_new_static(allocator, &sopts);
    } else {
        struct aws_credentials_provider_static_options sopts;
        AWS_ZERO_STRUCT(sopts);
        sopts.access_key_id = aws_byte_cursor_from_c_str("");
        sopts.secret_access_key = aws_byte_cursor_from_c_str("");
        ctx.provider = aws_credentials_provider_new_static(allocator, &sopts);
    }
    if (!ctx.provider) die("Failed to create credentials provider");

    /* signing config */
    AWS_ZERO_STRUCT(ctx.signing_config);
    ctx.signing_config.config_type = AWS_SIGNING_CONFIG_AWS;
    ctx.signing_config.algorithm = AWS_SIGNING_ALGORITHM_V4;
    ctx.signing_config.signature_type = AWS_ST_HTTP_REQUEST_HEADERS;
    ctx.signing_config.region = aws_byte_cursor_from_c_str(region);
    ctx.signing_config.service = aws_byte_cursor_from_c_str("s3");
    ctx.signing_config.credentials_provider = ctx.provider;
    ctx.signing_config.flags.use_double_uri_encode = false;
    ctx.signing_config.flags.should_normalize_uri_path = true;

    /* parse endpoint URI */
    struct aws_byte_cursor endpoint_cursor = aws_byte_cursor_from_c_str(endpoint);
    if (aws_uri_init_parse(&ctx.endpoint_uri, allocator, &endpoint_cursor)) {
        die("Failed to parse ENDPOINT");
    }

    /* client config */
    struct aws_s3_client_config client_config;
    AWS_ZERO_STRUCT(client_config);
    client_config.client_bootstrap = ctx.bootstrap;
    client_config.region = aws_byte_cursor_from_c_str(region);
    client_config.signing_config = &ctx.signing_config;

    /* Check TLS mode */
    struct aws_byte_cursor https_cursor = aws_byte_cursor_from_c_str("https");
    const struct aws_byte_cursor *scheme = aws_uri_scheme(&ctx.endpoint_uri);
    client_config.tls_mode =
        aws_byte_cursor_eq_ignore_case(scheme, &https_cursor)
            ? AWS_MR_TLS_ENABLED
            : AWS_MR_TLS_DISABLED;

    client_config.part_size = 5 * 1024 * 1024;

    ctx.client = aws_s3_client_new(allocator, &client_config);
    if (!ctx.client) die("Failed to create S3 client");

    /* Construct path-style request: /bucket/key */
    struct aws_byte_buf request_path;
    aws_byte_buf_init(&request_path, allocator, strlen(bucket) + strlen(key) + 3);
    struct aws_byte_cursor slash = aws_byte_cursor_from_c_str("/");
    struct aws_byte_cursor bucket_cursor = aws_byte_cursor_from_c_str(bucket);
    struct aws_byte_cursor key_cursor = aws_byte_cursor_from_c_str(key);

    aws_byte_buf_append_dynamic(&request_path, &slash);
    aws_byte_buf_append_dynamic(&request_path, &bucket_cursor);
    aws_byte_buf_append_dynamic(&request_path, &slash);
    aws_byte_buf_append_dynamic(&request_path, &key_cursor);
    struct aws_byte_cursor object_path = aws_byte_cursor_from_buf(&request_path);

    /* Prepare 1MB upload file */
    const char *upload_path = "/tmp/upload.bin";
    write_1mb_file(upload_path);
    size_t file_size = get_file_size(upload_path);
    ctx.upload_bytes = file_size;

    /* PUT message - use endpoint directly (path-style) */
    struct aws_http_message *put_msg = aws_http_message_new_request(allocator);
    struct aws_byte_cursor put_method = aws_byte_cursor_from_c_str("PUT");
    aws_http_message_set_request_method(put_msg, put_method);
    aws_http_message_set_request_path(put_msg, object_path);

    /* Use endpoint authority directly for Host header (path-style) */
    const struct aws_byte_cursor *authority = aws_uri_authority(&ctx.endpoint_uri);
    struct aws_http_headers *put_headers = aws_http_message_get_headers(put_msg);
    struct aws_byte_cursor host_header = aws_byte_cursor_from_c_str("Host");
    struct aws_byte_cursor content_type_header = aws_byte_cursor_from_c_str("Content-Type");
    struct aws_byte_cursor content_type_value = aws_byte_cursor_from_c_str("application/octet-stream");
    struct aws_byte_cursor content_length_header = aws_byte_cursor_from_c_str("Content-Length");

    char content_length_str[32];
    snprintf(content_length_str, sizeof(content_length_str), "%zu", file_size);
    struct aws_byte_cursor content_length_value = aws_byte_cursor_from_c_str(content_length_str);

    aws_http_headers_set(put_headers, host_header, *authority);
    aws_http_headers_set(put_headers, content_type_header, content_type_value);
    aws_http_headers_set(put_headers, content_length_header, content_length_value);

    struct aws_s3_meta_request_options put_opts;
    AWS_ZERO_STRUCT(put_opts);
    put_opts.type = AWS_S3_META_REQUEST_TYPE_PUT_OBJECT;
    put_opts.message = put_msg;
    put_opts.endpoint = &ctx.endpoint_uri; /* FIX: ctx is not a pointer */
    put_opts.send_filepath = aws_byte_cursor_from_c_str(upload_path);
    put_opts.signing_config = &ctx.signing_config;
    put_opts.finish_callback = s_on_put_finish;
    put_opts.shutdown_callback = s_on_request_shutdown;
    put_opts.user_data = &ctx;

    ctx.operation_finished = false;
    ctx.outstanding_shutdowns = 1;
    ctx.operation_error_code = 0;
    ctx.upload_http_status = 0;
    ctx.upload_start_ns = now_ns();

    fprintf(stdout, "Uploading to %.*s%.*s\n",
            (int)authority->len, (const char *)authority->ptr,
            (int)object_path.len, (const char *)object_path.ptr);

    struct aws_s3_meta_request *put_mr = aws_s3_client_make_meta_request(ctx.client, &put_opts);
    if (!put_mr) {
        fprintf(stderr, "PUT meta request creation failed: %s\n", aws_error_debug_str(aws_last_error()));
        die("PUT meta request failed");
    }
    aws_s3_meta_request_release(put_mr);
    aws_http_message_release(put_msg);

    /* Wait for PUT finished */
    aws_mutex_lock(&ctx.mutex);
    while (!ctx.operation_finished) {
        aws_condition_variable_wait(&ctx.cvar, &ctx.mutex);
    }
    aws_mutex_unlock(&ctx.mutex);

    /* Print upload benchmark */
    double up_secs = ns_to_s(ctx.upload_end_ns - ctx.upload_start_ns);
    if (ctx.operation_error_code != 0) {
        fprintf(stderr, "PUT failed with error: %s\n", aws_error_debug_str(ctx.operation_error_code));
    } else {
        fprintf(stdout, "PUT succeeded (HTTP %d)\n", ctx.upload_http_status);
    }
    fprintf(stdout, "Upload metrics:\n");
    fprintf(stdout, "  Size:             %zu bytes (%.2f MiB)\n", ctx.upload_bytes, bytes_to_mib(ctx.upload_bytes));
    fprintf(stdout, "  Duration:         %.6f s\n", up_secs);
    fprintf(stdout, "  Throughput:       %.3f MiB/s  (%.3f Mbps)\n", mib_per_s(ctx.upload_bytes, up_secs), mbps(ctx.upload_bytes, up_secs));

    /* Wait for PUT shutdown */
    aws_mutex_lock(&ctx.mutex);
    while (ctx.outstanding_shutdowns > 0) {
        aws_condition_variable_wait_pred(&ctx.cvar, &ctx.mutex, s_wait_shutdown_pred, &ctx);
    }
    aws_mutex_unlock(&ctx.mutex);

    /* GET N times concurrently; write to separate files */
    struct request_ctx *reqs = (struct request_ctx *)calloc((size_t)n, sizeof(struct request_ctx));
    if (!reqs) die("Failed to allocate request contexts");

    ctx.outstanding_shutdowns = (size_t)n;
    uint64_t downloads_start_ns = now_ns();

    for (int i = 0; i < n; ++i) {
        struct request_ctx *r = &reqs[i];
        r->app = &ctx;
        r->index = i;
        r->finished = false;
        r->error_code = 0;
        r->response_status = 0;
        r->start_ns = now_ns();

        char dl_path[256];
        snprintf(dl_path, sizeof(dl_path), "/tmp/download_%d.bin", i);

        struct aws_http_message *get_msg = aws_http_message_new_request(allocator);
        struct aws_byte_cursor get_method = aws_byte_cursor_from_c_str("GET");
        aws_http_message_set_request_method(get_msg, get_method);
        aws_http_message_set_request_path(get_msg, object_path);

        struct aws_http_headers *get_headers = aws_http_message_get_headers(get_msg);
        aws_http_headers_set(get_headers, host_header, *authority);

        struct aws_s3_meta_request_options get_opts;
        AWS_ZERO_STRUCT(get_opts);
        get_opts.type = AWS_S3_META_REQUEST_TYPE_GET_OBJECT;
        get_opts.message = get_msg;
        get_opts.endpoint = &ctx.endpoint_uri; /* FIX: ctx is not a pointer */
        get_opts.signing_config = &ctx.signing_config;
        get_opts.recv_filepath = aws_byte_cursor_from_c_str(dl_path);
        get_opts.recv_file_option = AWS_S3_RECV_FILE_CREATE_OR_REPLACE;
        get_opts.recv_file_delete_on_failure = true;
        get_opts.finish_callback = s_on_get_finish;
        get_opts.shutdown_callback = s_on_get_shutdown;
        get_opts.user_data = r;

        struct aws_s3_meta_request *get_mr = aws_s3_client_make_meta_request(ctx.client, &get_opts);
        if (!get_mr) {
            fprintf(stderr, "GET[%d] meta request creation failed: %s\n", i, aws_error_debug_str(aws_last_error()));
            r->finished = true;
            r->error_code = aws_last_error();
            r->end_ns = now_ns();

            aws_mutex_lock(&ctx.mutex);
            if (ctx.outstanding_shutdowns > 0) ctx.outstanding_shutdowns--;
            aws_condition_variable_notify_one(&ctx.cvar);
            aws_mutex_unlock(&ctx.mutex);
        } else {
            aws_s3_meta_request_release(get_mr);
        }
        aws_http_message_release(get_msg);
    }

    /* Wait for all GET shutdowns */
    aws_mutex_lock(&ctx.mutex);
    while (ctx.outstanding_shutdowns > 0) {
        aws_condition_variable_wait_pred(&ctx.cvar, &ctx.mutex, s_wait_shutdown_pred, &ctx);
    }
    aws_mutex_unlock(&ctx.mutex);
    uint64_t downloads_end_ns = now_ns();

    /* Compute download benchmarks */
    size_t success_count = 0;
    size_t failure_count = 0;
    double *latencies = (double *)calloc((size_t)n, sizeof(double));
    if (!latencies) die("Failed to allocate latency array");

    for (int i = 0; i < n; ++i) {
        struct request_ctx *r = &reqs[i];
        double dur = ns_to_s(r->end_ns - r->start_ns);
        bool ok = (r->finished && r->error_code == 0 && r->response_status >= 200 && r->response_status < 400);
        if (ok) {
            latencies[success_count++] = dur;
        } else {
            failure_count++;
        }
    }

    double agg_secs = ns_to_s(downloads_end_ns - downloads_start_ns);
    size_t bytes_downloaded = success_count * file_size;

    fprintf(stdout, "Completed upload and %d async downloads.\n", n);
    fprintf(stdout, "Download metrics (aggregate):\n");
    fprintf(stdout, "  Successful:       %zu/%d\n", success_count, n);
    fprintf(stdout, "  Duration:         %.6f s (phase wall time)\n", agg_secs);
    fprintf(stdout, "  Bytes:            %zu bytes (%.2f MiB)\n", bytes_downloaded, bytes_to_mib(bytes_downloaded));
    fprintf(stdout, "  Throughput:       %.3f MiB/s  (%.3f Mbps)\n", mib_per_s(bytes_downloaded, agg_secs), mbps(bytes_downloaded, agg_secs));

    if (success_count > 0) {
        /* Per-request latency stats */
        qsort(latencies, success_count, sizeof(double), cmp_double_asc);
        double sum = 0.0;
        for (size_t i = 0; i < success_count; ++i) sum += latencies[i];
        double avg = sum / (double)success_count;
        double min = latencies[0];
        double max = latencies[success_count - 1];
        double p50 = percentile_sorted(latencies, success_count, 50.0);
        double p90 = percentile_sorted(latencies, success_count, 90.0);
        double p99 = percentile_sorted(latencies, success_count, 99.0);

        fprintf(stdout, "Download latency (per-request):\n");
        fprintf(stdout, "  Min / Avg / Max:  %.6f / %.6f / %.6f s\n", min, avg, max);
        fprintf(stdout, "  P50 / P90 / P99:  %.6f / %.6f / %.6f s\n", p50, p90, p99);

        /* Mean per-request throughput (MiB/s) given object size */
        double mean_tput_mibs = mib_per_s(file_size, avg);
        fprintf(stdout, "  Mean per-request throughput: %.3f MiB/s (object size %.2f MiB)\n",
                mean_tput_mibs, bytes_to_mib(file_size));
    }

    if (failure_count > 0) {
        fprintf(stdout, "Download failures: %zu\n", failure_count);
        for (int i = 0; i < n; ++i) {
            struct request_ctx *r = &reqs[i];
            bool ok = (r->finished && r->error_code == 0 && r->response_status >= 200 && r->response_status < 400);
            if (!ok) {
                fprintf(stdout, "  GET[%d]: error_code=%d status=%d duration=%.6f s\n",
                        r->index, r->error_code, r->response_status,
                        ns_to_s(r->end_ns - r->start_ns));
            }
        }
    }

    /* Cleanup */
    free(latencies);
    free(reqs);

    aws_s3_client_release(ctx.client);
    aws_client_bootstrap_release(ctx.bootstrap);
    aws_host_resolver_release(ctx.resolver);
    aws_event_loop_group_release(ctx.elg);
    aws_credentials_provider_release(ctx.provider);
    aws_uri_clean_up(&ctx.endpoint_uri);
    aws_byte_buf_clean_up(&request_path);
    aws_mutex_clean_up(&ctx.mutex);

    aws_s3_library_clean_up();
    aws_auth_library_clean_up();
    aws_http_library_clean_up();
    aws_io_library_clean_up();
    aws_common_library_clean_up();

    return 0;
}
