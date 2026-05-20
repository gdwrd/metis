struct request {
    int done;
};

void log_request(struct request *req);

void finish_request_callback(struct request *req) {
    free(req);
    log_request(req);
}

void finish_request_safe(struct request *req) {
    free(req);
    req = NULL;
}

void cleanup_cache(void *cache) {
    free(cache);
}
