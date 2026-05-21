#[get("/health")]
async fn health(query: Query<HealthQuery>) -> String {
    return query.name.clone();
}

fn axum_handler(query: Query<HealthQuery>) -> String {
    return query.name.clone();
}

fn build_router() {
    Router::new().route("/axum/:id", get(axum_handler));
}
