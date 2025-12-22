use axum::{routing::post, Router};
use leptos::prelude::*;
use leptos_axum::{generate_route_list, handle_server_fns, LeptosRoutes};

mod ui;

#[tokio::main]
async fn main() {
    // In real apps you typically load this via leptos::config::get_configuration(None).await
    // but default is fine for a minimal sample.
    let leptos_options = get_config_from_env().unwrap().leptos_options;
    let routes = generate_route_list(ui::App);

    // Build the router (this yields Router<LeptosOptions> i.e. "missing state")
    let app = Router::new()
        // Server functions endpoint
        .route("/api/{*fn_name}", post(handle_server_fns))
        // SSR routes
        .leptos_routes(&leptos_options, routes, ui::App)
        // Provide the missing state so the router becomes Router<()>
        .with_state(leptos_options);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    println!("Listening on http://127.0.0.1:3000");

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
