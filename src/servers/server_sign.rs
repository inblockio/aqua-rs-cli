use crate::models::{ResponseMessage, SignMessage, SignOrWitnessNetwork, SignPayload};
use crate::servers::server_sign_html::SIGN_HTML;
use actix_cors::Cors;
use actix_web::{middleware, web, App, Error, HttpResponse, HttpServer};
use std::sync::{mpsc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

/// Application state for v3 sign message server
#[derive(Debug, Default)]
struct AppStateServerSign {
    /// The message to be signed, protected by a mutex
    message: Mutex<String>,
    /// The network chain, protected by a mutex
    network: Mutex<String>,
}

/// Get the current network for signing (v3 compatible)
async fn get_sign_network(data: web::Data<AppStateServerSign>) -> Result<HttpResponse, Error> {
    let msg = data
        .network
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to acquire lock"))?;

    let network = msg.clone();
    Ok(HttpResponse::Ok().json(SignOrWitnessNetwork { network }))
}

/// Generate sign message with nonce (v3 compatible)
async fn get_sign_message(data: web::Data<AppStateServerSign>) -> Result<HttpResponse, Error> {
    // Generate unique nonce
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();

    // Get message to sign (in v3, this is typically the latest revision hash)
    let message = {
        let msg = data
            .message
            .lock()
            .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to acquire lock"))?;
        format!("I sign the following page verification_hash: [0x{}]", *msg)
    };

    Ok(HttpResponse::Ok().json(SignMessage { message, nonce }))
}

/// Handle message signing payload with v3 signature type
async fn handle_message_sign_payload(
    payload: web::Json<SignPayload>,
    tx: web::Data<mpsc::Sender<SignPayload>>,
    shutdown_tx: web::Data<broadcast::Sender<()>>,
) -> Result<HttpResponse, Error> {
    println!("Received v3 signing request: {:?}", payload);

    // Validate v3 signature payload
    let validated_payload = validate_v3_signature_payload(&payload)?;

    // Send validated payload
    tx.send(validated_payload)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to send payload"))?;

    // Trigger server shutdown
    let _ = shutdown_tx.send(());

    Ok(HttpResponse::Ok().json(ResponseMessage {
        status: "success".to_string(),
    }))
}

/// Validate v3 signature payload structure
fn validate_v3_signature_payload(payload: &SignPayload) -> Result<SignPayload, Error> {
    // Validate signature format
    if !payload.signature.starts_with("0x") || payload.signature.len() < 130 {
        return Err(actix_web::error::ErrorBadRequest(
            "Invalid signature format",
        ));
    }

    // Validate public key format
    if !payload.public_key.starts_with("0x") || payload.public_key.len() < 66 {
        return Err(actix_web::error::ErrorBadRequest(
            "Invalid public key format",
        ));
    }

    // Validate wallet address format
    if !payload.wallet_address.starts_with("0x") || payload.wallet_address.len() != 42 {
        return Err(actix_web::error::ErrorBadRequest(
            "Invalid wallet address format",
        ));
    }

    // Validate signature type (v3 supports multiple types)
    let valid_signature_types = ["ethereum:eip-191", "did_key"];
    if !valid_signature_types.contains(&payload.signature_type.as_str()) {
        return Err(actix_web::error::ErrorBadRequest(
            "Unsupported signature type",
        ));
    }

    // Return validated payload
    Ok(SignPayload {
        signature: payload.signature.clone(),
        public_key: payload.public_key.clone(),
        wallet_address: payload.wallet_address.clone(),
        signature_type: payload.signature_type.clone(),
    })
}

/// Serve HTML page for signing
async fn sign_html() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(SIGN_HTML))
}

/// Start web server for v3 message signing
pub async fn sign_message_server(
    message_par: String,
    network_chain: String,
) -> Result<SignPayload, String> {
    println!(
        "Starting v3 sign_message_server :: message: {} network: {}",
        message_par, network_chain
    );

    // Initialize logging
    env_logger::init();

    // Initialize state
    let app_state = web::Data::new(AppStateServerSign {
        message: Mutex::new(message_par),
        network: Mutex::new(network_chain),
    });

    // Create communication channels
    let (tx, rx) = mpsc::channel::<SignPayload>();
    let tx = web::Data::new(tx);

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_tx = web::Data::new(shutdown_tx.clone());
    let mut shutdown_rx = shutdown_tx.subscribe();

    println!("Starting v3 signing server on http://localhost:8080");

    // Configure Actix web server
    let server_bind = HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .app_data(app_state.clone())
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .app_data(tx.clone())
            .app_data(shutdown_tx.clone())
            .app_data(web::JsonConfig::default().limit(8192)) // Increased for v3 payloads
            .service(web::resource("/network").route(web::get().to(get_sign_network)))
            .service(web::resource("/message").route(web::get().to(get_sign_message)))
            .service(web::resource("/auth").route(web::post().to(handle_message_sign_payload)))
            .service(web::resource("/").route(web::get().to(sign_html)))
    })
    .bind("127.0.0.1:8080");

    if server_bind.is_err() {
        return Err(format!("Unable to bind server: {:?}", server_bind.err()));
    }

    let server_obj = server_bind.unwrap();
    let server = server_obj.run();
    let srv = server.handle();

    // Open browser
    webbrowser::open("http://localhost:8080").unwrap();

    // Handle shutdown
    tokio::spawn(async move {
        let _ = shutdown_rx.recv().await;
        srv.stop(true).await;
    });

    // Wait for completion
    match server.await {
        Ok(_) => rx.recv().map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}
