use actix_cors::Cors;
use actix_web::{middleware, web, App, Error, HttpResponse, HttpServer};
use std::sync::{mpsc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

use crate::models::{ResponseMessage, SignMessage, SignOrWitnessNetwork, WitnessPayload};
use crate::servers::server_witness_html::WITNESS_HTML;

/// Application state for v3 witness message server
#[derive(Debug, Default)]
struct AppStateServerWitness {
    /// The verification hash to be witnessed, protected by a mutex
    message: Mutex<String>,
    /// The network chain, protected by a mutex
    network: Mutex<String>,
}

/// Get current network for witnessing (v3 compatible)
async fn get_witness_network(
    data: web::Data<AppStateServerWitness>,
) -> Result<HttpResponse, Error> {
    let network_res = data
        .network
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to acquire lock"));

    if network_res.is_err() {
        return Err(actix_web::error::ErrorInternalServerError(
            "Unable to get network from server state",
        ));
    }

    let network_guard: MutexGuard<'_, String> = network_res.unwrap();
    let network_value = network_guard.clone();

    Ok(HttpResponse::Ok().json(SignOrWitnessNetwork {
        network: network_value,
    }))
}

/// Generate witness message with nonce (v3 format)
async fn get_witness_message(
    data: web::Data<AppStateServerWitness>,
) -> Result<HttpResponse, Error> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();

    let msg = data
        .message
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to acquire lock"));

    if msg.is_err() {
        return Err(actix_web::error::ErrorInternalServerError(
            "Unable to get verification hash from server state",
        ));
    }

    // In v3, the message is the witness event hash (not wrapped in additional text)
    let message = format!("{}", msg.unwrap());

    println!("v3 witness message to be signed: {}", message);

    Ok(HttpResponse::Ok().json(SignMessage { message, nonce }))
}

/// Handle witness payload with v3 structure
async fn handle_witness_payload(
    payload: web::Json<WitnessPayload>,
    tx: web::Data<mpsc::Sender<WitnessPayload>>,
    shutdown_tx: web::Data<broadcast::Sender<()>>,
) -> Result<HttpResponse, Error> {
    println!("Received v3 witness request: {:?}", payload);

    // Validate v3 witness payload
    let validated_payload = validate_v3_witness_payload(&payload)?;

    // Send validated payload
    tx.send(validated_payload)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to send payload"))?;

    // Trigger shutdown
    let _ = shutdown_tx.send(());

    Ok(HttpResponse::Ok().json(ResponseMessage {
        status: "success".to_string(),
    }))
}

/// Validate v3 witness payload structure
fn validate_v3_witness_payload(payload: &WitnessPayload) -> Result<WitnessPayload, Error> {
    // Validate transaction hash format
    if !payload.tx_hash.starts_with("0x") || payload.tx_hash.len() != 66 {
        return Err(actix_web::error::ErrorBadRequest(
            "Invalid transaction hash format",
        ));
    }

    // Validate network (v3 supports multiple networks)
    let valid_networks = ["mainnet", "sepolia", "holesky", "nostr", "TSA_RFC3161"];
    if !valid_networks.contains(&payload.network.as_str()) {
        return Err(actix_web::error::ErrorBadRequest(
            "Unsupported witness network",
        ));
    }

    // Validate wallet address format (for Ethereum networks)
    if ["mainnet", "sepolia", "holesky"].contains(&payload.network.as_str()) {
        if !payload.wallet_address.starts_with("0x") || payload.wallet_address.len() != 42 {
            return Err(actix_web::error::ErrorBadRequest(
                "Invalid wallet address format",
            ));
        }
    }

    // Return validated payload with v3 enhancements
    Ok(WitnessPayload {
        tx_hash: payload.tx_hash.clone(),
        network: payload.network.clone(),
        wallet_address: payload.wallet_address.clone(),
        merkle_proof: payload.merkle_proof.clone(),
        merkle_root: payload.merkle_root.clone(),
        timestamp: payload.timestamp,
        smart_contract_address: payload.smart_contract_address.clone(),
    })
}

/// Serve HTML page for witnessing
async fn witness_html() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(WITNESS_HTML))
}

/// Start web server for v3 message witnessing
pub async fn witness_message_server(
    previous_verification_hash: String,
    network: String,
) -> Result<WitnessPayload, String> {
    println!(
        "Starting v3 witness_message_server :: hash: {} network: {}",
        previous_verification_hash, network
    );

    // Initialize logging
    env_logger::init();

    // Initialize state
    let app_state = web::Data::new(AppStateServerWitness {
        message: Mutex::new(previous_verification_hash),
        network: Mutex::new(network),
    });

    // Create communication channels
    let (tx, rx) = mpsc::channel::<WitnessPayload>();
    let tx = web::Data::new(tx);

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_tx = web::Data::new(shutdown_tx.clone());
    let mut shutdown_rx = shutdown_tx.subscribe();

    println!("Starting v3 witness server on http://localhost:8080");

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
            .service(web::resource("/network").route(web::get().to(get_witness_network)))
            .service(web::resource("/message").route(web::get().to(get_witness_message)))
            .service(web::resource("/auth").route(web::post().to(handle_witness_payload)))
            .service(web::resource("/").route(web::get().to(witness_html)))
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
