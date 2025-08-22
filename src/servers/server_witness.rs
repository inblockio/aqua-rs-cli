use actix_cors::Cors;
use actix_web::{middleware, web, App, Error, HttpResponse, HttpServer};
use hyper::body::HttpBody;
use std::sync::{mpsc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

use crate::models::{ResponseMessage, SignMessage, SignOrWitnessNetwork, WitnessPayload};
use crate::servers::server_witness_html::WITNESS_HTML;

/// Represents the application state for the witness message server.
///
/// This struct holds the current message and network information
/// using thread-safe mutexes to allow concurrent access.
///
/// # Fields
/// * `message`: A mutex-protected string containing the verification hash
/// * `network`: A mutex-protected string representing the blockchain network
#[derive(Debug, Default)]
struct AppStateServerWitness {
    /// The verification hash to be witnessed, protected by a mutex
    message: Mutex<String>,
    /// The network chain, protected by a mutex
    network: Mutex<String>,
}

/// Retrieves the current network for witnessing.
///
/// # Arguments
/// * `data` - The application state containing the network information
///
/// # Returns
/// A JSON response with the current network or an internal server error
///
/// # Errors
/// Returns an error if the mutex lock cannot be acquired or if accessing the network fails
async fn get_witness_network(
    data: web::Data<AppStateServerWitness>,
) -> Result<HttpResponse, Error> {
    // Attempt to acquire the network mutex lock
    let network_res = data
        .network
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to acquire lock"));

    // Panic if unable to get the network (alternative error handling)
    if network_res.is_err() {
        panic!("unable to get previous verification hash from server state");
    }

    // Safely extract the network value
    let network_guard: MutexGuard<'_, String> = network_res.unwrap();
    let network_value = network_guard.clone();

    Ok(HttpResponse::Ok().json(SignOrWitnessNetwork {
        network: network_value,
    }))
}

/// Generates a witness message with a unique nonce.
///
/// # Arguments
/// * `data` - The application state containing the message to be witnessed
///
/// # Returns
/// A JSON response with the witness message and a timestamp nonce
///
/// # Errors
/// Returns an error if the mutex lock cannot be acquired or if accessing the message fails
async fn get_witness_message(
    data: web::Data<AppStateServerWitness>,
) -> Result<HttpResponse, Error> {
    // Generate a unique nonce based on current system time
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();

    // Attempt to acquire the message mutex lock
    let msg = data
        .message
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to acquire lock"));

    // Panic if unable to get the message (alternative error handling)
    if msg.is_err() {
        panic!("unable to get previous verification hash from server state");
    }

    // Construct the message
    let message = format!("{}", msg.unwrap());

    println!("From get message the message to be signed ->  {}", message);

    Ok(HttpResponse::Ok().json(SignMessage { message, nonce }))
}

/// Handles the witness payload submission.
///
/// # Arguments
/// * `payload` - The JSON payload containing witnessing information
/// * `tx` - A channel sender to pass the payload for processing
/// * `shutdown_tx` - A broadcast channel to trigger server shutdown
///
/// # Returns
/// A success response if the payload is processed successfully
///
/// # Errors
/// Returns an error if the payload cannot be sent or processed
async fn handle_witness_payload(
    payload: web::Json<WitnessPayload>,
    tx: web::Data<mpsc::Sender<WitnessPayload>>,
    shutdown_tx: web::Data<broadcast::Sender<()>>,
) -> Result<HttpResponse, Error> {
    println!("Received auth request with payload: {:?}", payload);

    // Send the payload through the channel
    tx.send(payload.into_inner())
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to send payload"))?;

    // Trigger server shutdown
    let _ = shutdown_tx.send(());

    Ok(HttpResponse::Ok().json(ResponseMessage {
        status: "success".to_string(),
    }))
}

/// Serves the HTML page for witnessing.
///
/// # Returns
/// The HTML content for the witnessing page
///
/// # Errors
/// Returns an error if the HTML content cannot be served
async fn witness_html() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(WITNESS_HTML))
}

/// Starts a web server for message witnessing.
///
/// # Arguments
/// * `previous_verification_hash` - The verification hash to be witnessed
/// * `network` - The blockchain network for witnessing
///
/// # Returns
/// The witnessed payload if successful, or an error message
///
/// # Errors
/// Returns an error if the server cannot be started or bound
///
/// # Behavior
/// 1. Initializes logging
/// 2. Creates an application state with the provided verification hash and network
/// 3. Sets up a communication channel for payload processing
/// 4. Starts an Actix web server with CORS and logging middleware
/// 5. Opens a web browser to the server URL
/// 6. Waits for the witnessing process to complete
pub async fn witness_message_server(
    previous_verification_hash: String,
    network: String,
) -> Result<WitnessPayload, String> {
    println!(
        "witness_message_server :: hash  {} network {}",
        previous_verification_hash, network
    );

    // Initialize logging
    env_logger::init();

    // Initialize state with default values
    let app_state = web::Data::new(AppStateServerWitness {
        message: Mutex::new(previous_verification_hash),
        network: Mutex::new(network),
    });

    // Create channels for payload processing and server shutdown
    let (tx, rx) = mpsc::channel::<WitnessPayload>();
    let tx = web::Data::new(tx);

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_tx = web::Data::new(shutdown_tx.clone());
    let mut shutdown_rx = shutdown_tx.subscribe();

    println!("Starting server on http://localhost:8080");

    // Configure the Actix web server
    let server_bind = HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .app_data(app_state.clone())
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .app_data(tx.clone())
            .app_data(shutdown_tx.clone())
            .app_data(web::JsonConfig::default().limit(4096))
            .service(web::resource("/network").route(web::get().to(get_witness_network)))
            .service(web::resource("/message").route(web::get().to(get_witness_message)))
            .service(web::resource("/auth").route(web::post().to(handle_witness_payload)))
            .service(web::resource("/").route(web::get().to(witness_html)))
    })
    .bind("127.0.0.1:8080");

    // Handle server binding errors
    if server_bind.is_err() {
        return Err(format!("Unable to bind {:#?}", server_bind.err()));
    }
    let server_obj = server_bind.unwrap();

    // Run the server
    let server = server_obj.run();

    let srv = server.handle();

    // Open the default web browser to the server URL
    webbrowser::open("http://localhost:8080").unwrap();

    // Spawn a task to handle server shutdown
    tokio::spawn(async move {
        let _ = shutdown_rx.recv().await;
        srv.stop(true).await;
    });

    // Wait for the server to complete and return the payload
    match server.await {
        Ok(_) => rx.recv().map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}
