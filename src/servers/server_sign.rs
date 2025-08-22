use crate::models::{ResponseMessage, SignMessage, SignOrWitnessNetwork, SignPayload};
use crate::servers::server_sign_html::SIGN_HTML;
use actix_cors::Cors;
use actix_web::{middleware, web, App, Error, HttpResponse, HttpServer};
use std::sync::{mpsc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

/// Represents the application state for the sign message server.
///
/// This struct holds the current message and network information
/// using thread-safe mutexes to allow concurrent access.
///
/// # Fields
/// * `message`: A mutex-protected string containing the message to be signed
/// * `network`: A mutex-protected string representing the blockchain network
#[derive(Debug, Default)]
struct AppStateServerSign {
    /// The message to be signed, protected by a mutex
    message: Mutex<String>,
    /// The network chain, protected by a mutex
    network: Mutex<String>,
}

/// Retrieves the current network for signing.
///
/// # Arguments
/// * `data` - The application state containing the network information
///
/// # Returns
/// A JSON response with the current network or an internal server error
///
/// # Errors
/// Returns an error if the mutex lock cannot be acquired
async fn get_sign_network(data: web::Data<AppStateServerSign>) -> Result<HttpResponse, Error> {
    let msg = data
        .network
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to acquire lock"))?;

    let network = msg.clone();
    Ok(HttpResponse::Ok().json(SignOrWitnessNetwork { network }))
}

/// Generates a sign message with a unique nonce.
///
/// # Arguments
/// * `data` - The application state containing the message to be signed
///
/// # Returns
/// A JSON response with the sign message and a timestamp nonce
///
/// # Errors
/// Returns an error if the mutex lock cannot be acquired
async fn get_sign_message(data: web::Data<AppStateServerSign>) -> Result<HttpResponse, Error> {
    // Generate a unique nonce based on current system time
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();

    // Construct the message with the verification hash
    let message = {
        let msg = data
            .message
            .lock()
            .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to acquire lock"))?;
        format!("I sign the following page verification_hash: [0x{}]", *msg)
    };

    Ok(HttpResponse::Ok().json(SignMessage { message, nonce }))
}

/// Handles the message signing payload.
///
/// # Arguments
/// * `payload` - The JSON payload containing signing information
/// * `tx` - A channel sender to pass the payload for processing
/// * `shutdown_tx` - A broadcast channel to trigger server shutdown
///
/// # Returns
/// A success response if the payload is processed successfully
///
/// # Errors
/// Returns an error if the payload cannot be sent or processed
async fn handle_message_sign_payload(
    payload: web::Json<SignPayload>,
    tx: web::Data<mpsc::Sender<SignPayload>>,
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

/// Serves the HTML page for signing.
///
/// # Returns
/// The HTML content for the signing page
///
/// # Errors
/// Returns an error if the HTML content cannot be served
async fn sign_html() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(SIGN_HTML))
}

/// Starts a web server for message signing.
///
/// # Arguments
/// * `message_par` - The message to be signed
/// * `network_chain` - The blockchain network for signing
///
/// # Returns
/// The signed payload if successful, or an error message
///
/// # Errors
/// Returns an error if the server cannot be started or bound
///
/// # Behavior
/// 1. Initializes logging
/// 2. Creates an application state with the provided message and network
/// 3. Sets up a communication channel for payload processing
/// 4. Starts an Actix web server with CORS and logging middleware
/// 5. Opens a web browser to the server URL
/// 6. Waits for the signing process to complete
pub async fn sign_message_server(
    message_par: String,
    network_chain: String,
) -> Result<SignPayload, String> {
    println!(
        "sign_message_server :: message_par  {} network {}",
        message_par, network_chain
    );

    // Initialize logging
    env_logger::init();

    // Initialize state with default values
    let app_state = web::Data::new(AppStateServerSign {
        message: Mutex::new(message_par),
        network: Mutex::new(network_chain),
    });

    // Create channels for payload processing and server shutdown
    let (tx, rx) = mpsc::channel::<SignPayload>();
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
            .service(web::resource("/network").route(web::get().to(get_sign_network)))
            .service(web::resource("/message").route(web::get().to(get_sign_message)))
            .service(web::resource("/auth").route(web::post().to(handle_message_sign_payload)))
            .service(web::resource("/").route(web::get().to(sign_html)))
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
