use crate::models::{ResponseMessage, SignMessage, SignOrWitnessNetwork, SignPayload};
use crate::servers::server_sign_html::SIGN_HTML;
use actix_cors::Cors;
use actix_web::{middleware, web, App, Error, HttpResponse, HttpServer};
use std::sync::{mpsc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

// Changed to use Default derive
#[derive(Debug, Default)]
struct AppStateServerSign {
    message: Mutex<String>,
    network: Mutex<String>,
}

async fn get_sign_network(data: web::Data<AppStateServerSign>) -> Result<HttpResponse, Error> {
    let msg =  data
    .network
    .lock()
    .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to acquire lock"))?;

    // {
    //      format!("I sign the following page verification_hash: [0x{}]", *msg)
    // };
    let network = msg.clone();
    Ok(HttpResponse::Ok().json(SignOrWitnessNetwork { network   }))
}

async fn get_sign_message(data: web::Data<AppStateServerSign>) -> Result<HttpResponse, Error> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();

    let message = {
        let msg = data
            .message
            .lock()
            .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to acquire lock"))?;
        format!("I sign the following page verification_hash: [0x{}]", *msg)
    };

    Ok(HttpResponse::Ok().json(SignMessage { message, nonce }))
}

async fn handle_message_sign_payload(
    payload: web::Json<SignPayload>,
    tx: web::Data<mpsc::Sender<SignPayload>>,
    shutdown_tx: web::Data<broadcast::Sender<()>>,
) -> Result<HttpResponse, Error> {
    println!("Received auth request with payload: {:?}", payload);

    tx.send(payload.into_inner())
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to send payload"))?;

    let _ = shutdown_tx.send(());

    Ok(HttpResponse::Ok().json(ResponseMessage {
        status: "success".to_string(),
    }))
}

// Handler for serving the index.html
async fn sign_html() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(SIGN_HTML))
}

// #[actix_web::main]
pub async fn sign_message_server(
    message_par: String,
    network_chain: String,
) -> Result<SignPayload, String> {
    println!(
        "sign_message_server :: message_par  {} network {}",
        message_par, network_chain
    );

    env_logger::init();

    // Initialize state with default values
    let app_state = web::Data::new(AppStateServerSign {
        message: Mutex::new(message_par),
        network: Mutex::new(network_chain),
    });

    let (tx, rx) = mpsc::channel::<SignPayload>();
    let tx = web::Data::new(tx);

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_tx = web::Data::new(shutdown_tx.clone());
    let mut shutdown_rx = shutdown_tx.subscribe();

    println!("Starting server on http://localhost:8080");

    let server_bind = HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .app_data(app_state.clone()) // Changed to use app_data directly
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .app_data(tx.clone())
            .app_data(shutdown_tx.clone())
            .app_data(web::JsonConfig::default().limit(4096))
            .service(web::resource("/network").route(web::get().to(get_sign_network)))
            .service(web::resource("/message").route(web::get().to(get_sign_message)))
            .service(web::resource("/auth").route(web::post().to(handle_message_sign_payload)))
            .service(web::resource("/").route(web::get().to(sign_html)))
        // .service(Files::new("/", "./static").index_file("index.html"))
    })
    .bind("127.0.0.1:8080");

    if server_bind.is_err() {
        return Err(format!("Unable to bind {:#?}", server_bind.err()));
    }
    let server_obj = server_bind.unwrap();

    let server = server_obj.run();

    let srv = server.handle();

    webbrowser::open("http://localhost:8080").unwrap();

    tokio::spawn(async move {
        let _ = shutdown_rx.recv().await;
        srv.stop(true).await;
    });

    match server.await {
        Ok(_) => rx.recv().map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}
