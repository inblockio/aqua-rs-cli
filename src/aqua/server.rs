use actix_cors::Cors;
use actix_files::Files;
use actix_web::{middleware, web, App, Error, HttpResponse, HttpServer};
use serde::{Deserialize, Serialize};
use std::sync::{mpsc,  Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthPayload {
   pub signature: String,
   pub  public_key: String,
   pub  wallet_address: String,
}

#[derive(Debug, Serialize)]
struct SignMessage {
    message: String,
    nonce: String,
}

#[derive(Debug, Serialize)]
struct ResponseMessage {
    status: String,
}

// Changed to use Default derive
#[derive(Debug, Default)]
struct AppState {
    message: Mutex<String>
}

async fn get_sign_message(data: web::Data<AppState>) -> Result<HttpResponse, Error> {
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

async fn handle_auth(
    payload: web::Json<AuthPayload>,
    tx: web::Data<mpsc::Sender<AuthPayload>>,
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

// #[actix_web::main]
pub async fn sign_message_server(message_par: String) -> Result<AuthPayload, String> {
    env_logger::init();

    // Initialize state with default values
    let app_state = web::Data::new(AppState {
        message: Mutex::new(message_par),
    });

    let (tx, rx) = mpsc::channel::<AuthPayload>();
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
            .service(web::resource("/message").route(web::get().to(get_sign_message)))
            .service(web::resource("/auth").route(web::post().to(handle_auth)))
            .service(Files::new("/", "./static").index_file("index.html"))
    })
    .bind("127.0.0.1:8080");
    
    if server_bind.is_err() {
        return Err(format!("Unable to bind {:#?}", server_bind.err()));
    }
    let server_obj =  server_bind.unwrap();

   let server =  server_obj.run();

    let srv = server.handle();

    webbrowser::open("http://localhost:8080").unwrap();

    tokio::spawn(async move {
        let _ = shutdown_rx.recv().await;
        srv.stop(true).await;
    });


    // server.await?;

    // if let Ok(auth_payload) = rx.recv() {
    //     println!("Received auth payload:");
    //     println!("Signature: {}", auth_payload.signature);
    //     println!("Public Key: {}", auth_payload.public_key);
    //     println!("Wallet Address: {}", auth_payload.wallet_address);

    //     Ok(auth_payload);
    // }
    // Err("Server error ".to_string())

    // Ok(())

    match server.await {
        Ok(_) => {
            rx.recv()
                .map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}
