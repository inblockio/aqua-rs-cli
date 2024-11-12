use actix_cors::Cors;
use actix_web::{middleware, web, App, Error, HttpResponse, HttpServer};
use std::sync::{mpsc,  Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

use crate::server_witness_html::WITNESS_HTML;
use crate::models::{WitnessPayload, ResponseMessage, SignMessage};


// Changed to use Default derive
#[derive(Debug, Default)]
struct AppStateServerWitness {
    message: Mutex<String>
}

async fn get_witness_message(data: web::Data<AppStateServerWitness>) -> Result<HttpResponse, Error> {
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
            panic!("unable to get previous verification hash from server state");
        }

    let message =         format!("I sign the following page verification_hash: [0x{}]", msg.unwrap());
    
    println!("From get message the message to be signed ->  {}",  message);

    Ok(HttpResponse::Ok().json(SignMessage { message, nonce }))
}

async fn handle_witness_payload(
    payload: web::Json<WitnessPayload>,
    tx: web::Data<mpsc::Sender<WitnessPayload>>,
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
async fn witness_html() ->  Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(WITNESS_HTML))
}

// #[actix_web::main]
pub async fn witness_message_server(previous_verification_hash: String) -> Result<WitnessPayload, String> {
    println!("witness_message_server :: Previous  {}",previous_verification_hash);
    env_logger::init();

    // Initialize state with default values
    let app_state = web::Data::new(AppStateServerWitness {
        message: Mutex::new(previous_verification_hash),
    });

    let (tx, rx) = mpsc::channel::<WitnessPayload>();
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
            .service(web::resource("/message").route(web::get().to(get_witness_message)))
            .service(web::resource("/auth").route(web::post().to(handle_witness_payload)))
            .service(web::resource("/").route(web::get().to(witness_html))) 
        
            // .service(Files::new("/", "./static").index_file("witness.html"))
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
