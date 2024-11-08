use aqua_verifier_rs_types::models::content::RevisionContentSignature;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
use warp::Filter;
extern crate serde_json_path_to_error as serde_json;

pub async fn start_server() -> Result<RevisionContentSignature, Box<dyn std::error::Error>> {
    let port = 3030;

    // Check if port is available
    if !is_port_available(port) {
        return Err("Port is not available.".into());
    }

    // Shared variable for storing form data across async closures
    let form_data = Arc::new(Mutex::new(None));
    let form_data_clone = Arc::clone(&form_data);

    // HTML content (JavaScript embedded)
    let html_content = r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sign File</title>
        <script src="https://cdn.ethers.io/lib/ethers-5.2.umd.min.js"></script>
    </head>
    <body>
        <div id="app">
            <button onclick="signFileHandler()">Add Signature</button>
        </div>
        <script>
            async function signFileHandler() {
                if (window.ethereum) {
                    try {
                        const accounts = await ethereum.request({ method: 'eth_requestAccounts' });
                        const walletAddress = accounts[0];
                        if (!walletAddress) return alert("Please connect your wallet to continue");

                        const message = "I sign the following page verification_hash: [0x1234]";
                        const provider = new ethers.providers.Web3Provider(window.ethereum);
                        const signer = provider.getSigner();
                        const signature = await signer.signMessage(message);

                        const formData = new URLSearchParams();
                        formData.append('filename', "example_file.txt");
                        formData.append('signature', signature);
                        formData.append('wallet_address', walletAddress);

                        const response = await fetch('/submit', {
                            method: 'POST',
                            body: formData,
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                        });
                        const result = await response.json();
                        alert("Server Response: " + JSON.stringify(result));
                    } catch (error) {
                        console.error("Error signing:", error);
                    }
                } else {
                    alert("MetaMask is not installed");
                }
            }
        </script>
    </body>
    </html>
    "#;

    // Define routes
    let html_route = warp::path::end().map(move || warp::reply::html(html_content));

    let submit_route = warp::post()
        .and(warp::path("submit"))
        .and(warp::body::form())
        .and_then(
            move |form_data: std::collections::HashMap<String, String>| {
                let form_data_clone = Arc::clone(&form_data_clone);
                async move {
                    if let (Some(filename), Some(signature), Some(wallet_address)) = (
                        form_data.get("filename"),
                        form_data.get("signature"),
                        form_data.get("wallet_address"),
                    ) {
                        let mut data = form_data_clone.lock().unwrap();
                        *data = Some(RevisionContentSignature {
                            filename: filename.clone(),
                            signature: signature.clone(),
                            wallet_address: wallet_address.clone(),
                        });

                        let response = warp::reply::json(&serde_json::json!({
                            "status": "success",
                            "message": "Signature received",
                            "file": filename,
                            "wallet_address": wallet_address
                        }));
                        Ok::<_, warp::Rejection>(response)
                    } else {
                        Err(warp::reject::custom(ServerError(
                            "Invalid form data".into(),
                        )))
                    }
                }
            },
        );

    let routes = html_route.or(submit_route);

    // Start the server with graceful shutdown handling
    let (tx, rx) = oneshot::channel::<()>();

    println!("Spawnign a sserver");
    // tokio::spawn(async move {
    //     warp::serve(routes)
    //         .bind_with_graceful_shutdown(([127, 0, 0, 1], port), async { rx.await.ok(); });
    // });

    tokio::spawn(async move {
        // Start the server with graceful shutdown handling
        let server_future =
            warp::serve(routes).bind_with_graceful_shutdown(([127, 0, 0, 1], port), async {
                rx.await.ok(); // Await the shutdown signal
            });

        // Await the server future to ensure it runs
        server_future.await.unwrap(); // Handle any potential errors
    });

    // Wait for valid form submission and close the server
    loop {
        if let Some(data) = form_data.lock().unwrap().take() {
            tx.send(()).ok(); // Signal to stop the server
            return Ok(data); // Return valid form data
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

// Error type for handling server errors
#[derive(Debug)]
struct ServerError(String);

impl warp::reject::Reject for ServerError {}

fn is_port_available(port: u16) -> bool {
    println!("Port is available");
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}
