use rand::rngs::OsRng;
use reqwest::Client;
use rsa::{RsaPublicKey, Pkcs1v15Encrypt, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[derive(Serialize, Deserialize)]
struct ExchangeRequest {
    encrypted_aes_key: String, 
}

#[derive(Serialize, Deserialize)]
struct ExchangeResponse {
    public_key: String,
    success: bool,
}

fn generate_aes_key() -> ([u8; 32], [u8; 16]) {
    use rand::RngCore;
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut iv);
    (key, iv)
}

#[tokio::main]
async fn main() {
    let response = Client::new()
        .get("http://127.0.0.1:3000/public_key")
        .send()
        .await
        .unwrap()
        .json::<ExchangeResponse>()
        .await
        .unwrap();

    println!("Received server's public key");

    let public_key = RsaPublicKey::from_public_key_pem(&response.public_key)
        .expect("Failed to parse public key");

    let (aes_key, iv) = generate_aes_key();
    println!("Generated AES Key: {:x?}", aes_key);
    println!("Generated IV: {:x?}", iv);

    let mut combined = Vec::with_capacity(48);
    combined.extend_from_slice(&aes_key);
    combined.extend_from_slice(&iv);

    let encrypted_data = public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, &combined)
        .unwrap();

    let verify_response = Client::new()
        .post("http://127.0.0.1:3000/exchange")
        .json(&ExchangeRequest {
            encrypted_aes_key: BASE64.encode(encrypted_data),
        })
        .send()
        .await
        .unwrap()
        .json::<ExchangeResponse>()
        .await
        .unwrap();

    println!(
        "Key exchange success: {}",
        if verify_response.success { "Yes" } else { "No" }
    );
}
