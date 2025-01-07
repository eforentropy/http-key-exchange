use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{post, get},
    Router,
};
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt, pkcs8::{EncodePublicKey, LineEnding}};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

const RSA_BITS: usize = 2048;

#[derive(Debug, Error)]
enum AppError {
    #[error("Failed to lock state")]
    LockError,
    #[error("Invalid key format")]
    KeyFormatError,
    #[error("Server key not initialized")]
    KeyNotInitialized,
    #[error("Decryption error")]
    DecryptionError,
    #[error("Internal server error")]
    InternalError,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            AppError::LockError => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::KeyFormatError => StatusCode::BAD_REQUEST,
            AppError::KeyNotInitialized => StatusCode::SERVICE_UNAVAILABLE,
            AppError::DecryptionError => StatusCode::BAD_REQUEST,
            AppError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        };
        
        (status, self.to_string()).into_response()
    }
}

type Result<T> = std::result::Result<T, AppError>;

#[derive(Serialize, Deserialize, Debug)]
struct ExchangeRequest {
    encrypted_aes_key: String, 
}

#[derive(Serialize, Deserialize, Debug)]
struct ExchangeResponse {
    public_key: String, 
    success: bool,
}

struct ServerState {
    rsa_key: Option<RsaPrivateKey>,
    aes_key: Option<Vec<u8>>,
    iv: Option<[u8; 16]>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            rsa_key: None,
            aes_key: None,
            iv: None,
        }
    }

    fn generate_new_key(&mut self) -> Result<()> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, RSA_BITS)
            .map_err(|_| AppError::InternalError)?;
        self.rsa_key = Some(private_key);
        Ok(())
    }

    fn get_public_key(&self) -> Result<String> {
        let private_key = self.rsa_key.as_ref()
            .ok_or(AppError::KeyNotInitialized)?;
        let public_key = RsaPublicKey::from(private_key);
        
        public_key.to_public_key_pem(LineEnding::LF)
            .map_err(|_| AppError::InternalError)
    }

    fn process_exchange(&mut self, encrypted_aes_key: &str) -> Result<bool> {
        let private_key = self.rsa_key.as_ref()
            .ok_or(AppError::KeyNotInitialized)?;

        let encrypted_data = BASE64.decode(encrypted_aes_key)
            .map_err(|_| AppError::KeyFormatError)?;

        let decrypted_data = private_key
            .decrypt(Pkcs1v15Encrypt, &encrypted_data)
            .map_err(|_| AppError::DecryptionError)?;

        if decrypted_data.len() != 48 {
            return Err(AppError::KeyFormatError);
        }

        let mut aes_key = Vec::new();
        aes_key.extend_from_slice(&decrypted_data[0..32]);
        
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&decrypted_data[32..48]);

        self.aes_key = Some(aes_key);
        self.iv = Some(iv);

        println!("Server received AES Key: {:x?}", &decrypted_data[0..32]);
        println!("Server received IV: {:x?}", &decrypted_data[32..48]);

        Ok(true)
    }
}

#[tokio::main]
async fn main() {
    let mut state = ServerState::new();
    state.generate_new_key().expect("Failed to generate initial RSA key");
    
    let shared_state = Arc::new(Mutex::new(state));

    let app = Router::new()
        .route("/public_key", get(get_public_key))
        .route("/exchange", post(handle_exchange))
        .with_state(shared_state);

    println!("Server is running on http://127.0.0.1:3000");

    axum::Server::bind(&"127.0.0.1:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn get_public_key(
    State(state): State<Arc<Mutex<ServerState>>>,
) -> Result<Json<ExchangeResponse>> {
    let state = state.lock().map_err(|_| AppError::LockError)?;
    let public_key = state.get_public_key()?;
    
    Ok(Json(ExchangeResponse {
        public_key,
        success: true,
    }))
}

async fn handle_exchange(
    State(state): State<Arc<Mutex<ServerState>>>,
    Json(payload): Json<ExchangeRequest>,
) -> Result<Json<ExchangeResponse>> {
    let mut state = state.lock().map_err(|_| AppError::LockError)?;
    let success = state.process_exchange(&payload.encrypted_aes_key)?;
    let public_key = state.get_public_key()?;

    Ok(Json(ExchangeResponse {
        public_key,
        success,
    }))
}
