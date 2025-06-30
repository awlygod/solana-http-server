use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use spl_token::instruction::{initialize_mint, mint_to};
use std::str::FromStr;
use tower_http::cors::CorsLayer;

// Response structures
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

// Keypair endpoint structures
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

// Token create endpoint structures
#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

// Token mint endpoint structures
#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

// Message signing structures
#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

// Utility functions
fn keypair_from_secret_string(secret: &str) -> Result<Keypair, String> {
    let secret_bytes = bs58::decode(secret)
        .into_vec()
        .map_err(|_| "Invalid secret key format")?;
    
    if secret_bytes.len() != 64 {
        return Err("Invalid secret key length".to_string());
    }
    
    Keypair::from_bytes(&secret_bytes)
        .map_err(|_| "Failed to create keypair from secret".to_string())
}

fn pubkey_from_string(pubkey_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(pubkey_str).map_err(|_| format!("Invalid public key: {}", pubkey_str))
}

// Root endpoint for testing
async fn root() -> ResponseJson<ApiResponse<&'static str>> {
    ResponseJson(ApiResponse::success("Server is running! "))
}

// Endpoint handlers
async fn generate_keypair() -> Result<ResponseJson<ApiResponse<KeypairResponse>>, StatusCode> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();

    let response = KeypairResponse { pubkey, secret };
    Ok(ResponseJson(ApiResponse::success(response)))
}

async fn create_token(
    Json(request): Json<CreateTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionResponse>>, StatusCode> {
    // Parse public keys
    let mint_authority = match pubkey_from_string(&request.mint_authority) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::error(e)));
        }
    };

    let mint = match pubkey_from_string(&request.mint) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::error(e)));
        }
    };

    // Create the initialize mint instruction
    let instruction = initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority), // freeze_authority
        request.decimals,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Convert accounts to our format
    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|account| AccountInfo {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    Ok(ResponseJson(ApiResponse::success(response)))
}

async fn mint_token(
    Json(request): Json<MintTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionResponse>>, StatusCode> {
    // Parse public keys
    let mint = match pubkey_from_string(&request.mint) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::error(e)));
        }
    };

    let destination = match pubkey_from_string(&request.destination) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::error(e)));
        }
    };

    let authority = match pubkey_from_string(&request.authority) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::error(e)));
        }
    };

    // Create the mint_to instruction
    let instruction = mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],  // No multisig signers
        request.amount,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Convert accounts to our format
    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|account| AccountInfo {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    Ok(ResponseJson(ApiResponse::success(response)))
}

async fn sign_message(
    Json(request): Json<SignMessageRequest>,
) -> Result<ResponseJson<ApiResponse<SignMessageResponse>>, StatusCode> {
    // Validate required fields
    if request.message.is_empty() || request.secret.is_empty() {
        return Ok(ResponseJson(ApiResponse::error(
            "Missing required fields".to_string(),
        )));
    }

    // Create keypair from secret
    let keypair = match keypair_from_secret_string(&request.secret) {
        Ok(kp) => kp,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::error(e)));
        }
    };

    // Sign the message
    let message_bytes = request.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    
    let response = SignMessageResponse {
        signature: base64::encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: request.message,
    };

    Ok(ResponseJson(ApiResponse::success(response)))
}

#[tokio::main]
async fn main() {
    println!("starting the http server...");

    
    let app = Router::new()
        .route("/", get(root))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .layer(CorsLayer::permissive());

    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind to port 3000");
    
    println!("Server running on http://localhost:3000");
    println!("available endpoints:");
    println!("   GET  /                 - Server status");
    println!("   POST /keypair          - Generate keypair");
    println!("   POST /token/create     - Create token");
    println!("   POST /token/mint       - Mint tokens");
    println!("   POST /message/sign     - Sign message");
    
    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}