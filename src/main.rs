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
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction::{initialize_mint, mint_to, transfer};
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

// Message verification structures
#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

// SOL transfer structures
#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

// SPL Token transfer structures
#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
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

fn signature_from_string(signature_str: &str) -> Result<Signature, String> {
    let signature_bytes = base64::decode(signature_str)
        .map_err(|_| "Invalid signature format")?;
    
    if signature_bytes.len() != 64 {
        return Err("Invalid signature length".to_string());
    }
    
    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature_bytes);
    Ok(Signature::from(signature_array))
}

fn validate_lamports(lamports: u64) -> Result<(), String> {
    if lamports == 0 {
        return Err("Lamports must be greater than 0".to_string());
    }
    // Add reasonable upper bound to prevent overflow issues
    if lamports > 1_000_000_000_000_000 { // 1 million SOL in lamports
        return Err("Lamports amount too large".to_string());
    }
    Ok(())
}

fn validate_token_amount(amount: u64) -> Result<(), String> {
    if amount == 0 {
        return Err("Token amount must be greater than 0".to_string());
    }
    Ok(())
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

async fn verify_message(
    Json(request): Json<VerifyMessageRequest>,
) -> Result<ResponseJson<ApiResponse<VerifyMessageResponse>>, StatusCode> {
    // Validate required fields
    if request.message.is_empty() || request.signature.is_empty() || request.pubkey.is_empty() {
        return Ok(ResponseJson(ApiResponse::error(
            "Missing required fields".to_string(),
        )));
    }

    // Parse public key
    let pubkey = match pubkey_from_string(&request.pubkey) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::error(e)));
        }
    };

    // Parse signature
    let signature = match signature_from_string(&request.signature) {
        Ok(sig) => sig,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::error(e)));
        }
    };

    // Verify the signature
    let message_bytes = request.message.as_bytes();
    let is_valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    let response = VerifyMessageResponse {
        valid: is_valid,
        message: request.message,
        pubkey: request.pubkey,
    };

    Ok(ResponseJson(ApiResponse::success(response)))
}

async fn send_sol(
    Json(request): Json<SendSolRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionResponse>>, StatusCode> {
    // Validate required fields
    if request.from.is_empty() || request.to.is_empty() {
        return Ok(ResponseJson(ApiResponse::error(
            "Missing required fields".to_string(),
        )));
    }

    // Validate lamports amount
    if let Err(e) = validate_lamports(request.lamports) {
        return Ok(ResponseJson(ApiResponse::error(e)));
    }

    // Parse public keys
    let from_pubkey = match pubkey_from_string(&request.from) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::error(e)));
        }
    };

    let to_pubkey = match pubkey_from_string(&request.to) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::error(e)));
        }
    };

    // Ensure sender and recipient are different
    if from_pubkey == to_pubkey {
        return Ok(ResponseJson(ApiResponse::error(
            "Sender and recipient cannot be the same".to_string(),
        )));
    }

    // Create the transfer instruction
    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, request.lamports);

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

async fn send_token(
    Json(request): Json<SendTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionResponse>>, StatusCode> {
    // Validate required fields
    if request.destination.is_empty() || request.mint.is_empty() || request.owner.is_empty() {
        return Ok(ResponseJson(ApiResponse::error(
            "Missing required fields".to_string(),
        )));
    }

    // Validate token amount
    if let Err(e) = validate_token_amount(request.amount) {
        return Ok(ResponseJson(ApiResponse::error(e)));
    }

    // Parse public keys
    let destination = match pubkey_from_string(&request.destination) {
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

    let owner = match pubkey_from_string(&request.owner) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(ResponseJson(ApiResponse::error(e)));
        }
    };

    // For SPL token transfers, we need to derive the associated token accounts
    // This is a simplified version - in practice, you'd need to handle associated token accounts
    let source = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    let destination_ata = spl_associated_token_account::get_associated_token_address(&destination, &mint);

    // Create the transfer instruction
    let instruction = transfer(
        &spl_token::id(),
        &source,           // source token account
        &destination_ata,  // destination token account
        &owner,            // owner of source account
        &[],               // multisig signers (empty for single sig)
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

#[tokio::main]
async fn main() {
    println!("starting the http server...");

    let app = Router::new()
        .route("/", get(root))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(CorsLayer::permissive());

    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect(&format!("Failed to bind to {}", addr));
    
    println!("Server running on http://localhost:3000");
    println!("available endpoints:");
    println!("   GET  /                 - Server status");
    println!("   POST /keypair          - Generate keypair");
    println!("   POST /token/create     - Create token");
    println!("   POST /token/mint       - Mint tokens");
    println!("   POST /message/sign     - Sign message");
    println!("   POST /message/verify   - Verify message signature");
    println!("   POST /send/sol         - Send SOL transfer");
    println!("   POST /send/token       - Send SPL token transfer");
    
    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}