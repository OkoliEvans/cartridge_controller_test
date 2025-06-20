mod wallet;

use actix_web::{middleware::Logger, post, web::{self}, App, HttpResponse, HttpServer, Result};
use serde::Serialize;

use starknet::accounts::Account;
use wallet::models::{
    CreateSessionRequest, CreateSessionResponse, ReceivePaymentRequest, 
    WithdrawRequest, SystemManagementRequest, TransactionResponse, ControllerInfo
};

use crate::wallet::cartridge::ControllerService;

pub struct AppState {
    pub env: Environment,
}

#[derive(Clone)]
pub struct Environment {
    pub kharon_pay_contract_address: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

async fn create_session(
    app_state: web::Data<AppState>,
    req: web::Json<CreateSessionRequest>,
) -> Result<HttpResponse> {
    let service = ControllerService::new(app_state);
    
    match service.create_controller(&req.user_email, &req.user_permissions).await {
        Ok((controller, username, session_options)) => {
            let response = CreateSessionResponse {
                controller_address: format!("{:#x}", controller.address()),
                username,
                session_id: "generated_session_id".to_string(),
                session_options,
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            eprintln!("Failed to create session: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "session_creation_failed".to_string(),
                message: format!("Failed to create session: {}", e),
            }))
        }
    }
}

// Receive payment endpoint
async fn receive_payment(
    app_state: web::Data<AppState>,
    req: web::Json<ReceivePaymentRequest>,
) -> Result<HttpResponse> {
    let service = ControllerService::new(app_state.clone());
    
    // create/get the controller for this user
    let user_permissions = vec!["user".to_string()]; 
    
    match service.create_controller(&req.user_email, &user_permissions).await {
        Ok((controller, _username, _session_options)) => {
            match service.receive_payment(
                &controller,
                &req.token,
                &req.amount,
                &req.reference,
                &req.user_email,
            ).await {
                Ok(transaction_response) => {
                    Ok(HttpResponse::Ok().json(transaction_response))
                }
                Err(e) => {
                    eprintln!("Failed to process payment: {}", e);
                    Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "payment_processing_failed".to_string(),
                        message: format!("Failed to process payment: {}", e),
                    }))
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to create controller for payment: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "controller_creation_failed".to_string(),
                message: format!("Failed to create controller for payment: {}", e),
            }))
        }
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    let port = 5000;
    
    println!("🚀 Starting Kharon Pay API server on port {}", port);
    
    let app_state = web::Data::new(AppState { 
        env: Environment {
            kharon_pay_contract_address: "0x01f103e6694fcbdf2bfbe8db10d7b622bfab12da196ea1f212cb26367196af2c".to_string(),
        }
    });
    
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(Logger::default())
            .wrap(
                actix_cors::Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header()
                    .max_age(3600)
            )
            .service(
                web::scope("/api/v1")
                    .service(
                        web::scope("/session")
                            .route("/create", web::post().to(create_session))
                    )
                    .service(
                        web::scope("/payment")
                            .route("/receive", web::post().to(receive_payment))
                    )
                    // .service(
                    //     web::scope("/admin")
                    //         .route("/withdraw", web::post().to(withdraw))
                    //         .route("/pause", web::post().to(pause_system))
                    //         .route("/unpause", web::post().to(unpause_system))
                    // )
            )
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}

