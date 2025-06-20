use std::{collections::HashMap, vec};

use account_sdk::{
    artifacts::{CONTROLLERS, Version},
    controller::Controller,
    factory::ControllerFactory,
    provider::CartridgeJsonRpcProvider,
    signers::{Owner, Signer},
};

use account_sdk::account::session::policy::Policy;
use actix_web::web;
use starknet::{
    accounts::{Account, AccountFactory, AccountFactoryError},
    core::{
        types::{Call, Felt, StarknetError},
        utils::cairo_short_string_to_felt,
    },
    macros::{felt, selector},
    providers::ProviderError,
    signers::SigningKey,
};
use url::Url;

use crate::{
    AppState,
    wallet::models::{
        ContractMethod, SessionOptions, SessionPolicies, SignMessagePolicy, StarknetDomain,
        StarknetType, TransactionResponse,
    },
};

pub struct ControllerService {
    app_state: web::Data<AppState>,
}

impl ControllerService {
    pub fn new(app_state: web::Data<AppState>) -> Self {
        Self { app_state }
    }

    fn extract_username(&self, email: &str) -> String {
        email.split('@').next().unwrap_or(email).to_string()
    }

    async fn generate_session_policies(&self, user_permissions: &[String]) -> SessionPolicies {
        let rpc_url: Url =
            Url::parse("https://api.cartridge.gg/x/starknet/sepolia").expect("Invalid RPC URL");
        let provider = CartridgeJsonRpcProvider::new(rpc_url.clone());

        let chain_id = felt!("0x534e5f5345504f4c4941"); // Hex for "SN_SEPOLIA"
        // let chain_id = felt!("0x534e5f4d41494e"); // Hex for "SN_MAIN"

        let signer_key = felt!("0x0123034aeb5633f1ed59eefcd12eee41368b709e2a4d155ed464329f01d5a456");
        let signer = SigningKey::from_secret_scalar(signer_key);

        let owner = Owner::Signer(Signer::Starknet(signer.clone()));

        let mut methods = Vec::new();

        methods.extend(vec![ContractMethod {
            name: "Receive Payment".to_string(),
            entrypoint: "receive_payment".to_string(),
            description: Some("Receive payment from users to offramp".to_string()),
        }]);

        if user_permissions.contains(&"admin".to_string()) {
            methods.extend(vec![
                ContractMethod {
                    name: "Add Supported Token".to_string(),
                    entrypoint: "add_supported_token".to_string(),
                    description: Some("Add a new supported token".to_string()),
                },
                ContractMethod {
                    name: "Remove Supported Token".to_string(),
                    entrypoint: "remove_supported_token".to_string(),
                    description: Some("Remove a supported token".to_string()),
                },
                ContractMethod {
                    name: "Withdraw".to_string(),
                    entrypoint: "withdraw".to_string(),
                    description: Some("Withdraw tokens from the contract".to_string()),
                },
                ContractMethod {
                    name: "Pause System".to_string(),
                    entrypoint: "pause_system".to_string(),
                    description: Some("Pause the payment system".to_string()),
                },
                ContractMethod {
                    name: "Unpause System".to_string(),
                    entrypoint: "unpause_system".to_string(),
                    description: Some("Unpause the payment system".to_string()),
                },
            ]);
        }

        let contract = self.app_state.env.kharon_pay_contract_address.clone();

        let message_policy = SignMessagePolicy {
            name: Some("Kharon Pay Message Signing Policy".to_string()),
            description: Some("Allows signing messages for Kharon Pay transactions".to_string()),
            types: {
                let mut types = HashMap::new();
                types.insert(
                    "StarknetDomain".to_string(),
                    vec![
                        StarknetType {
                            name: "name".to_string(),
                            type_name: "shortstring".to_string(),
                        },
                        StarknetType {
                            name: "version".to_string(),
                            type_name: "shortstring".to_string(),
                        },
                        StarknetType {
                            name: "chainId".to_string(),
                            type_name: "shortstring".to_string(),
                        },
                        StarknetType {
                            name: "revision".to_string(),
                            type_name: "shortstring".to_string(),
                        },
                    ],
                );
                types.insert(
                    "KharonPayMessage".to_string(),
                    vec![
                        StarknetType {
                            name: "user".to_string(),
                            type_name: "ContractAddress".to_string(),
                        },
                        StarknetType {
                            name: "action".to_string(),
                            type_name: "shortstring".to_string(),
                        },
                        StarknetType {
                            name: "amount".to_string(),
                            type_name: "felt".to_string(),
                        },
                        StarknetType {
                            name: "token".to_string(),
                            type_name: "ContractAddress".to_string(),
                        },
                        StarknetType {
                            name: "timestamp".to_string(),
                            type_name: "felt".to_string(),
                        },
                        StarknetType {
                            name: "nonce".to_string(),
                            type_name: "felt".to_string(),
                        },
                    ],
                );
                types
            },
            primary_type: "KharonPayMessage".to_string(),
            domain: StarknetDomain {
                name: "KharonPay".to_string(),
                version: "1".to_string(),
                chain_id: chain_id.to_string(),
                revision: "1".to_string(),
            },
        };

        SessionPolicies {
            contract,
            messages: Some(vec![message_policy]),
        }
    }

    pub async fn create_controller(
        &self,
        user_email: &str,
        user_permissions: &[String],
    ) -> Result<(Controller, String, SessionOptions), Box<dyn std::error::Error>> {
        let username = self.extract_username(user_email);

        let rpc_url: Url =
            Url::parse("https://api.cartridge.gg/x/starknet/sepolia").expect("Invalid RPC URL");
        let provider = CartridgeJsonRpcProvider::new(rpc_url.clone());

        let chain_id = felt!("0x534e5f5345504f4c4941"); // Hex for "SN_SEPOLIA"
        // let chain_id = felt!("0x534e5f4d41494e"); // Hex for "SN_MAIN"

        let signer_key = felt!("0x0123034aeb5633f1ed59eefcd12eee41368b709e2a4d155ed464329f01d5a456");
        let signer = SigningKey::from_secret_scalar(signer_key);
        let owner = Owner::Signer(Signer::Starknet(signer.clone()));

        let salt = cairo_short_string_to_felt(&username)?;

        let factory = ControllerFactory::new(
            CONTROLLERS[&Version::LATEST].hash,
            chain_id,
            owner.clone(),
            provider,
        );

        let address = factory.address(salt);

        println!("Controller address for {}: {:#x}", username, address);

        match factory
            .deploy_v3(salt)
            .gas_estimate_multiplier(1.5)
            .send()
            .await
        {
            Ok(_) => println!("Controller deployed successfully"),
            Err(e) => {
                if let AccountFactoryError::Provider(ProviderError::StarknetError(
                    StarknetError::TransactionExecutionError(ref error_data),
                )) = e
                {
                    if !error_data
                        .execution_error
                        .contains("is unavailable for deployment")
                    {
                        println!("Deployment failed: {:?}", e);
                        return Err(Box::new(e));
                    }
                    // If it's already deployed, continue
                    println!("Controller already deployed, continuing...");
                } else {
                    println!("Deployment failed: {:?}", e);
                    return Err(Box::new(e));
                }
            }
        }

        let mut controller = Controller::new(
            "KharonPay".to_string(),
            username.clone(),
            CONTROLLERS[&Version::LATEST].hash,
            rpc_url,
            owner.clone(),
            address,
            chain_id,
        );

        let session_policies = self.generate_session_policies(user_permissions).await;

        let mut policies = Vec::new();

        let contract_address = Felt::from_hex(&session_policies.contract)?;

        policies.push(Policy::new_call(
            contract_address,
            selector!("receive_payment"),
        ));

        // Add admin policies if user has admin permissions
        if user_permissions.contains(&"admin".to_string()) {
            policies.extend(vec![
                Policy::new_call(contract_address, selector!("add_supported_token")),
                Policy::new_call(contract_address, selector!("remove_supported_token")),
                Policy::new_call(contract_address, selector!("withdraw")),
                Policy::new_call(contract_address, selector!("pause_system")),
                Policy::new_call(contract_address, selector!("unpause_system")),
            ]);
        }

        let _ = controller.create_session(policies, u32::MAX as u64).await?;

        let session_options = SessionOptions {
            policies: session_policies,
            expires_at: u32::MAX as u64,
        };

        Ok((controller, username.clone(), session_options))
    }

    pub async fn receive_payment(
        &self,
        controller: &Controller,
        token: &str,
        amount: &str,
        reference: &str,
        user_id: &str,
    ) -> Result<TransactionResponse, Box<dyn std::error::Error>> {
        let contract_address = Felt::from_hex(&self.app_state.env.kharon_pay_contract_address)?;
        let token_address = Felt::from_hex(token)?;
        let amount_felt = Felt::from_hex(amount)?;
        let reference_felt = Felt::from_hex(reference)?;
        let user_id = Felt::from_hex(user_id)?;

        let call = Call {
            to: contract_address,
            selector: selector!("receive_payment"),
            calldata: vec![token_address, amount_felt, reference_felt, user_id],
        };

        match controller.execute_v3(vec![call]).send().await {
            Ok(result) => Ok(TransactionResponse {
                transaction_hash: format!("{:#x}", result.transaction_hash.clone()),
                status: "success".to_string(),
                function_called: "receive_payment".to_string(),
                message: Some("Payment processed successfully".to_string()),
            }),
            Err(e) => Ok(TransactionResponse {
                transaction_hash: "0x0".to_string(),
                status: "failed".to_string(),
                function_called: "receive_payment".to_string(),
                message: Some(format!("Failed to process payment: {}", e.to_string())),
            }),
        }
    }
}
