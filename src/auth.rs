use base64;
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT},
    Client,
};
use serde::{de::Error, Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use thiserror::Error;
use tokio::time::{self, Duration};

const LOGIN_URL: &str = "https://api.twitter.com/1.1/onboarding/task.json";
const LOGOUT_URL: &str = "https://api.twitter.com/1.1/account/logout.json";
const OAUTH_URL: &str = "https://api.twitter.com/oauth2/token";
const GUEST_TOKEN_URL: &str = "https://api.twitter.com/1.1/guest/activate.json";
const VERIFY_CREDENTIALS_URL: &str = "https://api.twitter.com/1.1/account/verify_credentials.json";
const BEARER_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";
const APP_CONSUMER_KEY: &str = "3nVuSoBZnx6U4vzUxf5w";
const APP_CONSUMER_SECRET: &str = "Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys";

#[derive(Debug, Deserialize)]
struct Flow {
    errors: Option<Vec<FlowError>>,
    flow_token: Option<String>,
    subtasks: Option<Vec<Subtask>>,
}

#[derive(Debug, Deserialize)]
struct FlowError {
    code: i32,
    message: String,
}

#[derive(Debug, Deserialize)]
struct Subtask {
    subtask_id: String,
    open_account: Option<OpenAccount>,
}

#[derive(Debug, Deserialize)]
struct OpenAccount {
    oauth_token: String,
    oauth_token_secret: String,
}

#[derive(Debug, Deserialize)]
struct VerifyCredentials {
    errors: Option<Vec<FlowError>>,
}

#[derive(Debug, Deserialize)]
struct GuestTokenResponse {
    guest_token: String,
}

#[derive(Debug, Error)]
pub enum ScraperError {
    #[error("network request failed: {0}")]
    Network(#[from] reqwest::Error),

    #[error("error parsing response: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("authentication error (code: {code}): {message}")]
    Auth { code: i32, message: String },

    #[error("missing data: {0}")]
    MissingData(&'static str),

    #[error("unknown error: {0}")]
    Unknown(String),
}

struct Scraper {
    client: Client,
    is_logged: bool,
    guest_token: Option<String>,
    bearer_token: String,
    o_auth_token: Option<String>,
    o_auth_secret: Option<String>,
}

impl Scraper {
    fn new() -> Self {
        Scraper {
            client: Client::builder().cookie_store(true).build().unwrap(),
            is_logged: false,
            guest_token: None,
            bearer_token: BEARER_TOKEN.to_string(),
            o_auth_token: None,
            o_auth_secret: None,
        }
    }

    async fn get_access_token(
        &self,
        consumer_key: &str,
        consumer_secret: &str,
    ) -> Result<String, ScraperError> {
        let client = &self.client;
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let credentials = base64::encode(format!("{}:{}", consumer_key, consumer_secret));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", credentials)).unwrap(),
        );

        let response = client
            .post(OAUTH_URL)
            .headers(headers)
            .body("grant_type=client_credentials")
            .send()
            .await?;

        if response.status().is_success() {
            let json: HashMap<String, String> = response.json().await?;
            json.get("access_token")
                .cloned()
                .ok_or(ScraperError::MissingData("access_token"))
        } else {
            let status = response.status();
            let err_text = response.text().await?;
            Err(ScraperError::Unknown(format!(
                "Failed to get access token: {}, {}",
                err_text, status
            )))
        }
    }

    async fn get_guest_token(&mut self) -> Result<(), ScraperError> {
        let client = &self.client;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.bearer_token)).unwrap(),
        );

        let response = client.post(GUEST_TOKEN_URL).headers(headers).send().await?;

        if response.status().is_success() {
            let json: GuestTokenResponse = response.json().await?;
            self.guest_token = Some(json.guest_token);
            Ok(())
        } else {
            let status = response.status();
            let err_text = response.text().await?;
            Err(ScraperError::Unknown(format!(
                "Failed to get guest token: {}, {}",
                err_text, status
            )))
        }
    }

    async fn get_flow(&self, data: &serde_json::Value) -> Result<Flow, ScraperError> {
        let client = &self.client;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.bearer_token)).unwrap(),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(USER_AGENT, HeaderValue::from_static("TwitterAndroid/99"));
        if let Some(guest_token) = &self.guest_token {
            headers.insert("X-Guest-Token", HeaderValue::from_str(guest_token).unwrap());
        }
        headers.insert(
            "X-Twitter-Auth-Type",
            HeaderValue::from_static("OAuth2Client"),
        );
        headers.insert("X-Twitter-Active-User", HeaderValue::from_static("yes"));
        headers.insert("X-Twitter-Client-Language", HeaderValue::from_static("en"));

        let response = client
            .post(LOGIN_URL)
            .headers(headers)
            .json(data)
            .send()
            .await?;

        let status = response.status();
        let response_text = response.text().await?;
        if status.is_success() {
            serde_json::from_str(&response_text).map_err(|e| {
                ScraperError::Parse(serde_json::Error::custom(format!(
                    "Failed to parse response: {}, body: {}",
                    e, response_text
                )))
            })
        } else {
            Err(ScraperError::Unknown(format!(
                "Request failed: status {}, body: {}",
                status, response_text
            )))
        }
    }

    async fn get_flow_token(&self, data: &serde_json::Value) -> Result<String, ScraperError> {
        let info = self.get_flow(data).await?;

        if let Some(errors) = info.errors {
            if let Some(error) = errors.get(0) {
                return Err(ScraperError::Auth {
                    code: error.code,
                    message: error.message.clone(),
                });
            }
        }

        if let Some(subtasks) = info.subtasks {
            for subtask in &subtasks {
                match subtask.subtask_id.as_str() {
                    "LoginEnterAlternateIdentifierSubtask"
                    | "LoginAcid"
                    | "LoginTwoFactorAuthChallenge"
                    | "DenyLoginSubtask" => {
                        return Err(ScraperError::Auth {
                            code: 1,
                            message: subtask.subtask_id.clone(),
                        });
                    }
                    _ => {}
                }
            }
        }

        info.flow_token
            .ok_or(ScraperError::MissingData("flow_token"))
    }

    async fn get_open_account_tokens(&mut self, flow_token: &str) -> Result<(), ScraperError> {
        let data = json!({
            "flow_token": flow_token,
            "subtask_inputs": [{
                "subtask_id": "OpenAccount",
                "open_account": {}
            }]
        });

        let flow_response = self.get_flow(&data).await?;

        for subtask in flow_response.subtasks.unwrap_or_default() {
            if let Some(open_account) = subtask.open_account {
                self.o_auth_token = Some(open_account.oauth_token);
                self.o_auth_secret = Some(open_account.oauth_token_secret);
                return Ok(());
            }
        }

        Err(ScraperError::MissingData("OpenAccount tokens"))
    }

    async fn is_logged_in(&self) -> bool {
        let response = self
            .client
            .get(VERIFY_CREDENTIALS_URL)
            .header(AUTHORIZATION, format!("Bearer {}", self.bearer_token))
            .send()
            .await;

        match response {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<VerifyCredentials>().await {
                        Ok(json) => json.errors.is_none(),
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    async fn login(
        &mut self,
        username: &str,
        password: &str,
        confirmation: Option<&str>,
    ) -> Result<(), ScraperError> {
        self.bearer_token = BEARER_TOKEN.to_string();

        // Get guest token
        self.get_guest_token().await?;
        println!("Guest token: {:?}", self.guest_token);

        // Flow start
        let mut data = json!({
            "flow_name": "login",
            "input_flow_data": { "flow_context": { "debug_overrides": {}, "start_location": { "location": "splash_screen" }}}
        });

        let mut flow_token = self.get_flow_token(&data).await?;
        println!("Flow token step 1: {}", flow_token);

        // Flow instrumentation step
        data = json!({
            "flow_token": flow_token,
            "subtask_inputs": [ {
                "subtask_id": "LoginJsInstrumentationSubtask",
                "js_instrumentation": { "response": "{}", "link": "next_link" }
            }]
        });
        flow_token = self.get_flow_token(&data).await?;
        println!("Flow token step 2: {}", flow_token);

        // Flow username step
        data = json!({
            "flow_token": flow_token,
            "subtask_inputs": [{
                "subtask_id": "LoginEnterUserIdentifierSSO",
                "settings_list": {
                    "setting_responses": [{
                        "key": "user_identifier",
                        "response_data": { "text_data": { "result": username }}
                    }],
                    "link": "next_link"
                }
            }]
        });
        flow_token = self.get_flow_token(&data).await?;
        println!("Flow token step 3: {}", flow_token);

        // Flow password step
        data = json!({
            "flow_token": flow_token,
            "subtask_inputs": [{
                "subtask_id": "LoginEnterPassword",
                "enter_password": { "password": password, "link": "next_link" }
            }]
        });
        flow_token = self.get_flow_token(&data).await?;
        println!("Flow token step 4: {}", flow_token);

        // Flow duplication check
        data = json!({
            "flow_token": flow_token,
            "subtask_inputs": [{
                "subtask_id": "AccountDuplicationCheck",
                "check_logged_in_account": { "link": "AccountDuplicationCheck_false" }
            }]
        });
        let flow_token_result = self.get_flow_token(&data).await;

        match flow_token_result {
            Ok(_) => {
                self.is_logged = true;
                Ok(())
            }
            Err(err) => {
                if let Some(confirmation_subtask) = ["LoginAcid", "LoginTwoFactorAuthChallenge"]
                    .iter()
                    .find(|&&s| err.to_string().contains(s))
                {
                    if let Some(confirmation) = confirmation {
                        // Handle confirmation step
                        data = json!({
                            "flow_token": flow_token,
                            "subtask_inputs": [{
                                "subtask_id": confirmation_subtask,
                                "enter_text": { "text": confirmation, "link": "next_link" }
                            }]
                        });
                        let token_result = self.get_flow_token(&data).await?;
                        // Once confirmed, get the open account tokens
                        self.get_open_account_tokens(&token_result).await?;
                        self.is_logged = true;
                        return Ok(());
                    } else {
                        return Err(ScraperError::Unknown(format!(
                            "confirmation data required for {}",
                            confirmation_subtask
                        )));
                    }
                } else {
                    return Err(err);
                }
            }
        }
    }

    async fn logout(&mut self) -> Result<(), ScraperError> {
        let response = self
            .client
            .post(LOGOUT_URL)
            .header(AUTHORIZATION, format!("Bearer {}", self.bearer_token))
            .send()
            .await?;

        if response.status().is_success() {
            self.is_logged = false;
            self.o_auth_token = None;
            self.o_auth_secret = None;
            self.guest_token = None;
            self.bearer_token = BEARER_TOKEN.to_string();
            self.client = Client::builder().cookie_store(true).build().unwrap();
            Ok(())
        } else {
            let status = response.status();
            let error_text: String = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to get error text".to_string());
            Err(ScraperError::Unknown(format!(
                "Failed to logout: {}, {}",
                error_text, status
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_login() {
        let mut scraper = Scraper::new();
        match scraper.login("", "", None).await {
            Ok(_) => println!("Login successful"),
            Err(e) => println!("Error logging in: {}", e),
        }

        assert_eq!(scraper.is_logged_in().await, true);
    }
}
