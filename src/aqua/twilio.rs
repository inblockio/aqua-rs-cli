use std::env;
use std::fmt;

/// Twilio Verify API credentials loaded from environment variables.
pub struct TwilioConfig {
    pub account_sid: String,
    pub auth_token: String,
    pub verify_service_sid: String,
}

/// Whether to send the verification code via SMS or email.
pub enum VerificationChannel {
    Sms,
    Email,
}

impl VerificationChannel {
    fn as_str(&self) -> &'static str {
        match self {
            VerificationChannel::Sms => "sms",
            VerificationChannel::Email => "email",
        }
    }
}

/// Errors that can occur when interacting with the Twilio Verify API.
#[derive(Debug)]
pub enum TwilioError {
    /// One or more required environment variables are missing.
    MissingEnv(String),
    /// HTTP request to Twilio failed.
    Http(reqwest::Error),
    /// Twilio returned a non-success status code.
    Api { status: u16, body: String },
}

impl fmt::Display for TwilioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TwilioError::MissingEnv(msg) => write!(f, "Missing Twilio env var: {}", msg),
            TwilioError::Http(e) => write!(f, "Twilio HTTP error: {}", e),
            TwilioError::Api { status, body } => {
                write!(f, "Twilio API error (HTTP {}): {}", status, body)
            }
        }
    }
}

impl From<reqwest::Error> for TwilioError {
    fn from(e: reqwest::Error) -> Self {
        TwilioError::Http(e)
    }
}

impl TwilioConfig {
    /// Read Twilio credentials from environment variables.
    ///
    /// Required: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_VERIFY_SERVICE_SID`.
    pub fn from_env() -> Result<Self, TwilioError> {
        let account_sid = env::var("TWILIO_ACCOUNT_SID").map_err(|_| {
            TwilioError::MissingEnv("TWILIO_ACCOUNT_SID not set".to_string())
        })?;
        let auth_token = env::var("TWILIO_AUTH_TOKEN").map_err(|_| {
            TwilioError::MissingEnv("TWILIO_AUTH_TOKEN not set".to_string())
        })?;
        let verify_service_sid = env::var("TWILIO_VERIFY_SERVICE_SID").map_err(|_| {
            TwilioError::MissingEnv("TWILIO_VERIFY_SERVICE_SID not set".to_string())
        })?;

        Ok(Self {
            account_sid,
            auth_token,
            verify_service_sid,
        })
    }
}

/// Send a verification code to the given recipient via the specified channel.
///
/// POST `https://verify.twilio.com/v2/Services/{sid}/Verifications`
pub async fn send_verification_code(
    config: &TwilioConfig,
    to: &str,
    channel: &VerificationChannel,
) -> Result<(), TwilioError> {
    let url = format!(
        "https://verify.twilio.com/v2/Services/{}/Verifications",
        config.verify_service_sid
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .basic_auth(&config.account_sid, Some(&config.auth_token))
        .form(&[("To", to), ("Channel", channel.as_str())])
        .send()
        .await?;

    let status = resp.status().as_u16();
    if status >= 200 && status < 300 {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(TwilioError::Api { status, body })
    }
}

/// Check a verification code entered by the user.
///
/// POST `https://verify.twilio.com/v2/Services/{sid}/VerificationChecks`
///
/// Returns `true` if the Twilio response status is `"approved"`.
pub async fn check_verification_code(
    config: &TwilioConfig,
    to: &str,
    code: &str,
) -> Result<bool, TwilioError> {
    let url = format!(
        "https://verify.twilio.com/v2/Services/{}/VerificationCheck",
        config.verify_service_sid
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .basic_auth(&config.account_sid, Some(&config.auth_token))
        .form(&[("To", to), ("Code", code)])
        .send()
        .await?;

    let status = resp.status().as_u16();
    if status >= 200 && status < 300 {
        let body: serde_json::Value = resp.json().await?;
        let verified = body
            .get("status")
            .and_then(|v| v.as_str())
            .map(|s| s == "approved")
            .unwrap_or(false);
        Ok(verified)
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(TwilioError::Api { status, body })
    }
}
