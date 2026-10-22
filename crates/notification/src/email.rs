//! `EmailService`, `SMTPService` and `SendGridService` of the notification service: one mail per
//! recipient, rendered from the notification's `email` template, through the MAIL connection
//! named by the notification connection.
//!
//! These differ from core's email services (which `connections::email` ports) and are kept as
//! Java has them: SMTP checks the recipient and the connection and answers `false` instead of
//! failing, and a mail the server refuses is only logged; SendGrid checks less, and a refusal
//! (or a recipient without an address) fails the whole notification.

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use connections::connection::{Connection, ConnectionSubType, ConnectionType};
use connections::email::ProcessedEmail;
use connections::java::{is_blank, to_java_string};
use serde_json::{json, Map, Value};

use crate::model::{CoreNotification, MailConnection, NotificationUser};
use crate::template::{language, processed_template};

pub const EMAIL_TEMPLATE_NAME: &str = "email";

/// Where the send service hands each recipient's mail (the Java test mocks this service).
#[async_trait]
pub trait EmailSink: Send + Sync {
    async fn send_email(
        &self,
        user: &NotificationUser,
        mail: &MailConnection,
        notification: &CoreNotification,
        payload: &Map<String, Value>,
    ) -> Result<bool>;
}

/// `StringUtil.safeValueOf(obj)`: the value's `toString()`, `None` for null.
fn safe_value_of(v: Option<&Value>) -> Option<String> {
    match v {
        None | Some(Value::Null) => None,
        Some(v) => Some(to_java_string(v)),
    }
}

fn safe_is_blank(v: Option<&str>) -> bool {
    v.is_none_or(is_blank)
}

pub struct EmailService {
    pub sendgrid_url: String,
    pub http: reqwest::Client,
    /// SMTP hosts must resolve only to public addresses.
    pub block_private_targets: bool,
}

impl EmailService {
    pub fn new(sendgrid_url: &str) -> Result<Self> {
        Ok(Self {
            sendgrid_url: sendgrid_url.to_string(),
            http: reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?,
            block_private_targets: true,
        })
    }

    /// The rendered `email` parts, `None` when they come out empty.
    fn rendered(notification: &CoreNotification, payload: &Map<String, Value>) -> Result<Option<std::collections::HashMap<String, String>>> {
        let lang = language(notification, payload)?;
        let t = processed_template(lang.as_deref(), notification.channel(EMAIL_TEMPLATE_NAME), payload)?;
        Ok((!t.is_empty()).then_some(t))
    }

    /// `SMTPService.sendMail`.
    pub async fn smtp(&self, user: &NotificationUser, mail: &MailConnection, n: &CoreNotification, payload: &Map<String, Value>) -> Result<bool> {
        let Some(email) = user.email_id.as_deref() else { return Ok(false) };
        if is_blank(email) || email.eq_ignore_ascii_case("NONE") || !email.contains('@') {
            return Ok(false);
        }
        let Some(details) = mail.connection_details.as_ref().filter(|d| !d.is_empty()) else { return Ok(false) };
        let props = match details.get("mailProps") {
            None | Some(Value::Null) => return Ok(false),
            Some(Value::Object(p)) if p.is_empty() => return Ok(false),
            Some(Value::Object(p)) => p.clone(),
            Some(other) => bail!("class {} cannot be cast to class java.util.Map", java_class(other)),
        };
        let user_name = safe_value_of(details.get("username"));
        let password = safe_value_of(details.get("password"));
        if safe_is_blank(user_name.as_deref()) || safe_is_blank(password.as_deref()) {
            return Ok(false);
        }
        let from = safe_value_of(details.get("fromAddress"));
        let Some(from) = from.filter(|f| !is_blank(f)) else { return Ok(false) };

        let Some(t) = Self::rendered(n, payload)? else { return Ok(false) };
        // A null body makes JavaMail fail while writing the message (a NullPointerException,
        // which is not caught); nothing is delivered and the notification stops there.
        let body = t
            .get("body")
            .cloned()
            .ok_or_else(|| anyhow!("\"text/html\" DataContentHandler requires String object, was given null"))?;

        let mut cd = Map::new();
        cd.insert("mailProps".into(), Value::Object(props));
        cd.insert("username".into(), Value::from(user_name.unwrap_or_default()));
        cd.insert("password".into(), Value::from(password.unwrap_or_default()));
        let conn = Connection {
            connection_type: Some(ConnectionType::Mail),
            connection_sub_type: Some(ConnectionSubType::Smtp),
            connection_details: Some(cd),
            ..Default::default()
        };
        let details = ProcessedEmail {
            to: vec![email.to_string()],
            from,
            subject: t.get("subject").cloned().unwrap_or_default(),
            body,
            attachments: Vec::new(),
        };
        // Transport.send's MessagingException is logged, and the answer is still true.
        if let Err(e) = connections::email::smtp_send(&conn, &details, self.block_private_targets).await {
            tracing::error!("Error while adding : {email} {}", e.message());
        }
        Ok(true)
    }

    /// `SendGridService.sendMail`.
    pub async fn sendgrid(&self, user: &NotificationUser, mail: &MailConnection, n: &CoreNotification, payload: &Map<String, Value>) -> Result<bool> {
        let Some(details) = mail.connection_details.as_ref() else { return Ok(false) };
        let api_key = safe_value_of(details.get("apiKey"));
        let Some(api_key) = api_key.filter(|k| !is_blank(k)) else { return Ok(false) };
        let from = safe_value_of(details.get("fromAddress"));
        let Some(from) = from.filter(|f| !is_blank(f)) else { return Ok(false) };

        let Some(t) = Self::rendered(n, payload)? else { return Ok(false) };
        // Map.of refuses nulls: a recipient without an address, or a template without a subject
        // or body, fails the notification.
        let to = user.email_id.clone().ok_or_else(|| anyhow!("Map.of: the recipient's email is null"))?;
        let subject = t.get("subject").cloned().ok_or_else(|| anyhow!("Map.of: the subject is null"))?;
        let body = t.get("body").cloned().ok_or_else(|| anyhow!("Map.of: the body is null"))?;
        let payload = json!({
            "personalizations": [{"to": [{"email": to}]}],
            "from": {"email": from},
            "subject": subject,
            "content": [{"type": "text/html", "value": body}],
        });
        let rb = self
            .http
            .post(&self.sendgrid_url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .body(payload.to_string());
        let resp = platform::meter::send("sendgrid", rb).await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        // RestClient's retrieve(): a 4xx or 5xx is an exception.
        if status.is_client_error() || status.is_server_error() {
            bail!("{status} from POST {}: \"{text}\"", self.sendgrid_url);
        }
        // `.body(String.class) != null`: SendGrid's usual empty 202 reads as false.
        Ok(!text.is_empty())
    }
}

/// The Java class name a JSON value is read into, for the cast failure message.
fn java_class(v: &Value) -> &'static str {
    match v {
        Value::String(_) => "java.lang.String",
        Value::Bool(_) => "java.lang.Boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "java.lang.Integer",
        Value::Number(_) => "java.lang.Double",
        Value::Array(_) => "java.util.ArrayList",
        _ => "java.lang.Object",
    }
}

#[async_trait]
impl EmailSink for EmailService {
    /// `EmailService.sendEmail`: the service for the MAIL connection's sub type; any other sub
    /// type finds no service (a `NullPointerException` in Java).
    async fn send_email(&self, user: &NotificationUser, mail: &MailConnection, n: &CoreNotification, payload: &Map<String, Value>) -> Result<bool> {
        match mail.connection_sub_type.as_deref() {
            Some("SENDGRID") => self.sendgrid(user, mail, n, payload).await,
            Some("SMTP") => self.smtp(user, mail, n, payload).await,
            other => Err(anyhow!(
                "Cannot invoke \"IAppEmailService.sendMail(...)\" because no email service is registered for {}",
                other.unwrap_or("null")
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(safe_value_of(None), None);
        assert_eq!(safe_value_of(Some(&Value::Null)), None);
        assert_eq!(safe_value_of(Some(&json!(5))).as_deref(), Some("5"));
        assert!(safe_is_blank(None) && safe_is_blank(Some(" ")) && !safe_is_blank(Some("x")));
        assert_eq!(java_class(&json!("x")), "java.lang.String");
        assert_eq!(java_class(&json!(true)), "java.lang.Boolean");
        assert_eq!(java_class(&json!(1)), "java.lang.Integer");
        assert_eq!(java_class(&json!(1.5)), "java.lang.Double");
        assert_eq!(java_class(&json!([])), "java.util.ArrayList");
        assert_eq!(java_class(&Value::Null), "java.lang.Object");
    }
}
