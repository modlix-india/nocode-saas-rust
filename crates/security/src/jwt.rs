//! The access token, exactly as `commons-security` `JWTUtil` makes and reads it (jjwt 0.11.5).
//!
//! Making: header `{"alg":"HS512"}`; the claims map is a Java `HashMap` (`JWTClaims.getClaimsMap`)
//! that replaces the issuer and subject set before it, so `iss` and `sub` never reach the token;
//! then `jti`, `iat`, `exp` are appended. Signed with HMAC-SHA512 over the key's UTF-8 bytes,
//! base64url without padding throughout. Same inputs, same bytes as Java.
//!
//! Reading: what `Jwts.parserBuilder().setSigningKey(...).parseClaimsJws(token)` accepts: a signed
//! token whose header names an HMAC algorithm, a valid signature, and an `exp` that has not
//! passed (no clock skew). `JWTClaims.from` then needs `userId` and `loggedInClientId` as numbers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{Map, Value};
use sha2::{Sha256, Sha384, Sha512};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub user_id: u64,
    pub host_name: Option<String>,
    pub port: Option<String>,
    pub logged_in_client_id: u64,
    pub logged_in_client_code: Option<String>,
    pub app_code: Option<String>,
    pub one_time: bool,
}

/// What a freshly made token carries besides its string: `iat` and `exp` in epoch seconds.
#[derive(Debug, Clone)]
pub struct Made {
    pub token: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug)]
pub enum JwtError {
    Malformed(&'static str),
    Signature,
    Expired,
    Premature,
    Claim(&'static str),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed token: {m}"),
            Self::Signature => write!(f, "JWT signature does not match locally computed signature"),
            Self::Expired => write!(f, "JWT expired"),
            Self::Premature => write!(f, "JWT must not be accepted before nbf"),
            Self::Claim(c) => write!(f, "claim {c} missing or of the wrong type"),
        }
    }
}

impl std::error::Error for JwtError {}

const HEADER_HS512: &str = r#"{"alg":"HS512"}"#;

/// `JWTUtil.newTokenId()`: 12 random bytes, base64url without padding.
pub fn new_token_id() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The claims JSON in Java's order. `jti`, `iat`, `exp` follow the `HashMap` part.
pub fn payload_json(c: &Claims, jti: &str, iat: i64, exp: i64) -> String {
    // HashMap iteration order of these seven keys (see javamap's test); absent ones are skipped.
    let mut m = Map::new();
    m.insert("hostName".into(), c.host_name.clone().map(Value::from).unwrap_or(Value::Null));
    m.insert("port".into(), c.port.clone().map(Value::from).unwrap_or(Value::Null));
    m.insert("loggedInClientId".into(), Value::from(c.logged_in_client_id));
    if let Some(code) = &c.logged_in_client_code {
        m.insert("loggedInClientCode".into(), Value::from(code.clone()));
    }
    if let Some(app) = &c.app_code {
        m.insert("appCode".into(), Value::from(app.clone()));
    }
    m.insert("oneTime".into(), Value::Bool(c.one_time));
    m.insert("userId".into(), Value::from(c.user_id));
    m.insert("jti".into(), Value::from(jti));
    m.insert("iat".into(), Value::from(iat));
    m.insert("exp".into(), Value::from(exp));
    // jjwt drops null-valued claims when it serializes (JwtMap.setValue removes on null).
    m.retain(|_, v| !v.is_null());
    Value::Object(m).to_string()
}

fn sign(alg: &str, key: &[u8], input: &[u8]) -> Option<Vec<u8>> {
    macro_rules! mac {
        ($t:ty) => {{
            let mut mac = <Hmac<$t>>::new_from_slice(key).ok()?;
            mac.update(input);
            Some(mac.finalize().into_bytes().to_vec())
        }};
    }
    match alg {
        "HS256" => mac!(Sha256),
        "HS384" => mac!(Sha384),
        "HS512" => mac!(Sha512),
        _ => None,
    }
}

/// `JWTUtil.generateToken`: the token for these claims, valid for `expiry_minutes` from `now`.
pub fn make(key: &str, claims: &Claims, now_seconds: i64, expiry_minutes: i64) -> Made {
    make_with(key, claims, &new_token_id(), now_seconds, now_seconds + expiry_minutes * 60)
}

pub fn make_with(key: &str, claims: &Claims, jti: &str, iat: i64, exp: i64) -> Made {
    let header = URL_SAFE_NO_PAD.encode(HEADER_HS512);
    let payload = URL_SAFE_NO_PAD.encode(payload_json(claims, jti, iat, exp));
    let input = format!("{header}.{payload}");
    let sig = sign("HS512", key.as_bytes(), input.as_bytes()).unwrap_or_default();
    Made { token: format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)), issued_at: iat, expires_at: exp }
}

/// The raw claims of a valid token (signature checked, `exp`/`nbf` honoured at `now_millis`).
pub fn parse_raw(key: &str, token: &str, now_millis: i64) -> Result<Map<String, Value>, JwtError> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(JwtError::Malformed("not three parts"));
    };
    if s.is_empty() {
        return Err(JwtError::Malformed("unsigned"));
    }
    let header: Value = decode_json(h)?;
    let alg = header.get("alg").and_then(Value::as_str).ok_or(JwtError::Malformed("no alg"))?;
    if header.get("zip").is_some() {
        return Err(JwtError::Malformed("compressed tokens are not issued"));
    }
    let expected = sign(alg, key.as_bytes(), format!("{h}.{p}").as_bytes()).ok_or(JwtError::Malformed("alg"))?;
    let given = URL_SAFE_NO_PAD.decode(s).map_err(|_| JwtError::Malformed("signature encoding"))?;
    if !constant_time_eq(&expected, &given) {
        return Err(JwtError::Signature);
    }
    let Value::Object(claims) = decode_json(p)? else {
        return Err(JwtError::Malformed("claims are not an object"));
    };
    if let Some(exp) = claims.get("exp") {
        let exp = seconds(exp).ok_or(JwtError::Claim("exp"))?;
        if now_millis > exp * 1000 {
            return Err(JwtError::Expired);
        }
    }
    if let Some(nbf) = claims.get("nbf") {
        let nbf = seconds(nbf).ok_or(JwtError::Claim("nbf"))?;
        if now_millis < nbf * 1000 {
            return Err(JwtError::Premature);
        }
    }
    Ok(claims)
}

/// `JWTUtil.getClaimsFromToken` + `JWTClaims.from`.
pub fn parse(key: &str, token: &str, now_millis: i64) -> Result<Claims, JwtError> {
    let raw = parse_raw(key, token, now_millis)?;
    Ok(Claims {
        user_id: long_claim(&raw, "userId")?,
        host_name: string_claim(&raw, "hostName")?,
        port: string_claim(&raw, "port")?,
        logged_in_client_id: long_claim(&raw, "loggedInClientId")?,
        logged_in_client_code: string_claim(&raw, "loggedInClientCode")?,
        app_code: string_claim(&raw, "appCode")?,
        one_time: match raw.get("oneTime") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(JwtError::Claim("oneTime")),
        },
    })
}

/// `exp` - `iat` of a valid token, in seconds, when both are present.
pub fn lifetime_seconds(key: &str, token: &str, now_millis: i64) -> Option<i64> {
    let raw = parse_raw(key, token, now_millis).ok()?;
    Some(seconds(raw.get("exp")?)? - seconds(raw.get("iat")?)?)
}

fn seconds(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

/// `claims.get(name, Long.class)`, then `BigInteger.valueOf`: absent is a NullPointerException.
fn long_claim(raw: &Map<String, Value>, name: &'static str) -> Result<u64, JwtError> {
    match raw.get(name) {
        Some(Value::Number(n)) => n.as_u64().or_else(|| n.as_i64().map(|i| i as u64)).ok_or(JwtError::Claim(name)),
        _ => Err(JwtError::Claim(name)),
    }
}

fn string_claim(raw: &Map<String, Value>, name: &'static str) -> Result<Option<String>, JwtError> {
    match raw.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(JwtError::Claim(name)),
    }
}

fn decode_json(part: &str) -> Result<Value, JwtError> {
    let bytes = URL_SAFE_NO_PAD.decode(part.trim_end_matches('=')).map_err(|_| JwtError::Malformed("base64"))?;
    serde_json::from_slice(&bytes).map_err(|_| JwtError::Malformed("json"))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Header and claims of a token the Java service minted on 2026-10-15 (signature left out:
    /// it is a credential until it expires, and the key is not in the repository).
    const JAVA_HEADER: &str = "eyJhbGciOiJIUzUxMiJ9";
    const JAVA_PAYLOAD_JSON: &str = r#"{"hostName":"localhost","port":"8001","loggedInClientId":1,"loggedInClientCode":"SYSTEM","appCode":"appbuilder","oneTime":false,"userId":142,"jti":"kEi5kLy-ddWkxop9","iat":1792029758,"exp":1792033358}"#;

    fn java_claims() -> Claims {
        Claims {
            user_id: 142,
            host_name: Some("localhost".into()),
            port: Some("8001".into()),
            logged_in_client_id: 1,
            logged_in_client_code: Some("SYSTEM".into()),
            app_code: Some("appbuilder".into()),
            one_time: false,
        }
    }

    #[test]
    fn signing_input_is_byte_identical_to_java() {
        assert_eq!(URL_SAFE_NO_PAD.encode(HEADER_HS512), JAVA_HEADER);
        assert_eq!(payload_json(&java_claims(), "kEi5kLy-ddWkxop9", 1_792_029_758, 1_792_033_358), JAVA_PAYLOAD_JSON);
    }

    #[test]
    fn refreshed_token_has_no_app_code_claim() {
        // generateNewToken builds its parameters without appCode, so the claim is left out.
        let c = Claims { app_code: None, ..java_claims() };
        let json = payload_json(&c, "j", 1, 2);
        assert_eq!(
            json,
            r#"{"hostName":"localhost","port":"8001","loggedInClientId":1,"loggedInClientCode":"SYSTEM","oneTime":false,"userId":142,"jti":"j","iat":1,"exp":2}"#
        );
    }

    #[test]
    fn round_trip_and_rules() {
        let key = "k".repeat(91);
        let made = make_with(&key, &java_claims(), "abc", 1_000, 2_000);
        assert_eq!(parse(&key, &made.token, 1_500_000).unwrap(), java_claims());
        assert_eq!(lifetime_seconds(&key, &made.token, 1_500_000), Some(1_000));
        // exp is inclusive to the millisecond: now == exp still parses, one ms later does not.
        assert!(parse(&key, &made.token, 2_000_000).is_ok());
        assert!(matches!(parse(&key, &made.token, 2_000_001), Err(JwtError::Expired)));
        assert!(matches!(parse(&"x".repeat(91), &made.token, 1_500_000), Err(JwtError::Signature)));
        let mut tampered = made.token.clone();
        tampered.insert(30, 'A');
        assert!(parse(&key, &tampered, 1_500_000).is_err());
        assert!(parse(&key, "a.b", 0).is_err());
    }

    #[test]
    fn missing_logged_in_client_id_fails_like_java() {
        let key = "k".repeat(91);
        let header = URL_SAFE_NO_PAD.encode(HEADER_HS512);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"userId":1,"hostName":"h"}"#);
        let input = format!("{header}.{payload}");
        let sig = URL_SAFE_NO_PAD.encode(sign("HS512", key.as_bytes(), input.as_bytes()).unwrap());
        assert!(matches!(parse(&key, &format!("{input}.{sig}"), 0), Err(JwtError::Claim("loggedInClientId"))));
    }

    #[test]
    fn hs256_tokens_are_read_like_jjwt() {
        let key = "k".repeat(91);
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"userId":1,"loggedInClientId":2}"#);
        let input = format!("{header}.{payload}");
        let sig = URL_SAFE_NO_PAD.encode(sign("HS256", key.as_bytes(), input.as_bytes()).unwrap());
        let c = parse(&key, &format!("{input}.{sig}"), 0).unwrap();
        assert_eq!((c.user_id, c.logged_in_client_id, c.one_time), (1, 2, false));
        let none = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        assert!(parse(&key, &format!("{none}.{payload}.x"), 0).is_err());
    }

    // Ported from commons-security `JWTUtilTest`.
    fn params() -> Claims {
        Claims {
            user_id: 142,
            host_name: Some("leadzump.local".into()),
            port: Some("443".into()),
            logged_in_client_id: 7,
            logged_in_client_code: Some("CLIENT01".into()),
            app_code: Some("leadzump".into()),
            one_time: false,
        }
    }

    #[test]
    fn same_inputs_in_the_same_second_give_different_tokens() {
        let key = "k".repeat(64);
        assert_ne!(make(&key, &params(), 1_000, 30).token, make(&key, &params(), 1_000, 30).token);
    }

    #[test]
    fn the_id_does_not_disturb_the_claims() {
        let key = "k".repeat(64);
        let t = make(&key, &params(), 1_000, 30);
        assert_eq!((t.issued_at, t.expires_at), (1_000, 2_800));
        let c = parse(&key, &t.token, 1_000_000).unwrap();
        assert_eq!(c.user_id, 142);
        assert_eq!(c.host_name.as_deref(), Some("leadzump.local"));
        assert_eq!(c.app_code.as_deref(), Some("leadzump"));
        assert_eq!(c.logged_in_client_code.as_deref(), Some("CLIENT01"));
    }

    #[test]
    fn the_id_is_short() {
        assert_eq!(new_token_id().len(), 16);
        assert!(make(&"k".repeat(64), &params(), 1, 1).token.len() < 512);
    }

    #[test]
    fn errors_describe_themselves() {
        for (e, m) in [
            (JwtError::Malformed("x"), "malformed token: x"),
            (JwtError::Signature, "JWT signature does not match locally computed signature"),
            (JwtError::Expired, "JWT expired"),
            (JwtError::Premature, "JWT must not be accepted before nbf"),
            (JwtError::Claim("userId"), "claim userId missing or of the wrong type"),
        ] {
            assert_eq!(e.to_string(), m);
        }
    }

    #[test]
    fn claim_shapes() {
        let key = "k".repeat(64);
        let sign_payload = |payload: &str| {
            let header = URL_SAFE_NO_PAD.encode(HEADER_HS512);
            let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(payload));
            let sig = URL_SAFE_NO_PAD.encode(sign("HS512", key.as_bytes(), input.as_bytes()).unwrap());
            format!("{input}.{sig}")
        };
        let ok = sign_payload(r#"{"userId":1,"loggedInClientId":2,"oneTime":true,"nbf":5}"#);
        assert!(parse(&key, &ok, 5_000).unwrap().one_time);
        assert!(matches!(parse(&key, &ok, 4_000), Err(JwtError::Premature)));
        assert!(lifetime_seconds(&key, &ok, 5_000).is_none());
        for bad in [
            r#"{"userId":"1","loggedInClientId":2}"#,
            r#"{"userId":1,"loggedInClientId":2,"oneTime":"yes"}"#,
            r#"{"userId":1,"loggedInClientId":2,"hostName":5}"#,
            r#"{"userId":1,"loggedInClientId":2,"exp":"x"}"#,
            r#"{"userId":1,"loggedInClientId":2,"nbf":"x"}"#,
            r#"[1]"#,
        ] {
            assert!(parse(&key, &sign_payload(bad), 0).is_err(), "{bad}");
        }
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS512","zip":"DEF"}"#);
        assert!(parse(&key, &format!("{header}.e30.c2ln"), 0).is_err());
        assert!(parse(&key, &format!("{}.e30.", URL_SAFE_NO_PAD.encode(HEADER_HS512)), 0).is_err());
        assert!(parse(&key, &format!("{}.e30.!!", URL_SAFE_NO_PAD.encode(HEADER_HS512)), 0).is_err());
        assert!(parse(&key, &format!("{}.e30.c2ln", URL_SAFE_NO_PAD.encode("{}")), 0).is_err());
        assert!(parse(&key, "!!.e30.c2ln", 0).is_err());
        assert!(parse(&key, &format!("{}.e30.c2ln", URL_SAFE_NO_PAD.encode("not json")), 0).is_err());
        // A float expiry is read as seconds.
        let f = sign_payload(r#"{"userId":1,"loggedInClientId":2,"iat":1,"exp":9.5}"#);
        assert_eq!(lifetime_seconds(&key, &f, 0), Some(8));
    }

    /// With the real key (gated: `SECURITY_AUTH_LIVE`, `MODLIX__JWT__KEY`, `JAVA_TOKEN`): the claims
    /// of a token the Java service minted, signed again here, give the identical string.
    #[test]
    fn java_token_resigned_is_identical() {
        let (Ok(_), Ok(key), Ok(token)) =
            (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__JWT__KEY"), std::env::var("JAVA_TOKEN"))
        else {
            eprintln!("skipped: SECURITY_AUTH_LIVE / MODLIX__JWT__KEY / JAVA_TOKEN not set");
            return;
        };
        let raw = parse_raw(&key, &token, 0).expect("valid Java token");
        let c = parse(&key, &token, 0).unwrap();
        let made = make_with(
            &key,
            &c,
            raw["jti"].as_str().unwrap(),
            raw["iat"].as_i64().unwrap(),
            raw["exp"].as_i64().unwrap(),
        );
        assert_eq!(made.token, token);
    }
}
