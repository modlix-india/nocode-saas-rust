//! The billing tables as security-admin reads and writes them: `AppBillingConfigDAO`,
//! `AppBillingBundleDAO`, `BillingProfileDAO`, `InvoiceDAO`, `PaymentDAO`, `WalletDAO` and
//! `WalletTransactionDAO` (the wallet rules security-internal needs stay in `billing.rs`).
//!
//! Each table is a [`Schema`]: its columns in the Java DTO's property order (the base DTO's
//! `id`, `createdAt`, `createdBy`, `updatedAt`, `updatedBy`, then the class's fields), each with
//! its column name, its Java type and whether the column may hold NULL. A row is a [`Rec`]
//! over that schema, so one reader, one writer and one JSON writer serve every table, and the
//! jOOQ write rules are in one place:
//!
//! - `dao.create(pojo)`: every column the POJO has, except that a NULL for a NOT NULL column is
//!   left out so the database default applies (`Tools.resetTouchedOnNotNull`); `ID` is always
//!   left to the database.
//! - `dao.update(pojo)`: every column but `CREATED_BY` / `CREATED_AT`, `UPDATED_AT` forced to
//!   NULL (so left out, and MySQL's `ON UPDATE CURRENT_TIMESTAMP` applies), the same NOT NULL
//!   rule, `WHERE ID = ?`.
//!
//! The statements live in [`sql`] over one connection, so the live tests run them inside a
//! transaction they roll back; [`AdminBillingStore`] is what the service uses, implemented by
//! [`Db`] and, in the tests, by an in-memory store.

use async_trait::async_trait;
use chrono::{NaiveDate, NaiveDateTime};
use serde_json::{Map, Value};
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, MySqlConnection, QueryBuilder, Row};

use super::clients::Rows;
use super::Db;
use crate::condition::{self, Bind, ColType, Cond, Filter, Invalid, Op, Sql, Table};
use crate::decimal::Dec;
use crate::errors::{AuthError, AuthResult};
use crate::jackson::epoch;
use crate::spring::Pageable;

/// The Java type of a column, which decides how it is read, bound, written and coerced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `ULong`.
    Id,
    /// `BigDecimal`.
    Dec,
    Str,
    /// A jOOQ enum, with its literals in declaration order.
    Enum(&'static [&'static str]),
    /// `Integer`.
    Int,
    /// `Short`.
    Small,
    /// `Byte` (a `TINYINT(1)`).
    Byte,
    /// `Map<String, Object>` through `JSONMysqlMapConvertor`.
    Json,
    /// `LocalDateTime` on a `TIMESTAMP`.
    Ts,
    /// `LocalDate` on a `DATE`.
    Date,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Col {
    /// The Java property.
    pub prop: &'static str,
    /// The column.
    pub name: &'static str,
    pub kind: Kind,
    pub nullable: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Schema {
    pub table: &'static str,
    /// The DTO's simple class name, as `object_not_found` names it.
    pub pojo: &'static str,
    pub cols: &'static [Col],
}

const fn col(prop: &'static str, name: &'static str, kind: Kind, nullable: bool) -> Col {
    Col { prop, name, kind, nullable }
}

const ID: Col = col("id", "ID", Kind::Id, false);
const CREATED_AT: Col = col("createdAt", "CREATED_AT", Kind::Ts, false);
const CREATED_BY: Col = col("createdBy", "CREATED_BY", Kind::Id, true);
const UPDATED_AT: Col = col("updatedAt", "UPDATED_AT", Kind::Ts, false);
const UPDATED_BY: Col = col("updatedBy", "UPDATED_BY", Kind::Id, true);

pub const RECORD_STATUS: &[&str] = &["ACTIVE", "INACTIVE", "DELETED"];
pub const GATEWAYS: &[&str] = &["RAZORPAY", "OTHER"];
pub const BUNDLE_TYPES: &[&str] = &["FIXED", "CUSTOM"];
pub const INVOICE_STATUS: &[&str] = &["PENDING", "PAID", "FAILED", "UNDER_REVIEW"];
pub const PAYMENT_STATUS: &[&str] = &["PENDING", "PAID", "FAILED"];
pub const WALLET_STATUS: &[&str] = &["ACTIVE", "SUSPENDED"];
pub const TXN_TYPES: &[&str] = &["CREDIT", "DEBIT", "ADJUST", "SUSPEND", "REACTIVATE", "REFUND"];

/// `security_app_billing_config` / `AppBillingConfig`.
const CONFIG_COLS: &[Col] = &[
        ID,
        CREATED_AT,
        CREATED_BY,
        UPDATED_AT,
        UPDATED_BY,
        col("clientId", "CLIENT_ID", Kind::Id, false),
        col("appId", "APP_ID", Kind::Id, false),
        col("appRentPerMonth", "APP_RENT_PER_MONTH", Kind::Dec, false),
        col("siteRentPerMonth", "SITE_RENT_PER_MONTH", Kind::Dec, false),
        col("filesTokensPerMonth", "FILES_TOKENS_PER_MONTH", Kind::Dec, false),
        col("storageRowTokensPerMonth", "STORAGE_ROW_TOKENS_PER_MONTH", Kind::Dec, false),
        col("dealTokensPerMonth", "DEAL_TOKENS_PER_MONTH", Kind::Dec, false),
        col("userTokensPerMonth", "USER_TOKENS_PER_MONTH", Kind::Dec, false),
        col("aiTokensPerMillion", "AI_TOKENS_PER_MILLION", Kind::Dec, false),
        col("freeApps", "FREE_APPS", Kind::Dec, false),
        col("freeSites", "FREE_SITES", Kind::Dec, false),
        col("freeFilesGb", "FREE_FILES_GB", Kind::Dec, false),
        col("freeStorageRows", "FREE_STORAGE_ROWS", Kind::Dec, false),
        col("freeDeals", "FREE_DEALS", Kind::Dec, false),
        col("freeUsers", "FREE_USERS", Kind::Dec, false),
        col("freeAiTokensPerMonth", "FREE_AI_TOKENS_PER_MONTH", Kind::Dec, false),
        col("gstPercentage", "GST_PERCENTAGE", Kind::Dec, false),
        col("paymentGateway", "PAYMENT_GATEWAY", Kind::Enum(GATEWAYS), false),
        col("paymentGatewayConfig", "PAYMENT_GATEWAY_CONFIG", Kind::Json, true),
        col("sellerLegalName", "SELLER_LEGAL_NAME", Kind::Str, true),
        col("sellerGstin", "SELLER_GSTIN", Kind::Str, true),
        col("sellerAddress", "SELLER_ADDRESS", Kind::Str, true),
        col("lowBalanceThreshold", "LOW_BALANCE_THRESHOLD", Kind::Dec, true),
        col("suspendAppCode", "SUSPEND_APP_CODE", Kind::Str, true),
        col("suspendClientCode", "SUSPEND_CLIENT_CODE", Kind::Str, true),
        col("status", "STATUS", Kind::Enum(RECORD_STATUS), false),];

pub static CONFIG: Schema = Schema { table: "security_app_billing_config", pojo: "AppBillingConfig", cols: CONFIG_COLS };

/// `security_app_billing_bundle` / `AppBillingBundle`.
const BUNDLE_COLS: &[Col] = &[
        ID,
        CREATED_AT,
        CREATED_BY,
        UPDATED_AT,
        UPDATED_BY,
        col("billingConfigId", "BILLING_CONFIG_ID", Kind::Id, false),
        col("label", "LABEL", Kind::Str, false),
        col("bundleType", "BUNDLE_TYPE", Kind::Enum(BUNDLE_TYPES), false),
        col("tokens", "TOKENS", Kind::Dec, true),
        col("price", "PRICE", Kind::Dec, true),
        col("pricePerToken", "PRICE_PER_TOKEN", Kind::Dec, true),
        col("minTokens", "MIN_TOKENS", Kind::Dec, true),
        col("maxTokens", "MAX_TOKENS", Kind::Dec, true),
        col("currency", "CURRENCY", Kind::Str, false),
        col("status", "STATUS", Kind::Enum(RECORD_STATUS), false),
        col("displayOrder", "DISPLAY_ORDER", Kind::Int, false),];

pub static BUNDLE: Schema = Schema { table: "security_app_billing_bundle", pojo: "AppBillingBundle", cols: BUNDLE_COLS };

/// `security_billing_profile` / `BillingProfile`.
const PROFILE_COLS: &[Col] = &[
        ID,
        CREATED_AT,
        CREATED_BY,
        UPDATED_AT,
        UPDATED_BY,
        col("clientId", "CLIENT_ID", Kind::Id, false),
        col("appId", "APP_ID", Kind::Id, false),
        col("legalName", "LEGAL_NAME", Kind::Str, true),
        col("gstin", "GSTIN", Kind::Str, true),
        col("addressLine", "ADDRESS_LINE", Kind::Str, true),
        col("city", "CITY", Kind::Str, true),
        col("state", "STATE", Kind::Str, true),
        col("country", "COUNTRY", Kind::Str, true),
        col("postalCode", "POSTAL_CODE", Kind::Str, true),];

pub static PROFILE: Schema = Schema { table: "security_billing_profile", pojo: "BillingProfile", cols: PROFILE_COLS };

/// `security_invoice` / `Invoice` (its transient `paymentMethod` is not a column).
const INVOICE_COLS: &[Col] = &[
        ID,
        CREATED_AT,
        CREATED_BY,
        UPDATED_AT,
        UPDATED_BY,
        col("invoiceNumber", "INVOICE_NUMBER", Kind::Str, false),
        col("invoiceDate", "INVOICE_DATE", Kind::Ts, false),
        col("status", "STATUS", Kind::Enum(INVOICE_STATUS), false),
        col("sellerClientId", "SELLER_CLIENT_ID", Kind::Id, false),
        col("sellerLegalName", "SELLER_LEGAL_NAME", Kind::Str, true),
        col("sellerGstin", "SELLER_GSTIN", Kind::Str, true),
        col("sellerAddress", "SELLER_ADDRESS", Kind::Str, true),
        col("clientId", "CLIENT_ID", Kind::Id, false),
        col("buyerLegalName", "BUYER_LEGAL_NAME", Kind::Str, true),
        col("buyerGstin", "BUYER_GSTIN", Kind::Str, true),
        col("buyerAddress", "BUYER_ADDRESS", Kind::Str, true),
        col("appId", "APP_ID", Kind::Id, false),
        col("bundleId", "BUNDLE_ID", Kind::Id, true),
        col("bundleLabel", "BUNDLE_LABEL", Kind::Str, true),
        col("tokensPurchased", "TOKENS_PURCHASED", Kind::Dec, false),
        col("baseAmount", "BASE_AMOUNT", Kind::Dec, false),
        col("gstPercentage", "GST_PERCENTAGE", Kind::Dec, false),
        col("gstAmount", "GST_AMOUNT", Kind::Dec, false),
        col("totalAmount", "TOTAL_AMOUNT", Kind::Dec, false),
        col("currency", "CURRENCY", Kind::Str, false),
        col("paymentReference", "PAYMENT_REFERENCE", Kind::Str, true),
        col("gateway", "GATEWAY", Kind::Enum(GATEWAYS), false),
        col("paidAt", "PAID_AT", Kind::Ts, true),
        col("pdfFileKey", "PDF_FILE_KEY", Kind::Str, true),];

pub static INVOICE: Schema = Schema { table: "security_invoice", pojo: "Invoice", cols: INVOICE_COLS };

/// `security_payment` / `Payment`.
const PAYMENT_COLS: &[Col] = &[
        ID,
        CREATED_AT,
        CREATED_BY,
        UPDATED_AT,
        UPDATED_BY,
        col("invoiceId", "INVOICE_ID", Kind::Id, false),
        col("clientId", "CLIENT_ID", Kind::Id, false),
        col("gateway", "GATEWAY", Kind::Enum(GATEWAYS), false),
        col("gatewayOrderId", "GATEWAY_ORDER_ID", Kind::Str, true),
        col("gatewayPaymentId", "GATEWAY_PAYMENT_ID", Kind::Str, true),
        col("amount", "AMOUNT", Kind::Dec, false),
        col("status", "STATUS", Kind::Enum(PAYMENT_STATUS), false),
        col("response", "RESPONSE", Kind::Json, true),
        col("paidAt", "PAID_AT", Kind::Ts, true),];

pub static PAYMENT: Schema = Schema { table: "security_payment", pojo: "Payment", cols: PAYMENT_COLS };

/// `security_wallet` / `Wallet`.
const WALLET_COLS: &[Col] = &[
        ID,
        CREATED_AT,
        CREATED_BY,
        UPDATED_AT,
        UPDATED_BY,
        col("clientId", "CLIENT_ID", Kind::Id, false),
        col("appId", "APP_ID", Kind::Id, false),
        col("balance", "BALANCE", Kind::Dec, false),
        col("status", "STATUS", Kind::Enum(WALLET_STATUS), false),
        col("alertThreshold", "ALERT_THRESHOLD", Kind::Dec, true),
        col("lowBalanceNotified", "LOW_BALANCE_NOTIFIED", Kind::Byte, false),
        col("version", "VERSION", Kind::Int, false),];

pub static WALLET: Schema = Schema { table: "security_wallet", pojo: "Wallet", cols: WALLET_COLS };

/// `security_wallet_transaction` / `WalletTransaction` (an `AbstractDTO`: no update columns).
const TXN_COLS: &[Col] = &[
        ID,
        CREATED_AT,
        CREATED_BY,
        col("walletId", "WALLET_ID", Kind::Id, false),
        col("type", "TYPE", Kind::Enum(TXN_TYPES), false),
        col("tokens", "TOKENS", Kind::Dec, false),
        col("balanceAfter", "BALANCE_AFTER", Kind::Dec, false),
        col("actionKey", "ACTION_KEY", Kind::Str, true),
        col("appId", "APP_ID", Kind::Id, true),
        col("quantity", "QUANTITY", Kind::Dec, true),
        col("chargeDate", "CHARGE_DATE", Kind::Date, true),
        col("windowIndex", "WINDOW_INDEX", Kind::Small, true),
        col("idempotencyKey", "IDEMPOTENCY_KEY", Kind::Str, false),
        col("referenceType", "REFERENCE_TYPE", Kind::Str, true),
        col("referenceId", "REFERENCE_ID", Kind::Id, true),
        col("reason", "REASON", Kind::Str, false),
        col("description", "DESCRIPTION", Kind::Str, true),];

pub static TXN: Schema = Schema { table: "security_wallet_transaction", pojo: "WalletTransaction", cols: TXN_COLS };

/// One value of a row.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Null,
    Id(u64),
    Dec(Dec),
    Str(String),
    Int(i64),
    Json(Value),
    Ts(NaiveDateTime),
    Date(NaiveDate),
}

static NULL: Val = Val::Null;

/// A row (or a DTO being built) over a schema, its values in the schema's column order.
#[derive(Debug, Clone, PartialEq)]
pub struct Rec {
    pub schema: &'static Schema,
    pub vals: Vec<Val>,
}

impl Rec {
    /// `new Dto()`: every property null.
    pub fn new(schema: &'static Schema) -> Self {
        Self { schema, vals: vec![Val::Null; schema.cols.len()] }
    }

    fn index(&self, prop: &str) -> Option<usize> {
        self.schema.cols.iter().position(|c| c.prop == prop)
    }

    pub fn get(&self, prop: &str) -> &Val {
        self.index(prop).map(|i| &self.vals[i]).unwrap_or(&NULL)
    }

    /// Sets a property the schema has (others are ignored, as a missing setter is).
    pub fn set(&mut self, prop: &str, v: Val) -> &mut Self {
        if let Some(i) = self.index(prop) {
            self.vals[i] = v;
        }
        self
    }

    pub fn with(mut self, prop: &str, v: Val) -> Self {
        self.set(prop, v);
        self
    }

    pub fn id(&self) -> Option<u64> {
        self.u64("id")
    }

    pub fn u64(&self, prop: &str) -> Option<u64> {
        match self.get(prop) {
            Val::Id(v) => Some(*v),
            _ => None,
        }
    }

    pub fn dec(&self, prop: &str) -> Option<Dec> {
        match self.get(prop) {
            Val::Dec(v) => Some(*v),
            _ => None,
        }
    }

    pub fn str(&self, prop: &str) -> Option<&str> {
        match self.get(prop) {
            Val::Str(v) => Some(v.as_str()),
            _ => None,
        }
    }

    pub fn int(&self, prop: &str) -> Option<i64> {
        match self.get(prop) {
            Val::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub fn ts(&self, prop: &str) -> Option<NaiveDateTime> {
        match self.get(prop) {
            Val::Ts(v) => Some(*v),
            _ => None,
        }
    }

    /// A `Map<String, Object>` property: `JSONMysqlMapConvertor` reads a NULL column (and
    /// anything that is not an object) as an empty map.
    pub fn map(&self, prop: &str) -> Map<String, Value> {
        match self.get(prop) {
            Val::Json(Value::Object(m)) => m.clone(),
            _ => Map::new(),
        }
    }

    /// The DTO as the service's `ObjectMapper` writes it: property order, `NON_EMPTY` (null,
    /// `""`, an empty map are left out), `BigDecimal` with its scale, times as epoch seconds.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        for (c, v) in self.schema.cols.iter().zip(&self.vals) {
            let j = match v {
                Val::Null => continue,
                Val::Id(n) => Value::from(*n),
                Val::Dec(d) => d.to_json(),
                Val::Str(s) if s.is_empty() => continue,
                Val::Str(s) => Value::from(s.as_str()),
                Val::Int(n) => Value::from(*n),
                Val::Json(Value::Object(m)) if !m.is_empty() => Value::Object(m.clone()),
                Val::Json(_) => continue,
                Val::Ts(t) => epoch(Some(*t)),
                Val::Date(d) => Value::from(d.and_hms_opt(0, 0, 0).map(|t| t.and_utc().timestamp()).unwrap_or(0)),
            };
            out.insert(c.prop.to_string(), j);
        }
        Value::Object(out)
    }
}

/// What a `find` selects: equalities on columns, `STATUS <> 'DELETED'`, an order, one row.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Find {
    pub eq: Vec<(&'static str, Val)>,
    pub not_deleted: bool,
    pub order_by: Option<&'static str>,
    pub first: bool,
}

impl Find {
    pub fn eq(eq: Vec<(&'static str, Val)>) -> Self {
        Self { eq, ..Default::default() }
    }
}

#[async_trait]
pub trait AdminBillingStore: Send + Sync {
    /// `readById`'s row, or `None`.
    async fn by_id(&self, s: &'static Schema, id: u64) -> AuthResult<Option<Rec>>;
    async fn find(&self, s: &'static Schema, q: &Find) -> AuthResult<Vec<Rec>>;
    /// `dao.create`'s insert: the new id.
    async fn insert(&self, rec: &Rec) -> AuthResult<u64>;
    /// `dao.update`'s statement: rows matched.
    async fn update(&self, rec: &Rec) -> AuthResult<u64>;
    async fn delete(&self, s: &'static Schema, id: u64) -> AuthResult<u64>;
    /// `InvoiceDAO.readPageFilter`: `party` is the caller's client for a non-SYSTEM caller.
    async fn invoice_page(&self, cond: Option<&Cond>, party: Option<u64>, page: &Pageable) -> AuthResult<Rows<Rec>>;
    /// `WalletTransactionDAO.readPageFilter(pageable, walletId = ?)`.
    async fn txn_page(&self, wallet_id: u64, page: &Pageable) -> AuthResult<Rows<Rec>>;
    /// `PaymentDAO.findByInvoiceIds`.
    async fn payments_of(&self, invoice_ids: &[u64]) -> AuthResult<Vec<Rec>>;
    /// `InvoiceDAO.nextInvoiceNumber`.
    async fn next_invoice_number(&self, seller: u64, fin_year: &str) -> AuthResult<String>;
    /// `WalletDAO.createSeeded`.
    async fn seed_wallet(&self, client: u64, app: u64, initial: Dec) -> AuthResult<Option<Rec>>;
    /// `WalletDAO.creditBalance`.
    async fn credit_balance(&self, wallet: u64, tokens: Dec) -> AuthResult<u64>;
    async fn set_wallet_status(&self, wallet: u64, status: &str) -> AuthResult<u64>;
    async fn set_low_balance_notified(&self, wallet: u64, notified: bool) -> AuthResult<u64>;
    /// `WalletTransactionDAO.recordTxn`: false when the idempotency key was used already.
    async fn record_txn(&self, txn: &Rec) -> AuthResult<bool>;
    /// `AppDAO.hasWriteAccess(appId, clientId)`.
    async fn has_write_access(&self, app: u64, client: u64) -> AuthResult<bool>;
    /// `MeteringCountDAO.countAppsByType`.
    async fn count_apps(&self, client: u64, app_type: &str) -> AuthResult<i64>;
    /// `MeteringCountDAO.countUsersWithProfileInApp`.
    async fn count_users_with_profile(&self, client: u64, app: u64) -> AuthResult<i64>;
}

/// The filter columns of `security_invoice` (`AbstractDAO.getField` over the table).
pub static INVOICE_TABLE: Table = Table { name: "security_invoice", columns: &INVOICE_FILTER_COLUMNS };

const INVOICE_FILTER_COLUMNS: [(&str, ColType); INVOICE_COLS.len()] = filter_columns(INVOICE_COLS);

/// The filter columns of `security_wallet_transaction`.
pub static TXN_TABLE: Table = Table { name: "security_wallet_transaction", columns: &TXN_FILTER_COLUMNS };

const TXN_FILTER_COLUMNS: [(&str, ColType); TXN_COLS.len()] = filter_columns(TXN_COLS);

const fn col_type(k: Kind) -> ColType {
    match k {
        Kind::Str | Kind::Json => ColType::Str,
        Kind::Enum(_) => ColType::Enum,
        Kind::Ts | Kind::Date => ColType::Ts,
        Kind::Id | Kind::Dec | Kind::Int | Kind::Small | Kind::Byte => ColType::Num,
    }
}

const fn filter_columns<const N: usize>(cols: &[Col]) -> [(&'static str, ColType); N] {
    let mut out = [("", ColType::Str); N];
    let mut i = 0;
    while i < N {
        out[i] = (cols[i].name, col_type(cols[i].kind));
        i += 1;
    }
    out
}

/// `AbstractDAO.fieldValue` for a column with a precision (`DECIMAL`): `Double.valueOf` where
/// the base rules (`ColType::Num`) parse a `Long`. The other filters go through the base rules.
pub fn decimal_hook(schema: &'static Schema) -> impl Fn(&Filter, &Table) -> Option<Result<Option<Sql>, Invalid>> {
    move |f: &Filter, table: &Table| {
        let field = f.field.as_deref()?;
        if f.field_expr.as_ref().is_some_and(|fe| fe.is_valid()) {
            return None;
        }
        let (col, _) = table.column(field)?;
        if !schema.cols.iter().any(|c| c.name == col && c.kind == Kind::Dec) {
            return None;
        }
        Some(decimal_filter(f, table, col))
    }
}

fn as_double(v: &Value) -> Result<Value, Invalid> {
    match v {
        Value::Number(_) => Ok(v.clone()),
        other => {
            let s = condition::java_string(other);
            let d: f64 = s.trim().parse().map_err(|_| Invalid(format!("For input string: \"{s}\"")))?;
            Ok(serde_json::Number::from_f64(d).map(Value::Number).unwrap_or(Value::Null))
        }
    }
}

fn decimal_filter(f: &Filter, table: &Table, col: &str) -> Result<Option<Sql>, Invalid> {
    if f.op == Op::In {
        let pieces = condition::multi_values(ColType::Str, f)?;
        if pieces.is_empty() {
            return Ok(Some(Sql::text("1 = 0")));
        }
        let mut sql = Sql::text(format!("{} IN (", table.qualified(col)));
        for (i, p) in pieces.into_iter().enumerate() {
            if i > 0 {
                sql.push_text(", ");
            }
            let b = match p {
                Bind::Str(s) => match as_double(&Value::String(s))? {
                    Value::Number(n) => Bind::F64(n.as_f64().unwrap_or(0.0)),
                    _ => Bind::Null,
                },
                other => other,
            };
            sql.push_bind(b);
        }
        sql.push_text(")");
        return Ok(Some(sql));
    }
    let mut g = f.clone();
    g.negate = false;
    g.value = g.value.as_ref().map(as_double).transpose()?;
    g.to_value = g.to_value.as_ref().map(as_double).transpose()?;
    condition::to_sql(&Cond::Filter(g), table)
}

/// The statements, each on one connection.
pub mod sql {
    use super::*;

    fn select_list(s: &Schema) -> String {
        s.cols
            .iter()
            .map(|c| match c.kind {
                Kind::Dec | Kind::Json => format!("CAST({}.{} AS CHAR) {}", s.table, c.name, c.name),
                _ => format!("{}.{}", s.table, c.name),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// One row as the DTO.
    pub fn read_row(s: &'static Schema, row: &MySqlRow) -> AuthResult<Rec> {
        let mut vals = Vec::with_capacity(s.cols.len());
        for c in s.cols {
            let n = c.name;
            let v = match c.kind {
                Kind::Id => row.try_get::<Option<u64>, _>(n)?.map(Val::Id),
                Kind::Dec => match row.try_get::<Option<String>, _>(n)? {
                    None => None,
                    Some(t) => Some(Val::Dec(Dec::parse(&t).ok_or_else(|| AuthError::internal(format!("{n} is not a number: {t}")))?)),
                },
                Kind::Str | Kind::Enum(_) => row.try_get::<Option<String>, _>(n)?.map(Val::Str),
                Kind::Int => row.try_get::<Option<i32>, _>(n)?.map(|x| Val::Int(i64::from(x))),
                Kind::Small => row.try_get::<Option<i16>, _>(n)?.map(|x| Val::Int(i64::from(x))),
                Kind::Byte => row.try_get::<Option<i8>, _>(n)?.map(|x| Val::Int(i64::from(x))),
                // `JSONMysqlMapConvertor.from`: NULL (or anything but an object) is `Map.of()`, which a
                // later `dao.update` writes back as `{}`.
                Kind::Json => Some(Val::Json(match row.try_get::<Option<String>, _>(n)? {
                    Some(t) => match serde_json::from_str::<Value>(&t) {
                        Ok(v @ Value::Object(_)) => v,
                        _ => Value::Object(Map::new()),
                    },
                    None => Value::Object(Map::new()),
                })),
                Kind::Ts => crate::mysql::ts(row, n)?.map(Val::Ts),
                Kind::Date => row.try_get::<Option<NaiveDate>, _>(n)?.map(Val::Date),
            };
            vals.push(v.unwrap_or(Val::Null));
        }
        Ok(Rec { schema: s, vals })
    }

    pub(crate) fn push_val(qb: &mut QueryBuilder<'_, MySql>, v: &Val) {
        match v {
            Val::Null => {
                qb.push_bind(Option::<String>::None);
            }
            Val::Id(n) => {
                qb.push_bind(*n);
            }
            Val::Dec(d) => {
                qb.push_bind(d.to_string());
            }
            Val::Str(s) => {
                qb.push_bind(s.clone());
            }
            Val::Int(n) => {
                qb.push_bind(*n);
            }
            Val::Json(j) => {
                qb.push_bind(j.to_string());
            }
            Val::Ts(t) => {
                qb.push_bind(*t);
            }
            Val::Date(d) => {
                qb.push_bind(*d);
            }
        }
    }

    pub async fn by_id(c: &mut MySqlConnection, s: &'static Schema, id: u64) -> AuthResult<Option<Rec>> {
        let q = format!("SELECT {} FROM {} WHERE {}.ID = ? LIMIT 1", select_list(s), s.table, s.table);
        let row = sqlx::query(&q).bind(id).fetch_optional(&mut *c).await?;
        row.as_ref().map(|r| read_row(s, r)).transpose()
    }

    pub async fn find(c: &mut MySqlConnection, s: &'static Schema, f: &Find) -> AuthResult<Vec<Rec>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("SELECT {} FROM {}", select_list(s), s.table));
        let mut first = true;
        let mut and = |qb: &mut QueryBuilder<MySql>| {
            qb.push(if first { " WHERE " } else { " AND " });
            first = false;
        };
        for (column, v) in &f.eq {
            and(&mut qb);
            qb.push(format!("{}.{column} = ", s.table));
            push_val(&mut qb, v);
        }
        if f.not_deleted {
            and(&mut qb);
            qb.push(format!("{}.STATUS <> 'DELETED'", s.table));
        }
        if let Some(o) = f.order_by {
            qb.push(format!(" ORDER BY {}.{o} ASC", s.table));
        }
        if f.first {
            qb.push(" LIMIT 1");
        }
        let rows = qb.build().fetch_all(&mut *c).await?;
        rows.iter().map(|r| read_row(s, r)).collect()
    }

    /// `insertInto(table).set(record)`: every set column, NULLs for NOT NULL columns left out.
    pub async fn insert(c: &mut MySqlConnection, rec: &Rec) -> AuthResult<u64> {
        let s = rec.schema;
        let cols: Vec<(&Col, &Val)> = s
            .cols
            .iter()
            .zip(&rec.vals)
            .filter(|(col, v)| col.name != "ID" && !(matches!(v, Val::Null) && !col.nullable))
            .collect();
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("INSERT INTO {} (", s.table));
        qb.push(cols.iter().map(|(c, _)| c.name).collect::<Vec<_>>().join(", "));
        qb.push(") VALUES (");
        for (i, (_, v)) in cols.iter().enumerate() {
            if i > 0 {
                qb.push(", ");
            }
            push_val(&mut qb, v);
        }
        qb.push(")");
        Ok(qb.build().execute(&mut *c).await?.last_insert_id())
    }

    /// `AbstractUpdatableDAO.update(entity)`'s statement.
    pub async fn update(c: &mut MySqlConnection, rec: &Rec) -> AuthResult<u64> {
        let s = rec.schema;
        let Some(id) = rec.id() else { return Ok(0) };
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("UPDATE {} SET ", s.table));
        let mut n = 0;
        for (col, v) in s.cols.iter().zip(&rec.vals) {
            if matches!(col.name, "CREATED_BY" | "CREATED_AT" | "UPDATED_AT") || (matches!(v, Val::Null) && !col.nullable) {
                continue;
            }
            if n > 0 {
                qb.push(", ");
            }
            qb.push(format!("{} = ", col.name));
            push_val(&mut qb, v);
            n += 1;
        }
        qb.push(" WHERE ID = ").push_bind(id);
        Ok(qb.build().execute(&mut *c).await?.rows_affected())
    }

    pub async fn delete(c: &mut MySqlConnection, s: &'static Schema, id: u64) -> AuthResult<u64> {
        let q = format!("DELETE FROM {} WHERE {}.ID = ?", s.table, s.table);
        Ok(sqlx::query(&q).bind(id).execute(&mut *c).await?.rows_affected())
    }

    /// `AbstractDAO.list`: the page's rows (sorted on the columns the table has) and the count.
    async fn page(c: &mut MySqlConnection, s: &'static Schema, table: &Table, cond: Option<Sql>, p: &Pageable) -> AuthResult<Rows<Rec>> {
        let build = |select: &str| {
            let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("SELECT {select} FROM {}", s.table));
            if let Some(w) = &cond {
                qb.push(" WHERE ");
                w.push_to(&mut qb);
            }
            qb
        };
        let mut qb = build(&select_list(s));
        qb.push(condition::order_by(&p.sort, table));
        qb.push(" LIMIT ").push_bind(p.size).push(" OFFSET ").push_bind(p.offset());
        let rows = qb.build().fetch_all(&mut *c).await?;
        let rows = rows.iter().map(|r| read_row(s, r)).collect::<AuthResult<Vec<_>>>()?;
        let total = build("COUNT(*)").build().fetch_one(&mut *c).await?.try_get::<i64, _>(0)?;
        Ok(Rows { rows, total: Some(total) })
    }

    /// `InvoiceDAO.filter`: the caller's filter, and for a non-SYSTEM caller only the invoices
    /// its client sells or buys.
    pub async fn invoice_page(c: &mut MySqlConnection, cond: Option<&Cond>, party: Option<u64>, p: &Pageable) -> AuthResult<Rows<Rec>> {
        let hook = decimal_hook(&INVOICE);
        let filter = match cond {
            Some(cd) => condition::to_sql_with(cd, &INVOICE_TABLE, &hook)?,
            None => None,
        };
        let scoped = match party {
            None => filter,
            Some(client) => {
                let mut access = Sql::text("(security_invoice.SELLER_CLIENT_ID = ");
                access.push_bind(Bind::U64(client));
                access.push_text(" OR security_invoice.CLIENT_ID = ");
                access.push_bind(Bind::U64(client));
                access.push_text(")");
                Sql::and(filter, Some(access))
            }
        };
        page(c, &INVOICE, &INVOICE_TABLE, scoped, p).await
    }

    pub async fn txn_page(c: &mut MySqlConnection, wallet_id: u64, p: &Pageable) -> AuthResult<Rows<Rec>> {
        let mut w = Sql::text("security_wallet_transaction.WALLET_ID = ");
        w.push_bind(Bind::U64(wallet_id));
        page(c, &TXN, &TXN_TABLE, Some(w), p).await
    }

    pub async fn payments_of(c: &mut MySqlConnection, invoice_ids: &[u64]) -> AuthResult<Vec<Rec>> {
        if invoice_ids.is_empty() {
            return Ok(vec![]);
        }
        let mut qb: QueryBuilder<MySql> =
            QueryBuilder::new(format!("SELECT {} FROM security_payment WHERE ", select_list(&PAYMENT)));
        crate::data::push_in_u64(&mut qb, "security_payment.INVOICE_ID", invoice_ids);
        let rows = qb.build().fetch_all(&mut *c).await?;
        rows.iter().map(|r| read_row(&PAYMENT, r)).collect()
    }

    pub async fn next_invoice_number(c: &mut MySqlConnection, seller: u64, fin_year: &str) -> AuthResult<String> {
        sqlx::query(
            "INSERT INTO security_invoice_counter (SELLER_CLIENT_ID, FIN_YEAR, LAST_NUMBER) VALUES (?, ?, 1) \
             ON DUPLICATE KEY UPDATE LAST_NUMBER = (LAST_NUMBER + 1)",
        )
        .bind(seller)
        .bind(fin_year)
        .execute(&mut *c)
        .await?;
        let n: Option<u64> = sqlx::query_scalar("SELECT LAST_NUMBER FROM security_invoice_counter WHERE SELLER_CLIENT_ID = ? AND FIN_YEAR = ?")
            .bind(seller)
            .bind(fin_year)
            .fetch_optional(&mut *c)
            .await?;
        let n = n.ok_or_else(|| AuthError::internal("no invoice counter"))?;
        Ok(format!("INV/{fin_year}/{seller}/{n}"))
    }

    pub async fn seed_wallet(c: &mut MySqlConnection, client: u64, app: u64, initial: Dec) -> AuthResult<Option<Rec>> {
        crate::data::billing::sql::create_seeded_wallet(&mut *c, client, app, initial).await?;
        let found = find(&mut *c, &WALLET, &Find { first: true, ..Find::eq(vec![("CLIENT_ID", Val::Id(client)), ("APP_ID", Val::Id(app))]) }).await?;
        Ok(found.into_iter().next())
    }

    pub async fn credit_balance(c: &mut MySqlConnection, wallet: u64, tokens: Dec) -> AuthResult<u64> {
        let r = sqlx::query("UPDATE security_wallet SET BALANCE = (BALANCE + ?) WHERE ID = ?")
            .bind(tokens.to_string())
            .bind(wallet)
            .execute(&mut *c)
            .await?;
        Ok(r.rows_affected())
    }

    /// `recordTxn`: the explicit columns jOOQ sets (NULLs included), duplicates ignored.
    pub async fn record_txn(c: &mut MySqlConnection, t: &Rec) -> AuthResult<bool> {
        let cols = [
            "walletId", "type", "tokens", "balanceAfter", "actionKey", "appId", "quantity", "chargeDate", "windowIndex",
            "idempotencyKey", "referenceType", "referenceId", "reason", "description", "createdBy",
        ];
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "INSERT IGNORE INTO security_wallet_transaction (WALLET_ID, TYPE, TOKENS, BALANCE_AFTER, ACTION_KEY, APP_ID, \
             QUANTITY, CHARGE_DATE, WINDOW_INDEX, IDEMPOTENCY_KEY, REFERENCE_TYPE, REFERENCE_ID, REASON, DESCRIPTION, CREATED_BY) VALUES (",
        );
        for (i, p) in cols.iter().enumerate() {
            if i > 0 {
                qb.push(", ");
            }
            push_val(&mut qb, t.get(p));
        }
        qb.push(")");
        Ok(qb.build().execute(&mut *c).await?.rows_affected() > 0)
    }

    /// `AppDAO.hasOnlyInternalAccess(appId, clientId, 1)`.
    pub async fn has_write_access(c: &mut MySqlConnection, app: u64, client: u64) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_app LEFT JOIN security_client ON security_client.ID = security_app.CLIENT_ID \
             WHERE (security_app.ID = ? AND (security_client.ID = ? OR security_app.ID IN (SELECT security_app_access.APP_ID \
             FROM security_app_access LEFT JOIN security_client ON security_client.ID = security_app_access.CLIENT_ID \
             WHERE (security_app_access.APP_ID = ? AND security_client.ID = ? AND security_app_access.EDIT_ACCESS = 1)))) LIMIT 1",
        )
        .bind(app)
        .bind(client)
        .bind(app)
        .bind(client)
        .fetch_one(&mut *c)
        .await?;
        Ok(n != 0)
    }

    pub async fn set_wallet_status(c: &mut MySqlConnection, wallet: u64, status: &str) -> AuthResult<u64> {
        crate::data::billing::sql::set_status(&mut *c, wallet, status).await
    }

    pub async fn set_low_balance_notified(c: &mut MySqlConnection, wallet: u64, notified: bool) -> AuthResult<u64> {
        crate::data::billing::sql::set_low_balance_notified(&mut *c, wallet, notified).await
    }
}

#[async_trait]
impl AdminBillingStore for Db {
    async fn by_id(&self, s: &'static Schema, id: u64) -> AuthResult<Option<Rec>> {
        sql::by_id(&mut *self.pool.acquire().await?, s, id).await
    }

    async fn find(&self, s: &'static Schema, q: &Find) -> AuthResult<Vec<Rec>> {
        sql::find(&mut *self.pool.acquire().await?, s, q).await
    }

    async fn insert(&self, rec: &Rec) -> AuthResult<u64> {
        sql::insert(&mut *self.pool.acquire().await?, rec).await
    }

    async fn update(&self, rec: &Rec) -> AuthResult<u64> {
        sql::update(&mut *self.pool.acquire().await?, rec).await
    }

    async fn delete(&self, s: &'static Schema, id: u64) -> AuthResult<u64> {
        sql::delete(&mut *self.pool.acquire().await?, s, id).await
    }

    async fn invoice_page(&self, cond: Option<&Cond>, party: Option<u64>, page: &Pageable) -> AuthResult<Rows<Rec>> {
        sql::invoice_page(&mut *self.pool.acquire().await?, cond, party, page).await
    }

    async fn txn_page(&self, wallet_id: u64, page: &Pageable) -> AuthResult<Rows<Rec>> {
        sql::txn_page(&mut *self.pool.acquire().await?, wallet_id, page).await
    }

    async fn payments_of(&self, invoice_ids: &[u64]) -> AuthResult<Vec<Rec>> {
        sql::payments_of(&mut *self.pool.acquire().await?, invoice_ids).await
    }

    async fn next_invoice_number(&self, seller: u64, fin_year: &str) -> AuthResult<String> {
        sql::next_invoice_number(&mut *self.pool.acquire().await?, seller, fin_year).await
    }

    async fn seed_wallet(&self, client: u64, app: u64, initial: Dec) -> AuthResult<Option<Rec>> {
        sql::seed_wallet(&mut *self.pool.acquire().await?, client, app, initial).await
    }

    async fn credit_balance(&self, wallet: u64, tokens: Dec) -> AuthResult<u64> {
        sql::credit_balance(&mut *self.pool.acquire().await?, wallet, tokens).await
    }

    async fn set_wallet_status(&self, wallet: u64, status: &str) -> AuthResult<u64> {
        sql::set_wallet_status(&mut *self.pool.acquire().await?, wallet, status).await
    }

    async fn set_low_balance_notified(&self, wallet: u64, notified: bool) -> AuthResult<u64> {
        sql::set_low_balance_notified(&mut *self.pool.acquire().await?, wallet, notified).await
    }

    async fn record_txn(&self, txn: &Rec) -> AuthResult<bool> {
        sql::record_txn(&mut *self.pool.acquire().await?, txn).await
    }

    async fn has_write_access(&self, app: u64, client: u64) -> AuthResult<bool> {
        sql::has_write_access(&mut *self.pool.acquire().await?, app, client).await
    }

    async fn count_apps(&self, client: u64, app_type: &str) -> AuthResult<i64> {
        crate::data::billing::BillingStore::count_apps(self, client, app_type).await
    }

    async fn count_users_with_profile(&self, client: u64, app: u64) -> AuthResult<i64> {
        crate::data::billing::BillingStore::count_users_with_profile(self, client, app).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn d(s: &str) -> Dec {
        Dec::parse(s).unwrap()
    }

    #[test]
    fn schemas_follow_the_dto_property_order() {
        for s in [&CONFIG, &BUNDLE, &PROFILE, &INVOICE, &PAYMENT, &WALLET, &TXN] {
            assert_eq!(s.cols[0].prop, "id");
            assert_eq!(s.cols[1].prop, "createdAt");
            assert_eq!(s.cols[2].prop, "createdBy");
        }
        assert_eq!((CONFIG.cols.len(), INVOICE.cols.len(), TXN.cols.len()), (31, 29, 17));
        assert_eq!(INVOICE_FILTER_COLUMNS[8], ("SELLER_CLIENT_ID", ColType::Num));
        assert_eq!(TXN_TABLE.column("walletId"), Some(("WALLET_ID", ColType::Num)));
        assert_eq!(INVOICE_TABLE.column("status"), Some(("STATUS", ColType::Enum)));
        assert_eq!(TXN_TABLE.column("chargeDate"), Some(("CHARGE_DATE", ColType::Ts)));
    }

    #[test]
    fn json_is_non_empty_with_scales_and_epochs() {
        let t = NaiveDate::from_ymd_opt(2026, 10, 16).unwrap().and_hms_opt(1, 2, 3).unwrap();
        let r = Rec::new(&TXN)
            .with("id", Val::Id(7))
            .with("createdAt", Val::Ts(t))
            .with("tokens", Val::Dec(d("13.0000")))
            .with("actionKey", Val::Str(String::new()))
            .with("chargeDate", Val::Date(t.date()))
            .with("windowIndex", Val::Int(42))
            .with("nope", Val::Int(1));
        let v = r.to_json();
        assert_eq!(crate::jackson::pretty(&v), "{\n  \"id\" : 7,\n  \"createdAt\" : 1792112523,\n  \"tokens\" : 13.0000,\n  \"chargeDate\" : 1792108800,\n  \"windowIndex\" : 42\n}");
        let c = Rec::new(&CONFIG).with("paymentGatewayConfig", Val::Json(json!({}))).with("status", Val::Str("ACTIVE".into()));
        assert_eq!(c.to_json(), json!({"status": "ACTIVE"}));
        assert!(c.map("paymentGatewayConfig").is_empty());
        let c = c.with("paymentGatewayConfig", Val::Json(json!({"a": null})));
        assert_eq!(c.to_json()["paymentGatewayConfig"], json!({"a": null}));
        assert_eq!(c.map("paymentGatewayConfig").len(), 1);
        assert_eq!(Rec::new(&CONFIG).with("paymentGatewayConfig", Val::Json(json!([1]))).to_json(), json!({}));
        assert_eq!((r.u64("id"), r.dec("tokens"), r.int("windowIndex"), r.ts("createdAt")), (Some(7), Some(d("13.0000")), Some(42), Some(t)));
        assert_eq!((r.str("actionKey"), r.str("nope"), r.u64("tokens"), r.dec("id")), (Some(""), None, None, None));
        assert_eq!((r.int("id"), r.ts("id")), (None, None));
    }

    fn render(s: Option<Sql>) -> String {
        s.map(|s| {
            s.parts
                .iter()
                .map(|p| match p {
                    condition::Part::Text(t) => t.clone(),
                    condition::Part::Bind(b) => format!("{{{b:?}}}"),
                })
                .collect::<String>()
        })
        .unwrap_or_else(|| "<none>".into())
    }

    fn cond(v: Value) -> Cond {
        condition::parse(&v).unwrap().unwrap()
    }

    #[test]
    fn decimal_filters_read_doubles() {
        let hook = decimal_hook(&INVOICE);
        let sql = |v: Value| condition::to_sql_with(&cond(v), &INVOICE_TABLE, &hook).map(render);
        assert_eq!(sql(json!({"field": "totalAmount", "value": "1178.82"})).unwrap(), "security_invoice.TOTAL_AMOUNT = {F64(1178.82)}");
        assert_eq!(
            sql(json!({"field": "totalAmount", "operator": "BETWEEN", "value": 1, "toValue": "2.5", "negate": true})).unwrap(),
            "NOT (security_invoice.TOTAL_AMOUNT BETWEEN {I64(1)} AND {F64(2.5)})"
        );
        assert_eq!(sql(json!({"field": "baseAmount", "operator": "IN", "value": "1.5, 2"})).unwrap(), "security_invoice.BASE_AMOUNT IN ({F64(1.5)}, {F64(2.0)})");
        assert_eq!(sql(json!({"field": "baseAmount", "operator": "IN", "value": ""})).unwrap(), "1 = 0");
        assert_eq!(sql(json!({"field": "baseAmount", "operator": "IN", "multiValue": [1, "x"]})).unwrap_err(), Invalid("For input string: \"x\"".into()));
        assert_eq!(sql(json!({"field": "totalAmount", "value": "abc"})).unwrap_err(), Invalid("For input string: \"abc\"".into()));
        // Not a decimal column, or an expression: the base rules.
        assert_eq!(sql(json!({"field": "status", "value": "PAID"})).unwrap(), "security_invoice.STATUS = {Str(\"PAID\")}");
        assert_eq!(sql(json!({"fieldExpr": {"function": "LOWER", "fields": ["currency"]}, "value": "inr"})).unwrap(), "LOWER(CAST(security_invoice.CURRENCY AS CHAR)) = {Str(\"inr\")}");
        assert_eq!(sql(json!({"field": "nope", "value": 1})).unwrap(), "<none>");
    }

    #[test]
    fn finders() {
        let f = Find::eq(vec![("APP_ID", Val::Id(2))]);
        assert!(!f.not_deleted && !f.first && f.order_by.is_none());
    }
}
