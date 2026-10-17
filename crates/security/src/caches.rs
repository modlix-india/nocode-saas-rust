//! The Java security service's caches this unit reads, under the same names, so that every
//! eviction Java publishes (`cmn-<name>:<key>` or `:*` on `evictionChannel`) drops the Rust copy
//! too. Keys are made as Java's `CacheService.makeKey` makes them: one key is its `toString()`,
//! several are concatenated.
//!
//! Rust keeps the in-process level only. Java's Redis level holds Java-serialized objects, which
//! Rust neither reads nor writes; a Rust write that Java caches publishes the same eviction
//! Java would and deletes the same Redis entry (`CacheService::evict_everywhere`).

use std::collections::HashMap;
use std::sync::Arc;

use platform::cache::{CacheService, LocalCaches};

use crate::data::apps::AppDependency;
use crate::data::billing::BillingConfig;
use crate::data::misc::CertificateConfig;
use crate::dto::{Department, Designation, ExplicitApp};
use crate::model::{App, Client, ClientHierarchy, ContextAuth, Policy, UrlPattern, User};
use crate::org::OrgStructure;

/// `IAuthenticationService.CACHE_NAME_TOKEN`: the signed-in context by bearer token.
pub const TOKEN: &str = "tokenCache";
/// `UserService.CACHE_NAME_USER`: `readInternal(userId)`.
pub const USER: &str = "user";
/// `UserService.CACHE_NAME_USER_ROLE`: role authorities per app, by user id.
pub const USER_ROLES: &str = "userRoles";
/// `ProfileService.CACHE_AUTHORITIES_BY_ID + "_" + profileId`, by client id.
pub const PROFILE_AUTHS_PREFIX: &str = "profileAuthsById_";
/// `ClientHierarchyService.CACHE_NAME_CLIENT_HIERARCHY`, by client id.
pub const CLIENT_HIERARCHY: &str = "clientHierarchy";
/// `ClientService.CACHE_NAME_CLIENT_TYPE_CODE_LEVEL`, by client id.
pub const CLIENT_TYPE_CODE_LEVEL: &str = "clientTypeCodeLevel";
/// `ClientService.CACHE_NAME_CLIENT_ID`: `readInternal(clientId)`.
pub const CLIENT_ID: &str = "clientId";
/// `ClientService.CACHE_NAME_CLIENT_CODE`: `getClientBy(clientCode)`, keyed by the code.
pub const CLIENT_CODE: &str = "clientCodeId";
/// `ClientService.CACHE_NAME_MANAGED_CLIENT_INFO`, by client id.
pub const MANAGED_CLIENT: &str = "managedClientInfoById";
/// `ClientService.CACHE_NAME_CLIENT_URI`: the URL pattern for scheme + host + ":" + port.
pub const CLIENT_URI: &str = "uri";
/// `ClientService.CACHE_NAME_CLIENT_URL`: every URL pattern, under the key `list`.
pub const CLIENT_URL: &str = "clientUrl";
pub const CLIENT_URL_KEY: &str = "list";
/// `AppService.CACHE_NAME_APP_BY_APPCODE` / `CACHE_NAME_APP_BY_APPID`.
pub const APP_BY_CODE: &str = "byAppCode";
pub const APP_BY_ID: &str = "byAppId";
/// `AppService.CACHE_NAME_APP_READ_ACCESS`, by appCode + ":" + clientCode.
pub const APP_READ_ACCESS: &str = "appReadAccess";

/// `ClientManagerService.CACHE_NAME_CLIENT_MANAGER`, by userId + targetClientId.
pub const CLIENT_MANAGER: &str = "clientManager";
/// `AppService.CACHE_NAME_APP_INHERITANCE`, by appCode:urlClientCode:clientCode.
pub const APP_INHERITANCE: &str = "appInheritance";
/// `AppService.CACHE_NAME_APP_STATUS`, by appCode.
pub const APP_STATUS: &str = "appStatus";
/// `AppService.CACHE_NAME_APP_DEPENDENCIES` (`cacheEmptyValueOrGet`), by appCode.
pub const APP_DEPENDENCIES: &str = "appDependencies";
/// `AppService.CACHE_NAME_APP_BY_APPCODE_EXPLICIT`, by appCode.
pub const APP_BY_CODE_EXPLICIT: &str = "byAppCodeExplicit";
/// `OrgStructureService.CACHE_NAME` / `UserSubOrganizationService`: `<clientId>:owner` holds
/// every user id of the client, `orgStructure:<clientId>` its reporting tree.
pub const USER_SUB_ORG: &str = "userSubOrg";
/// `DesignationService.CACHE_NAME_DESIGNATION`, by id.
pub const DESIGNATION: &str = "designation";
/// `DepartmentService.CACHE_NAME_DEPARTMENT`, by id.
pub const DEPARTMENT: &str = "department";
/// `AppBillingConfigService.CACHE_NAME_CONFIG_BY_CODES` (`cacheEmptyValueOrGet`), by appCode +
/// clientCode.
pub const BILLING_CONFIG_BY_CODES: &str = "appBillingConfigByCodes";
/// `WalletService.CACHE_NAME_WALLET_STATUS`, by clientId + appId (evicted here, read by admin).
pub const WALLET_STATUS: &str = "walletStatus";
/// `SSLCertificateService.CACHE_NAME_CERTIFICATE`, under the key `certificates`.
pub const CERTIFICATES: &str = "certificateCache";
pub const CERTIFICATES_KEY: &str = "certificates";
/// `SSLCertificateService.CACHE_NAME_CERTIFICATE_LAST_UPDATED_AT`, key `certificatesLastUpdated`.
pub const CERTIFICATES_LAST_UPDATED: &str = "certificatesLastUpdatedCache";
pub const CERTIFICATES_LAST_UPDATED_KEY: &str = "certificatesLastUpdated";

pub type RoleMap = HashMap<String, Vec<String>>;

#[derive(Clone)]
pub struct Caches {
    pub service: CacheService,
    pub tokens: Arc<LocalCaches<String, Arc<ContextAuth>>>,
    pub users: Arc<LocalCaches<String, Arc<User>>>,
    pub role_maps: Arc<LocalCaches<String, Arc<RoleMap>>>,
    pub string_lists: Arc<LocalCaches<String, Arc<Vec<String>>>>,
    pub hierarchies: Arc<LocalCaches<String, Arc<ClientHierarchy>>>,
    pub type_levels: Arc<LocalCaches<String, Arc<(String, String, String)>>>,
    pub clients: Arc<LocalCaches<String, Arc<Client>>>,
    pub url_patterns: Arc<LocalCaches<String, Arc<UrlPattern>>>,
    pub url_lists: Arc<LocalCaches<String, Arc<Vec<UrlPattern>>>>,
    pub apps: Arc<LocalCaches<String, Arc<App>>>,
    pub flags: Arc<LocalCaches<String, bool>>,
    /// The client-app policies (`cacheEmptyValueOrGet`: an absent policy is cached too).
    pub policies: Arc<LocalCaches<String, Arc<Option<Policy>>>>,
    pub strings: Arc<LocalCaches<String, Arc<String>>>,
    pub id_lists: Arc<LocalCaches<String, Arc<Vec<u64>>>>,
    pub orgs: Arc<LocalCaches<String, Arc<OrgStructure>>>,
    pub dependencies: Arc<LocalCaches<String, Arc<Option<Vec<AppDependency>>>>>,
    pub explicit_apps: Arc<LocalCaches<String, Arc<ExplicitApp>>>,
    pub designations: Arc<LocalCaches<String, Arc<Designation>>>,
    pub departments: Arc<LocalCaches<String, Arc<Department>>>,
    pub billing_configs: Arc<LocalCaches<String, Arc<Option<BillingConfig>>>>,
    pub certificates: Arc<LocalCaches<String, Arc<Vec<CertificateConfig>>>>,
}

impl Caches {
    pub fn new(service: CacheService) -> Self {
        Self {
            tokens: service.family(),
            users: service.family(),
            role_maps: service.family(),
            string_lists: service.family(),
            hierarchies: service.family(),
            type_levels: service.family(),
            clients: service.family(),
            url_patterns: service.family(),
            url_lists: service.family(),
            apps: service.family(),
            flags: service.family(),
            policies: service.family(),
            strings: service.family(),
            id_lists: service.family(),
            orgs: service.family(),
            dependencies: service.family(),
            explicit_apps: service.family(),
            designations: service.family(),
            departments: service.family(),
            billing_configs: service.family(),
            certificates: service.family(),
            service,
        }
    }
}
