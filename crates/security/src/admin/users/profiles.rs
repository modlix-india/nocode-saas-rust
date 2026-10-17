//! `ProfileController` / `ProfileService`: an app's profiles, read through their overrides down
//! the client hierarchy (`readRootProfile`: the root, then each override merged in with
//! `DifferenceApplicator`), each arrangement line filled with its role; created or updated as a
//! root or as an override (stored as the difference from its root); deleted; restricted to
//! clients. `fetchProfiles` on the internal user routes reads through here as well.

use std::collections::{HashMap, HashSet};

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{Map, Value};

use super::arrangement::{self, apply_map, extract_map, JMap, RoleFacts};
use super::common::{not_found, object_body, page_response, pre_authorize, pre_authorize_all, refuse, Fields};
use crate::admin::AdminState;
use crate::internal::Internal;
use crate::data::profiles::{ProfileRow, ProfileWrite};
use crate::dto::Role;
use crate::errors::{AuthError, AuthResult};
use crate::jackson::{epoch, json, opt, Obj};
use crate::model::{ClientHierarchy, ContextAuth};
use crate::spring::Pageable;
use crate::web::{nothing, to_u64, unreadable};

const PROFILE: &str = "Profile";
/// `ProfileService.CACHE_AUTHORITIES_BY_ID`.
const AUTHORITIES_CACHE: &str = "profileAuthsById";

/// The `Profile` DTO.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub id: Option<u64>,
    pub app_id: Option<u64>,
    pub client_id: Option<u64>,
    pub name: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub default_profile: bool,
    pub root_profile_id: Option<u64>,
    pub arrangement: Option<JMap>,
    pub created_by: Option<u64>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_by: Option<u64>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

impl Profile {
    fn from_row(r: ProfileRow) -> Profile {
        Profile {
            id: Some(r.id),
            app_id: r.app_id,
            client_id: r.client_id,
            name: r.name,
            title: r.title,
            description: r.description,
            default_profile: r.default_profile,
            root_profile_id: r.root_profile_id,
            arrangement: Some(JMap::from_map(&r.arrangement)),
            created_by: r.created_by,
            created_at: r.created_at,
            updated_by: r.updated_by,
            updated_at: r.updated_at,
        }
    }

    /// Jackson's view: `NON_EMPTY` leaves an empty arrangement out; its entries are written as
    /// they are, nulls included.
    pub fn to_json(&self) -> Value {
        let arrangement = match &self.arrangement {
            Some(m) if !m.is_empty() => Value::Object(m.to_map()),
            _ => Value::Null,
        };
        Obj::new()
            .put("id", opt(self.id))
            .put("createdAt", epoch(self.created_at))
            .put("createdBy", opt(self.created_by))
            .put("updatedAt", epoch(self.updated_at))
            .put("updatedBy", opt(self.updated_by))
            .put("appId", opt(self.app_id))
            .put("clientId", opt(self.client_id))
            .put("name", opt(self.name.clone()))
            .put("title", opt(self.title.clone()))
            .put("description", opt(self.description.clone()))
            .put("defaultProfile", self.default_profile)
            .put("rootProfileId", opt(self.root_profile_id))
            .put("arrangement", arrangement)
            .build()
    }

    /// `profileIdentity`: the root it overrides, or itself.
    fn identity(&self) -> Option<u64> {
        self.root_profile_id.or(self.id)
    }

    fn write(&self) -> ProfileWrite {
        ProfileWrite {
            client_id: self.client_id,
            default_profile: self.default_profile,
            name: self.name.clone(),
            title: self.title.clone(),
            app_id: self.app_id,
            description: self.description.clone(),
            root_profile_id: self.root_profile_id,
            arrangement: self.arrangement.as_ref().map(|m| Value::Object(m.to_map()).to_string()),
            created_by: self.created_by,
            created_at: self.created_at,
            updated_by: self.updated_by,
            updated_at: self.updated_at,
        }
    }
}

/// `Profile` as Jackson reads a request body.
pub fn profile_from_body(m: &Map<String, Value>) -> AuthResult<Profile> {
    let f = Fields(m);
    let arrangement = match m.get("arrangement") {
        None | Some(Value::Null) => None,
        Some(Value::Object(a)) => Some(JMap::from_map(a)),
        Some(_) => return Err(unreadable()),
    };
    Ok(Profile {
        id: f.u64("id")?,
        app_id: f.u64("appId")?,
        client_id: f.u64("clientId")?,
        name: f.string("name")?,
        title: f.string("title")?,
        description: f.string("description")?,
        default_profile: f.bool("defaultProfile")?,
        root_profile_id: f.u64("rootProfileId")?,
        arrangement,
        created_by: f.u64("createdBy")?,
        created_at: f.ts("createdAt")?,
        updated_by: f.u64("updatedBy")?,
        updated_at: f.ts("updatedAt")?,
    })
}

fn blank(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(|v| v.trim().is_empty())
}

/// `getManagingClientIds()`: the managers, nearest first, without repeats.
fn managing_client_ids(h: &ClientHierarchy) -> Vec<u64> {
    let mut ids = Vec::new();
    for l in [h.level0, h.level1, h.level2, h.level3].into_iter().flatten() {
        if !ids.contains(&l) {
            ids.push(l);
        }
    }
    ids
}

/// A `ProfileDAO` write refused by the database: a constraint (`23xxx`) is the name taken.
fn write_error(e: sqlx::Error, name: Option<&str>) -> AuthError {
    match &e {
        sqlx::Error::Database(db) if db.code().is_some_and(|c| c.starts_with("23")) => {
            refuse(StatusCode::CONFLICT, "name_taken", &[PROFILE, name.unwrap_or("null")])
        }
        _ => e.into(),
    }
}

impl Internal {
    /// `RoleV2Service.getRolesForProfileService`: the roles, each with its sub-roles.
    async fn roles_with_sub_roles(&self, ids: &[u64]) -> AuthResult<HashMap<u64, Role>> {
        let mut subs: HashMap<u64, Vec<Role>> = HashMap::new();
        for (parent, sub) in self.db.sub_role_rows(ids).await? {
            subs.entry(parent).or_default().push(sub);
        }
        let mut out = HashMap::new();
        for mut r in self.db.roles_by_ids(ids).await? {
            r.sub_roles = subs.remove(&r.id);
            out.insert(r.id, r);
        }
        Ok(out)
    }

    async fn role_facts(&self, index: &[(u64, Vec<String>)]) -> AuthResult<HashMap<u64, RoleFacts>> {
        let mut ids: Vec<u64> = index.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        ids.dedup();
        Ok(self
            .roles_with_sub_roles(&ids)
            .await?
            .into_iter()
            .map(|(id, r)| {
                let facts = RoleFacts { json: r.to_json(), name: r.name.clone(), short_name: r.short_name.clone(), description: r.description.clone() };
                (id, facts)
            })
            .collect())
    }

    /// `fillProfileArrangements`.
    async fn fill_profile_arrangements(&self, p: &mut Profile) -> AuthResult<()> {
        let Some(arr) = p.arrangement.as_mut() else { return Ok(()) };
        let index = arrangement::fill_prepare(arr)?;
        if index.is_empty() {
            return Ok(());
        }
        let facts = self.role_facts(&index).await?;
        arrangement::fill_apply(arr, &index, |id| facts.get(&id).cloned())
    }

    /// `cleanProfileArrangement`.
    async fn clean_profile_arrangement(&self, p: &mut Profile) -> AuthResult<()> {
        let Some(arr) = p.arrangement.as_mut() else { return Ok(()) };
        let index = arrangement::clean_prepare(arr)?;
        if index.is_empty() {
            return Ok(());
        }
        let facts = self.role_facts(&index).await?;
        arrangement::clean_apply(arr, &index, |id| facts.get(&id).cloned())
    }

    /// `ProfileDAO.readRootProfile`: the root with the overrides of the given clients merged in,
    /// farthest client first; the result carries the last override's id and client.
    async fn read_root_profile(&self, id: u64, h: &ClientHierarchy, include_client: bool) -> AuthResult<Profile> {
        let clients = if include_client { h.client_ids() } else { managing_client_ids(h) };
        let rows: Vec<Profile> = self.db.profile_and_overrides(id, &clients).await?.into_iter().map(Profile::from_row).collect();
        let Some(mut base) = rows.iter().find(|p| p.root_profile_id.is_none()).cloned() else {
            return Err(AuthError::literal(StatusCode::BAD_REQUEST, "SEC.ROOT_PROFILE_NOT_FOUND", "Root profile not found"));
        };
        base.root_profile_id = base.id;
        let mut sorted = rows;
        let order = |p: &Profile| p.client_id.and_then(|c| h.client_order(c)).unwrap_or(-1);
        sorted.sort_by_key(|p| std::cmp::Reverse(order(p)));
        for p in sorted {
            // Java's filter reads `base.getId()` as each element passes, after the earlier ones
            // moved it.
            if p.id == base.id {
                continue;
            }
            base.id = p.id;
            base.client_id = p.client_id;
            if !blank(&p.name) {
                base.name = p.name.clone();
            }
            if !blank(&p.description) {
                base.description = p.description.clone();
            }
            if !blank(&p.title) {
                base.title = p.title.clone();
            }
            base.arrangement = apply_map(p.arrangement.as_ref(), base.arrangement.as_ref());
        }
        Ok(base)
    }

    /// `ProfileDAO.read(id, hierarchy)`.
    pub(crate) async fn profile_dao_read(&self, id: u64, h: &ClientHierarchy) -> AuthResult<Profile> {
        let p = Profile::from_row(self.db.profile(id).await?.ok_or_else(|| not_found(PROFILE, id))?);
        if p.root_profile_id.is_none() && p.client_id == Some(h.client_id) {
            return Ok(p);
        }
        self.read_root_profile(p.root_profile_id.unwrap_or(id), h, true).await
    }

    /// `ProfileService.readObject(id, type)`: the profile as the caller's client sees it (no
    /// app-access check, no arrangement fill).
    #[allow(dead_code)]
    pub(crate) async fn profile_read_object(&self, ca: &ContextAuth, id: u64) -> AuthResult<Profile> {
        let h = self.dir().hierarchy(ca.user.client_id()).await?;
        self.profile_dao_read(id, &h).await
    }

    /// `ProfileService.read` without the authority check (Java's own internal calls): `None`
    /// when the caller's client cannot read the profile's app.
    pub async fn profile_read_unchecked(&self, ca: &ContextAuth, id: u64) -> AuthResult<Option<Profile>> {
        let h = self.dir().hierarchy(ca.user.client_id()).await?;
        let mut p = self.profile_dao_read(id, &h).await?;
        if !self.db.has_read_access_ids(p.app_id.unwrap_or_default(), ca.user.client_id()).await? {
            return Ok(None);
        }
        self.fill_profile_arrangements(&mut p).await?;
        Ok(Some(p))
    }

    /// `ProfileService.read`.
    pub async fn profile_read(&self, ca: &ContextAuth, id: u64) -> AuthResult<Option<Profile>> {
        pre_authorize(ca, &["Authorities.Profile_READ"])?;
        self.profile_read_unchecked(ca, id).await
    }

    /// `ProfileDAO.readAll`: the ids the hierarchy sees (the client's restrictions, else every
    /// profile of the app it sees, as roots), a page of them read.
    async fn profile_dao_read_all(&self, app_id: u64, h: &ClientHierarchy, offset: usize, size: usize) -> AuthResult<(Vec<Profile>, i64)> {
        let mut ids = self.db.restricted_profiles(h.client_id, app_id).await?;
        if ids.is_empty() {
            ids = self.db.app_profiles(app_id, &h.client_ids()).await?;
        }
        let mut out = Vec::new();
        for id in ids.iter().skip(offset).take(size) {
            out.push(self.profile_dao_read(*id, h).await?);
        }
        Ok((out, ids.len() as i64))
    }

    /// `ProfileService.readAll(appId, pageable)`.
    pub async fn profile_page(&self, ca: &ContextAuth, app_id: u64, page: &Pageable) -> AuthResult<(Vec<Profile>, i64)> {
        pre_authorize(ca, &["Authorities.Profile_READ"])?;
        let h = self.dir().hierarchy(ca.user.client_id()).await?;
        let offset = usize::try_from(page.offset()).unwrap_or(usize::MAX);
        let size = usize::try_from(page.size).unwrap_or(usize::MAX);
        self.profile_dao_read_all(app_id, &h, offset, size).await
    }

    /// `checkName`: the trimmed name, refused when blank (unless an override) or when another
    /// profile the client sees in the app has it.
    async fn check_profile_name(&self, p: &mut Profile, h: &ClientHierarchy) -> AuthResult<()> {
        let name = p.name.as_deref().unwrap_or("").trim().to_string();
        let is_override = p.root_profile_id.is_some() || (p.id.is_some() && p.client_id != Some(h.client_id));
        if name.is_empty() {
            return if is_override { Ok(()) } else { Err(refuse(StatusCode::BAD_REQUEST, "name_mandatory", &[PROFILE])) };
        }
        p.name = Some(name.clone());
        let me = p.identity();
        let (others, _) = self.profile_dao_read_all(p.app_id.unwrap_or_default(), h, 0, usize::MAX).await?;
        let lower = name.to_lowercase();
        if others
            .iter()
            .filter(|o| me.is_none() || me != o.identity())
            .any(|o| o.name.as_deref().is_some_and(|n| n.trim().to_lowercase() == lower))
        {
            return Err(refuse(StatusCode::CONFLICT, "name_taken", &[PROFILE, &name]));
        }
        Ok(())
    }

    /// `ProfileDAO.hasAccessToRoles`: every role is in a profile the client sees (or under one
    /// of its roles), or is the client's own role of the app.
    pub async fn has_access_to_roles(&self, app_id: u64, h: &ClientHierarchy, role_ids: &[u64]) -> AuthResult<bool> {
        let mut profiles = self.db.restricted_profiles(h.client_id, app_id).await?;
        if profiles.is_empty() {
            profiles = self.db.app_profile_ids_unmapped(app_id, &h.client_ids()).await?;
        }
        let reachable: HashSet<u64> = self.db.roles_reachable_in_profiles(&profiles, role_ids).await?.into_iter().collect();
        let remaining: Vec<u64> = role_ids.iter().copied().filter(|r| !reachable.contains(r)).collect();
        if remaining.is_empty() {
            return Ok(true);
        }
        Ok(self.db.count_client_app_roles(&remaining, app_id, h.client_id).await? == remaining.len() as i64)
    }

    /// `nullFieldsMatchingRoot` / the same step in `ProfileDAO.create` and `update`.
    fn null_fields_matching(p: &mut Profile, root: &Profile) {
        if p.name == root.name {
            p.name = None;
        }
        if p.title == root.title {
            p.title = None;
        }
        if p.description == root.description {
            p.description = None;
        }
    }

    fn distinct_role_ids(arr: Option<&JMap>) -> AuthResult<Vec<u64>> {
        let mut ids = arrangement::role_ids(arr)?;
        let mut seen = HashSet::new();
        ids.retain(|i| seen.insert(*i));
        Ok(ids)
    }

    /// `prepAndCreateRoleRelations`: an override records the roles it adds and the ones it drops.
    async fn override_role_relations(&self, id: u64, root: &Profile, arr: Option<&JMap>) -> AuthResult<()> {
        let mine = Self::distinct_role_ids(arr)?;
        let roots = Self::distinct_role_ids(root.arrangement.as_ref())?;
        let added: Vec<u64> = mine.iter().copied().filter(|r| !roots.contains(r)).collect();
        let removed: Vec<u64> = roots.iter().copied().filter(|r| !mine.contains(r)).collect();
        self.db.replace_profile_roles(id, &added, &removed).await
    }

    /// `ProfileDAO.createUpdateProfile`.
    async fn create_update_profile(&self, mut p: Profile, user_id: u64, h: &ClientHierarchy) -> AuthResult<Profile> {
        let name = p.name.clone();
        let arrangements = p.arrangement.clone();
        if p.id.is_none() || p.client_id != Some(h.client_id) {
            if p.id.is_some() {
                p.root_profile_id = p.id;
            }
            p.id = None;
            p.created_by = Some(user_id);
            let Some(root_id) = p.root_profile_id else {
                let id = self.db.insert_profile(&p.write()).await.map_err(|e| write_error(e, name.as_deref()))?;
                self.db.replace_profile_roles(id, &Self::distinct_role_ids(arrangements.as_ref())?, &[]).await?;
                return self.profile_dao_read(id, h).await;
            };
            let root = self.read_root_profile(root_id, h, false).await?;
            Self::null_fields_matching(&mut p, &root);
            p.arrangement = Some(extract_map(p.arrangement.as_ref(), root.arrangement.as_ref()));
            let id = self.db.insert_profile(&p.write()).await.map_err(|e| write_error(e, name.as_deref()))?;
            self.override_role_relations(id, &root, arrangements.as_ref()).await?;
            return self.profile_dao_read(id, h).await;
        }
        p.updated_by = Some(user_id);
        let id = p.id.unwrap_or_default();
        let Some(root_id) = p.root_profile_id else {
            self.db.update_profile(id, &p.write(), false).await.map_err(|e| write_error(e, name.as_deref()))?;
            self.db.replace_profile_roles(id, &Self::distinct_role_ids(arrangements.as_ref())?, &[]).await?;
            return self.profile_dao_read(id, h).await;
        };
        let root = self.read_root_profile(root_id, h, false).await?;
        Self::null_fields_matching(&mut p, &root);
        p.arrangement = Some(extract_map(p.arrangement.as_ref(), root.arrangement.as_ref()));
        self.db.update_profile(id, &p.write(), true).await.map_err(|e| write_error(e, name.as_deref()))?;
        self.override_role_relations(id, &root, arrangements.as_ref()).await?;
        self.profile_dao_read(id, h).await
    }

    /// `ProfileService.create` (POST and PUT both).
    pub async fn profile_create(&self, ca: &ContextAuth, mut p: Profile) -> AuthResult<Profile> {
        pre_authorize_all(ca, &["Authorities.Profile_CREATE", "Authorities.Profile_UPDATE"])?;
        let Some(app_id) = p.app_id else { return Err(refuse(StatusCode::BAD_REQUEST, "profile_needs_app", &[])) };
        let forbidden = || refuse(StatusCode::FORBIDDEN, "forbidden_create", &[PROFILE]);
        // `SECURITY_CLIENT.ID.eq(null)` matches nothing.
        let has_access = match p.client_id {
            Some(c) => self.db.has_read_access_ids(app_id, c).await?,
            None => false,
        };
        if !has_access {
            return Err(forbidden());
        }
        if !ca.is_system_client() && !self.db.has_read_access_ids(app_id, ca.user.client_id()).await? {
            return Err(forbidden());
        }
        match p.client_id {
            None => p.client_id = Some(ca.user.client_id()),
            Some(c) if !ca.is_system_client() && !self.caller_manages_client(ca, c).await? => return Err(forbidden()),
            Some(_) => {}
        }
        let h = self.dir().hierarchy(p.client_id.unwrap_or_default()).await?;
        self.check_profile_name(&mut p, &h).await?;
        if !self.has_access_to_roles(app_id, &h, &Self::distinct_role_ids(p.arrangement.as_ref())?).await? {
            return Err(refuse(StatusCode::BAD_REQUEST, "forbidden_role_access", &[]));
        }
        self.clean_profile_arrangement(&mut p).await?;
        if let Some(root_id) = p.root_profile_id {
            let root = self.read_root_profile(root_id, &h, false).await?;
            Self::null_fields_matching(&mut p, &root);
        }
        let mut saved = self.create_update_profile(p, ca.user.id(), &h).await?;
        self.fill_profile_arrangements(&mut saved).await?;
        self.evict_profile(&saved).await?;
        Ok(saved)
    }

    /// `evictAuthoritiesAndProfileCache`.
    async fn evict_profile(&self, p: &Profile) -> AuthResult<()> {
        let service = &self.caches().service;
        let id = p.id.unwrap_or_default();
        let cache = format!("{AUTHORITIES_CACHE}_{}", p.root_profile_id.unwrap_or(id));
        match p.root_profile_id {
            None => service.evict_all_everywhere(&cache).await,
            Some(root) => {
                let client = p.client_id.unwrap_or_default();
                if self.db.profile_used_by_managing_clients(client, root).await? {
                    service.evict_all_everywhere(&cache).await;
                } else {
                    service.evict_everywhere(&cache, &client.to_string()).await;
                }
            }
        }
        service.evict_everywhere(PROFILE, &id.to_string()).await;
        Ok(())
    }

    /// `ProfileService.delete`: false when other clients override the profile.
    pub async fn profile_delete(&self, ca: &ContextAuth, id: u64) -> AuthResult<bool> {
        pre_authorize(ca, &["Authorities.Profile_DELETE"])?;
        let h = self.dir().hierarchy(ca.user.client_id()).await?;
        let p = self.profile_dao_read(id, &h).await?;
        self.evict_profile(&p).await?;
        let again = self.profile_dao_read(id, &h).await?;
        let target = again.id.unwrap_or_default();
        if self.db.count_profile_overrides(target).await? != 0 {
            return Ok(false);
        }
        match self.db.delete_profile(target).await {
            Ok(n) => Ok(n > 0),
            Err(sqlx::Error::Database(_)) => Err(refuse(StatusCode::FORBIDDEN, "delete_role_error", &[])),
            Err(e) => Err(e.into()),
        }
    }

    /// `restrictClient`: `None` (an empty answer) when the caller cannot manage the client or the
    /// client has no access to the profile's app.
    pub async fn profile_restrict_client(&self, ca: &ContextAuth, profile_id: u64, client_id: u64) -> AuthResult<Option<bool>> {
        pre_authorize_all(ca, &["Authorities.Profile_READ", "Authorities.Client_UPDATE"])?;
        if !self.caller_manages_client(ca, client_id).await? || !self.db.profile_app_access(profile_id, client_id).await? {
            return Ok(None);
        }
        Ok(Some(self.db.restrict_profile(profile_id, client_id).await?))
    }

    /// `ProfileService.hasAccessToRoles(clientId, roleIds)`: the caller's hierarchy, and (as Java
    /// passes it) the user's client id in the app id's place.
    pub async fn user_has_access_to_roles(&self, ca: &ContextAuth, client_id: u64, role_ids: &[u64]) -> AuthResult<bool> {
        let h = self.dir().hierarchy(ca.user.client_id()).await?;
        self.has_access_to_roles(client_id, &h, role_ids).await
    }

    /// `ProfileDAO.hasAccessToProfiles`: every profile is of an app the client owns or can reach,
    /// and not one of the client's restricted ones.
    pub async fn has_access_to_profiles(&self, client_id: u64, profile_ids: &[u64]) -> AuthResult<bool> {
        let (mut apps, restrictions) = self.db.client_app_ids_and_restrictions(client_id).await?;
        let mut profiles: Vec<u64> = profile_ids.to_vec();
        if !restrictions.is_empty() {
            for (app, profile) in &restrictions {
                apps.retain(|a| a != app);
                profiles.retain(|p| p != profile);
            }
        }
        if profiles.is_empty() {
            return Ok(true);
        }
        Ok(self.db.count_profiles_outside_apps(&profiles, &apps).await? == 0)
    }

    /// `ProfileService.assignedProfiles` / `fillUser`: the user's profiles (of the app, when
    /// given), each read as the caller.
    pub async fn assigned_profiles(&self, ca: &ContextAuth, user_id: u64, app_id: Option<u64>, distinct: bool) -> AuthResult<Vec<Profile>> {
        let mut ids = self.db.assigned_profile_ids(user_id, app_id).await?;
        if distinct {
            ids = crate::data::distinct(ids);
        }
        let mut out = Vec::new();
        for id in ids {
            if let Some(p) = self.profile_read_unchecked(ca, id).await? {
                out.push(p);
            }
        }
        Ok(out)
    }
}

macro_rules! r {
    ($name:ident, $path:expr, |$s:ident, $r:ident, $ca:ident| $body:block) => {
        $crate::web_route!($name, AdminState, $path, true, |$s, $r, $ca| $body);
    };
}

macro_rules! rp {
    ($name:ident, $path:expr, |$s:ident, $r:ident, $ca:ident, $p:ident| $body:block) => {
        $crate::web_route_path!($name, AdminState, $path, true, |$s, $r, $ca, $p| $body);
    };
}

r!(create_or_update, "/app/profiles", |s, r, ca| {
    let body = profile_from_body(&object_body(&r.body)?)?;
    Ok(json(&s.profile_create(&ca, body).await?.to_json()))
});

rp!(read, "/app/profiles/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    Ok(match s.profile_read(&ca, id).await? {
        Some(p) => json(&p.to_json()),
        None => crate::jackson::empty(StatusCode::NOT_FOUND),
    })
});

rp!(remove, "/app/profiles/{id}", |s, r, ca, id| {
    let id = to_u64(&id)?;
    Ok(json(&Value::Bool(s.profile_delete(&ca, id).await?)))
});

rp!(app_profiles, "/app/{appId}/profiles", |s, r, ca, app_id| {
    let app_id = to_u64(&app_id)?;
    let page = Pageable::from_params(&r.params);
    let (items, total) = s.profile_page(&ca, app_id, &page).await?;
    Ok(page_response(items.iter().map(Profile::to_json).collect(), &page, total))
});

crate::web_route_path2!(restrict, AdminState, "/app/profiles/{id}/restrictClient/{clientId}", true, |s, r, ca, pid, cid| {
    let (pid, cid) = (to_u64(&pid)?, to_u64(&cid)?);
    Ok(match s.profile_restrict_client(&ca, pid, cid).await? {
        Some(b) => json(&Value::Bool(b)),
        None => nothing(),
    })
});

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/app/profiles", post(create_or_update).put(create_or_update))
        .route("/api/security/app/profiles/{id}", get(read).delete(remove))
        .route("/api/security/app/profiles/{id}/restrictClient/{clientId}", post(restrict))
        .route("/api/security/app/{appId}/profiles", get(app_profiles))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bodies_and_json() {
        let p = profile_from_body(json!({"appId": 2, "name": " P ", "defaultProfile": true, "arrangement": {"a": {"roleId": 1}}}).as_object().unwrap()).unwrap();
        assert_eq!((p.app_id, p.default_profile), (Some(2), true));
        assert!(profile_from_body(json!({"arrangement": [1]}).as_object().unwrap()).is_err());
        let j = Profile { id: Some(5), arrangement: Some(JMap::default()), ..Default::default() }.to_json();
        assert_eq!(j, json!({"id": 5, "defaultProfile": false}));
        assert_eq!(p.write().arrangement.as_deref(), Some(r#"{"a":{"roleId":1}}"#));
        let h = ClientHierarchy { client_id: 9, level0: Some(1), level1: Some(1), level2: None, level3: None };
        assert_eq!(managing_client_ids(&h), vec![1]);
        assert!(blank(&Some("  ".into())) && blank(&None) && !blank(&Some("x".into())));
        let mut q = Profile { name: Some("a".into()), title: None, description: Some("d".into()), ..Default::default() };
        Internal::null_fields_matching(&mut q, &Profile { name: Some("a".into()), description: Some("e".into()), ..Default::default() });
        assert_eq!((q.name, q.title, q.description.as_deref()), (None, None, Some("d")));
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::admin::users::testkit::{fx, sys, NONE};
    use serde_json::json;

    fn body(v: Value) -> Profile {
        profile_from_body(v.as_object().unwrap()).unwrap()
    }

    /// `ProfileServiceTest`: overrides made, edited and read through the root, the name rules,
    /// the refusals.
    #[tokio::test]
    async fn overrides_names_and_refusals() {
        let Some(fx) = fx().await else { return };
        let (s, c, m) = (&fx.s, fx.c, fx.m);
        let sys = sys();
        let run = fx.run.clone();
        let e = fx.user(m, "e").await;
        // A database refusal reads as the name being taken; anything else passes through.
        let fk = sqlx::query("INSERT INTO security_profile_client_restriction (PROFILE_ID, CLIENT_ID) VALUES (0, 0)").execute(&s.db.pool).await.unwrap_err();
        assert_eq!(write_error(fk, Some("x")).status(), StatusCode::CONFLICT);
        assert_eq!(write_error(sqlx::Error::RowNotFound, None).status(), StatusCode::INTERNAL_SERVER_ERROR);
        // A root of lines without roles, and its override by the client below.
        let root = s.profile_create(&sys, body(json!({"appId": 2, "clientId": c, "name": format!("zz pr {run}"), "description": "Rd", "arrangement": {"g": {"name": "G"}}}))).await.unwrap();
        let root_id = root.id.unwrap();
        assert_eq!(s.profile_create(&sys, body(json!({"appId": 2, "clientId": c, "name": "  "}))).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
        let unknown_root = body(json!({"appId": 2, "clientId": m, "rootProfileId": NONE, "name": "x"}));
        assert_eq!(s.profile_create(&sys, unknown_root).await.unwrap_err().status(), StatusCode::BAD_REQUEST);
        // An override of it by the client below (an override's name may be blank).
        let o = s.profile_create(&sys, body(json!({"rootProfileId": root_id, "appId": 2, "clientId": m, "name": "", "title": "Below", "arrangement": {"g": {"name": "G2"}}}))).await.unwrap();
        let o_id = o.id.unwrap();
        assert_eq!((o.root_profile_id, o.client_id), (Some(root_id), Some(m)));
        // Its own name and description, edited in place.
        let edited = body(json!({"id": o_id, "rootProfileId": root_id, "appId": 2, "clientId": m, "name": format!("zz po {run}"), "description": "Od"}));
        assert_eq!(s.profile_create(&sys, edited).await.unwrap().id, Some(o_id));
        let below = fx.as_user(&e, "ZZRUM", &["Authorities.Profile_READ"]);
        let seen = s.profile_read(&below, root_id).await.unwrap().unwrap();
        assert_eq!((seen.id, seen.name.as_deref(), seen.description.as_deref()), (Some(o_id), Some(format!("zz po {run}").as_str()), Some("Od")));
        assert_eq!(s.profile_read_object(&below, root_id).await.unwrap().id, Some(o_id));
        // A client without the app's access reads nothing.
        let mut outsider = below.clone();
        outsider.user.client_id = Some(NONE);
        assert!(s.profile_read_unchecked(&outsider, root_id).await.is_err() || s.profile_read_unchecked(&outsider, root_id).await.unwrap().is_none());
        let no_app = s.profile_create(&outsider, body(json!({"appId": 2, "clientId": c, "name": "x"}))).await;
        assert_eq!(no_app.unwrap_err().status(), StatusCode::FORBIDDEN);
        // No client given: Java's access check reads `CLIENT.ID = null`, which matches nothing.
        let own = fx.as_user(&e, "ZZRUM", &["Authorities.Profile_CREATE", "Authorities.Profile_UPDATE"]);
        let mine = s.profile_create(&own, body(json!({"appId": 2, "name": format!("zz pm {run}")}))).await;
        assert_eq!(mine.unwrap_err().status(), StatusCode::FORBIDDEN);
        // Restricting a client the caller does not manage, or one without the app: nothing.
        let from_m = fx.as_user(&e, "ZZRUM", &["Authorities.Profile_READ", "Authorities.Client_UPDATE"]);
        assert_eq!(s.profile_restrict_client(&from_m, root_id, c).await.unwrap(), None);
        // Deleting the root while the client below overrides it.
        assert!(!s.profile_delete(&sys, root_id).await.unwrap());
        let del = fx.as_user(&e, "ZZRUM", &["Authorities.Profile_DELETE"]);
        assert!(s.profile_delete(&del, root_id).await.unwrap(), "the override, as the client below sees the root");
        assert!(s.profile_delete(&sys, root_id).await.unwrap());
        // An override (and its root) left for the fixture's sweep to remove.
        let root2 = s.profile_create(&sys, body(json!({"appId": 2, "clientId": c, "name": format!("zz pr2 {run}")}))).await.unwrap().id.unwrap();
        s.profile_create(&sys, body(json!({"rootProfileId": root2, "appId": 2, "clientId": m, "name": "", "title": "Left"}))).await.unwrap();
        fx.finish().await;
    }
}
