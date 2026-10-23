//! What a document kind adds to the shared write path: the overrides the Java subclasses of
//! `AbstractOverridableDataService` make (`PageService`, `ApplicationService`, `StorageService`,
//! ...), as hooks with the base class's behaviour as their defaults.
//!
//! Each hook runs where the Java override's code runs relative to `super`: `before_*` before
//! the base method, `after_*` after it returned, `updatable_*` inside `updatableEntity`.

use async_trait::async_trait;
use platform::error::AppResult;
use platform::security::ContextAuthentication;

use crate::json::JMap;
use crate::pojo::{Pojo, OVERRIDABLE_BASE};
use crate::store::DocType;
use crate::write::service::Commons;

/// The access-check method, as in `Authorities.<Object>_<METHOD>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Create,
    Read,
    Update,
    Delete,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Create => "CREATE",
            Method::Read => "READ",
            Method::Update => "UPDATE",
            Method::Delete => "DELETE",
        }
    }
}

/// Copies every field the class declares beyond `AbstractOverridableDTO` from `incoming` onto
/// `existing`: what most `updatableEntity` implementations do field by field.
pub fn copy_content(pojo: &Pojo, existing: &mut JMap, incoming: &JMap) {
    for f in pojo.fields() {
        if OVERRIDABLE_BASE.iter().any(|b| b.name == f.name) {
            continue;
        }
        existing.insert(f.name.to_string(), incoming.get(f.name).cloned().unwrap_or_default());
    }
}

/// One overridable document kind and its overrides of the base service.
#[async_trait]
pub trait Kind: DocType {
    /// `getAccessCheckName()`: the object name in the authorities (`URIPath` and the fillers
    /// check `Application`).
    fn access_check_name(&self) -> &'static str {
        self.object_name()
    }

    /// `isVersionable()`: whether creates and updates write a `version` snapshot.
    fn versionable(&self) -> bool {
        true
    }

    /// Whether the class's `extractDifference` changes the entity in place and returns it, as
    /// nearly every Java document class does. Java snapshots the entity after the override was
    /// extracted, so for such a class a derived object's Version holds its delta.
    fn snapshot_is_override(&self) -> bool {
        true
    }

    /// Whether the Java `delete` override starts with `this.read(id)` (an access-checked read
    /// that answers 404), as Page, Style, Theme, Application, URIPath and the fillers do.
    fn delete_reads_first(&self) -> bool {
        false
    }

    /// Replaces the whole access check (`PersonalizationService` allows everything).
    async fn access_override(&self, _ca: &ContextAuthentication, _method: Method) -> Option<bool> {
        None
    }

    /// The start of `create`: names, validation, defaults (Application's name rule, the
    /// filler's name, URIPath's generated name, Storage's uniqueName).
    async fn before_create(&self, _cx: &Commons, _ca: &ContextAuthentication, _entity: &mut JMap) -> AppResult<()> {
        Ok(())
    }

    /// After `create` (and every fork, which creates): the kind's own evictions.
    async fn after_create(&self, _cx: &Commons, _created: &JMap) -> AppResult<()> {
        Ok(())
    }

    /// The start of `update`, on the body as sent (URIPath validates it here).
    async fn before_update(&self, _cx: &Commons, _ca: &ContextAuthentication, _entity: &mut JMap) -> AppResult<()> {
        Ok(())
    }

    /// In `updatableEntity`, before the version check (Personalization refuses another user's
    /// row first).
    async fn updatable_precheck(&self, _cx: &Commons, _ca: &ContextAuthentication, _existing: &JMap, _incoming: &JMap) -> AppResult<()> {
        Ok(())
    }

    /// In `updatableEntity`, after the version check and the version bump: copy the content
    /// from `incoming` (the override delta) onto `existing` (the merged stored object), and
    /// whatever else the class does there (Page bumps component versions, Function and Schema
    /// check the name, Storage validates).
    async fn updatable_fill(&self, _cx: &Commons, _ca: &ContextAuthentication, existing: &mut JMap, incoming: &JMap) -> AppResult<()> {
        copy_content(self.pojo(), existing, incoming);
        Ok(())
    }

    /// After `update` (and so after every publish): the kind's own evictions. `request` is
    /// the body as the caller sent it, before identity was taken from the stored row, which is
    /// what the Java ui overrides key their evictions on; `saved` is the merged result.
    async fn after_update(&self, _cx: &Commons, _request: &JMap, _saved: &JMap) -> AppResult<()> {
        Ok(())
    }

    /// Before the base `delete` (Personalization refuses another user's row).
    async fn before_delete(&self, _cx: &Commons, _ca: &ContextAuthentication, _stored: &JMap) -> AppResult<()> {
        Ok(())
    }

    /// After the base `delete`: evictions, and the answer (Page, Style and Theme answer the
    /// SSR publish's result rather than the delete's).
    async fn after_delete(&self, _cx: &Commons, _deleted: &JMap, result: bool) -> AppResult<bool> {
        Ok(result)
    }

    /// After the base `evictRecursively` (Schema and Storage rebuild tables).
    async fn after_evict_recursively(&self, _cx: &Commons, _app: &str, _client: &str, _name: &str) -> AppResult<()> {
        Ok(())
    }

    /// After the base `evictDraft` (the ui OUI and SSR caches, Application's index and
    /// properties caches, URIPath's pattern cache).
    async fn after_evict_draft(&self, _cx: &Commons, _app: &str, _client: &str, _name: &str) -> AppResult<()> {
        Ok(())
    }

    /// After the base `deleteEverything` of an app (Application's caches, core's draft data).
    async fn after_delete_everything(&self, _cx: &Commons, _app: &str, _client: &str) -> AppResult<()> {
        Ok(())
    }

    /// The end of `read(id)` (Connection hides credentials).
    async fn after_read(&self, _cx: &Commons, _ca: &ContextAuthentication, entity: JMap) -> AppResult<JMap> {
        Ok(entity)
    }

    /// Rust only: the document as a reply carries it, which may hold back what never leaves
    /// the service (a connection's credentials, masked). Every route that answers a document
    /// of the kind (the object, its draft, the eager list's `data`) answers this; reads inside
    /// the service still see the stored document.
    fn redact(&self, entity: JMap) -> JMap {
        entity
    }

    /// Rust only: what a save sends back held back (as [`Kind::redact`] answered it) put back
    /// from `current`, the stored document or the draft being replaced, before the save is
    /// applied. `None` on a create, which has nothing stored to keep.
    fn keep_withheld(&self, _incoming: &mut JMap, _current: Option<&JMap>) {}

    /// Rust only: whether a list request may filter or sort on `field` (a field
    /// [`Kind::redact`] holds back could be matched against a guess).
    fn filterable(&self, _field: &str) -> bool {
        true
    }

    /// `getTransportDependencies`: same-type names to import first.
    fn transport_dependencies(&self, _entity: &JMap) -> Vec<String> {
        Vec::new()
    }

    /// `stripTransportDependencies`: a copy without the links, for the first of two passes.
    fn strip_transport_dependencies(&self, _entity: &JMap) -> Option<JMap> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::JValue;
    use crate::pojo::{CloneRule, Field, Kind as K};

    #[test]
    fn methods_and_copies() {
        assert_eq!([Method::Create, Method::Read, Method::Update, Method::Delete].map(|m| m.as_str()), ["CREATE", "READ", "UPDATE", "DELETE"]);
        const P: Pojo = Pojo { name: "P", parts: &[OVERRIDABLE_BASE, &[Field::new("a", K::Str, CloneRule::Copy), Field::new("b", K::Str, CloneRule::Copy)]] };
        let mut existing = JMap::new();
        existing.insert("name".into(), JValue::Str("keep".into()));
        existing.insert("a".into(), JValue::Str("old".into()));
        let mut incoming = JMap::new();
        incoming.insert("name".into(), JValue::Str("ignored".into()));
        incoming.insert("b".into(), JValue::Str("new".into()));
        copy_content(&P, &mut existing, &incoming);
        assert_eq!(existing["name"], JValue::Str("keep".into()));
        assert_eq!(existing["a"], JValue::Null, "a field the request lacks is cleared, as a setter with null does");
        assert_eq!(existing["b"], JValue::Str("new".into()));
    }
}
