//! What Lighthouse servers send each other: the registry protocol's peer replication batch, and the digest
//! they compare once a minute to repair anything a batch lost.

use serde::{Deserialize, Serialize};

use crate::wire::{InstanceInfo, Lenient, Status};

/// Set to `true` on every call one server makes to another. A server never replicates what it
/// received this way again, and answers a stale heartbeat with 409 and its own copy.
pub const REPLICATION_HEADER: &str = "x-netflix-discovery-replication";

/// The operation a replicated item repeats on the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Heartbeat,
    Register,
    Cancel,
    StatusUpdate,
    DeleteStatusOverride,
}

/// One item of `POST /eureka/peerreplication/batch`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationInstance {
    pub app_name: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "lenient_opt")]
    pub last_dirty_timestamp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden_status: Option<Status>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// The whole instance, for `Register` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_info: Option<InstanceInfo>,
    pub action: Action,
}

fn lenient_opt<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    Ok(Option::<Lenient>::deserialize(d)?.map(|l| l.0))
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ReplicationList {
    #[serde(rename = "replicationList")]
    pub replication_list: Vec<ReplicationInstance>,
}

/// The peer's answer to one item: the status the single call would have answered, and for a
/// 409 the peer's newer copy, which the sender adopts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationInstanceResponse {
    pub status_code: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_entity: Option<InstanceInfo>,
}

/// One response per item, in the same order.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ReplicationListResponse {
    #[serde(rename = "responseList")]
    pub response_list: Vec<ReplicationInstanceResponse>,
}

/// `GET /v1/peer/digest`: what a server holds, small enough to compare every minute.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Digest {
    pub instances: Vec<DigestEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DigestEntry {
    pub app: String,
    pub id: String,
    pub status: Status,
    pub last_dirty_timestamp: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Java server's batch request and answer parse, and our answer writes the same shape.
    #[test]
    fn java_batch_shapes() {
        let req: ReplicationList = serde_json::from_str(include_str!("../tests/goldens/batch_request.json")).unwrap();
        assert_eq!(req.replication_list.len(), 3);
        assert_eq!(req.replication_list[0].action, Action::Heartbeat);
        assert_eq!(req.replication_list[0].overridden_status, Some(Status::Unknown));
        assert!(req.replication_list[1].last_dirty_timestamp.is_some());

        let golden = include_str!("../tests/goldens/batch_response.json");
        let resp: ReplicationListResponse = serde_json::from_str(golden).unwrap();
        let codes: Vec<u16> = resp.response_list.iter().map(|r| r.status_code).collect();
        assert_eq!(codes, vec![200, 404, 409]);
        assert_eq!(resp.response_list[2].response_entity.as_ref().unwrap().app, "FILES");
        assert_eq!(serde_json::to_string(&resp).unwrap(), golden);

        let item = ReplicationInstance {
            app_name: "A".into(),
            id: "i".into(),
            last_dirty_timestamp: None,
            overridden_status: None,
            status: None,
            instance_info: None,
            action: Action::Cancel,
        };
        let s = serde_json::to_string(&ReplicationList { replication_list: vec![item.clone()] }).unwrap();
        assert_eq!(s, r#"{"replicationList":[{"appName":"A","id":"i","action":"Cancel"}]}"#);
        let back: ReplicationList = serde_json::from_str(&s).unwrap();
        assert_eq!(back.replication_list[0], item);
        let dated: ReplicationInstance =
            serde_json::from_str(r#"{"appName":"A","id":"i","lastDirtyTimestamp":"7","action":"StatusUpdate"}"#).unwrap();
        assert_eq!(dated.last_dirty_timestamp, Some(7));

        let d = Digest {
            instances: vec![DigestEntry { app: "A".into(), id: "i".into(), status: Status::Up, last_dirty_timestamp: 3 }],
        };
        let s = serde_json::to_string(&d).unwrap();
        assert_eq!(s, r#"{"instances":[{"app":"A","id":"i","status":"UP","lastDirtyTimestamp":3}]}"#);
        assert_eq!(serde_json::from_str::<Digest>(&s).unwrap(), d);
    }
}
