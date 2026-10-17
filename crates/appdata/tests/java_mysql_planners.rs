//! Ports of the Java MySQL backend's pure unit tests (no database): the migration planner,
//! the table planner and its shape key, the type mapper, the value codec, and the static
//! helpers of `MySQLAppDataService` (naming, default connection, null and boolean
//! handling, read shaping, received field names).
//!
//! One `mod` per Java class, one sub-`mod` per `@Nested` class, one test per Java method.
//! Where Java renders jOOQ with its default dialect (`"name"`), the Rust builders render
//! MySQL's quoting (`` `name` ``); the assertions are otherwise the Java ones.
//! `MySQLTenantsOwningTest` needs a private method and lives in `src/mysql/service.rs`.
//! `mod extra` at the end is not a port: behaviour checked against the Java code.

use appdata::model::{Items, Schema, SchemaType, StringFormat};
use appdata::mysql::column::MySqlColumn;
use appdata::mysql::type_mapper;
use appdata::value::{Document, Value};

fn v(s: &str) -> Value {
    Value::parse_json(s).unwrap()
}

fn doc(s: &str) -> Document {
    match v(s) {
        Value::Object(o) => o,
        other => panic!("not an object: {other:?}"),
    }
}

fn typed(name: &str, t: SchemaType) -> Schema {
    Schema { name: Some(name.into()), types: Some(vec![t]), ..Default::default() }
}

/// `Schema.ofString(name).setMaxLength(n)`.
fn string_len(name: &str, n: i32) -> Schema {
    Schema { max_length: Some(n), ..Schema::of_string(name) }
}

fn integer(name: &str) -> Schema {
    typed(name, SchemaType::Integer)
}

fn long(name: &str) -> Schema {
    typed(name, SchemaType::Long)
}

fn double(name: &str) -> Schema {
    typed(name, SchemaType::Double)
}

fn boolean(name: &str) -> Schema {
    typed(name, SchemaType::Boolean)
}

/// `new Schema().setType(OBJECT).setProperties(props)`, properties in the given order.
fn object(props: Vec<(&str, Schema)>) -> Schema {
    Schema {
        types: Some(vec![SchemaType::Object]),
        properties: Some(props.into_iter().map(|(k, s)| (k.to_string(), s)).collect()),
        ..Default::default()
    }
}

fn columns(s: &Schema) -> Vec<MySqlColumn> {
    type_mapper::columns(Some(s), None).unwrap()
}

fn col(name: &str, t: &str) -> MySqlColumn {
    MySqlColumn::new(name, t, true).unwrap()
}

fn not_null(name: &str, t: &str) -> MySqlColumn {
    MySqlColumn::new(name, t, false).unwrap()
}

// ====================================================================== MySQLMigrationPlannerTest

mod mysql_migration_planner_test {
    use appdata::mysql::migration_planner::{self, MigrationStep, Phase};
    use appdata::mysql::table_planner::{Kind, SchemaChange};

    const DB: &str = "LZCLA_leadzump";
    const T: &str = "sales";

    fn plan(changes: Vec<SchemaChange>) -> Vec<MigrationStep> {
        migration_planner::plan(DB, T, 7, &changes).unwrap()
    }

    fn widen(c: &str, from: Option<&str>, to: &str) -> SchemaChange {
        SchemaChange::new(Kind::Widening, c, from, Some(to), "test")
    }

    fn narrow(c: &str, from: Option<&str>, to: &str) -> SchemaChange {
        SchemaChange::new(Kind::Narrowing, c, from, Some(to), "test")
    }

    fn drop(c: &str, from: &str) -> SchemaChange {
        SchemaChange::new(Kind::Destructive, c, Some(from), None, "test")
    }

    fn phases(steps: &[MigrationStep]) -> Vec<Phase> {
        steps.iter().map(|s| s.phase).collect()
    }

    fn sql(s: &MigrationStep) -> &str {
        s.sql.as_deref().unwrap()
    }

    fn first(steps: Vec<MigrationStep>, phase: Phase) -> MigrationStep {
        steps.into_iter().find(|s| s.phase == phase).unwrap()
    }

    mod widening {
        use super::*;

        #[test]
        fn new_column() {
            let p = plan(vec![widen("region", None, "VARCHAR(40)")]);
            assert_eq!(p.len(), 1);
            assert!(sql(&p[0]).contains("ADD COLUMN `region` VARCHAR(40) NULL"));
            assert!(p[0].data_check.is_none(), "a widening cannot lose data");
        }

        #[test]
        fn modify_in_place() {
            let p = plan(vec![widen("code", Some("VARCHAR(10)"), "VARCHAR(50)")]);
            assert_eq!(p.len(), 1);
            assert!(sql(&p[0]).contains("MODIFY COLUMN `code` VARCHAR(50)"));
        }

        #[test]
        fn no_snapshot_for_safe_plans() {
            assert!(!phases(&plan(vec![widen("a", None, "INT"), widen("b", None, "INT")])).contains(&Phase::Snapshot));
        }
    }

    mod narrowing {
        use super::*;

        #[test]
        fn the_case_that_started_all_this() {
            let p = plan(vec![narrow("amount", Some("VARCHAR(40)"), "DOUBLE")]);
            assert_eq!(
                phases(&p),
                vec![Phase::Snapshot, Phase::Preflight, Phase::Expand, Phase::Backfill, Phase::Verify, Phase::Contract, Phase::Contract]
            );
        }

        #[test]
        fn old_column_survives_until_verified() {
            let p = plan(vec![narrow("amount", Some("VARCHAR(40)"), "DOUBLE")]);
            let verify = phases(&p).iter().position(|ph| *ph == Phase::Verify).unwrap() as isize;
            let first_drop = p
                .iter()
                .rposition(|s| s.sql.as_deref().is_some_and(|q| q.contains("DROP COLUMN `amount`")))
                .map(|i| i as isize)
                .unwrap_or(-1);
            assert!(verify < first_drop, "nothing destructive may precede the check");
        }

        #[test]
        fn preflight_touches_only_the_original_column() {
            let pre = first(plan(vec![narrow("amount", Some("VARCHAR(40)"), "DOUBLE")]), Phase::Preflight);
            let check = pre.data_check.as_deref().unwrap();
            assert!(check.contains("`amount` IS NOT NULL"), "{check}");
            assert!(
                !check.contains("amount__v"),
                "a pre-flight that needs the temporary column cannot run before the migration"
            );
        }

        #[test]
        fn backfill_filters_to_convertible_rows() {
            let back = first(plan(vec![narrow("amount", Some("VARCHAR(40)"), "DOUBLE")]), Phase::Backfill);
            assert!(sql(&back).contains("REGEXP"), "{}", sql(&back));
        }

        #[test]
        fn backfill_is_dml() {
            let back = first(plan(vec![narrow("amount", Some("VARCHAR(40)"), "DOUBLE")]), Phase::Backfill);
            assert!(sql(&back).starts_with("UPDATE "), "{}", sql(&back));
        }

        #[test]
        fn temporary_column_is_version_scoped() {
            assert!(plan(vec![narrow("amount", Some("VARCHAR(40)"), "DOUBLE")])
                .iter()
                .any(|s| s.sql.as_deref().is_some_and(|q| q.contains("amount__v7"))));
        }

        #[test]
        fn new_not_null_column_is_checked_against_existing_rows() {
            let p = plan(vec![narrow("code", None, "VARCHAR(10)")]);
            assert_eq!(phases(&p), vec![Phase::Snapshot, Phase::Preflight, Phase::Expand]);
            assert!(p[1].data_check.as_deref().unwrap().contains("SELECT COUNT(*)"));
        }
    }

    mod destructive {
        use super::*;

        #[test]
        fn snapshot_precedes_the_drop() {
            let p = plan(vec![drop("legacy", "VARCHAR(10)")]);
            assert_eq!(p[0].phase, Phase::Snapshot);
            assert!(sql(&p[0]).contains("sales__bak_7"));
        }

        #[test]
        fn drop_reports_what_would_be_lost() {
            let d = first(plan(vec![drop("legacy", "VARCHAR(10)")]), Phase::Contract);
            assert!(d.data_check.as_deref().unwrap().contains("`legacy` IS NOT NULL"));
            assert!(d.is_destructive());
        }

        #[test]
        fn snapshot_is_taken_once() {
            let snapshots = plan(vec![drop("a", "INT"), drop("b", "INT"), narrow("c", Some("VARCHAR(9)"), "INT")])
                .iter()
                .filter(|s| s.phase == Phase::Snapshot)
                .count();
            assert_eq!(snapshots, 1);
        }
    }

    mod reruns {
        use super::*;

        #[test]
        fn every_statement_has_a_precondition() {
            let p = plan(vec![widen("a", None, "INT"), narrow("amount", Some("VARCHAR(40)"), "DOUBLE"), drop("old", "INT")]);
            for s in p.iter().filter(|s| s.sql.is_some()) {
                let pre = s.precondition.as_deref().unwrap_or_else(|| panic!("unguarded step: {}", sql(s)));
                assert!(pre.contains("information_schema"), "{pre}");
            }
        }

        #[test]
        fn preconditions_match_their_statements() {
            let add = &plan(vec![widen("region", None, "VARCHAR(40)")])[0];
            assert!(add.precondition.as_deref().unwrap().contains("= 0"), "an ADD must be skipped if already applied");
            let modify = &plan(vec![widen("code", Some("VARCHAR(10)"), "VARCHAR(50)")])[0];
            assert!(!modify.precondition.as_deref().unwrap().contains("= 0"), "a MODIFY needs the column to exist");
        }

        #[test]
        fn snapshot_is_guarded_too() {
            let snap = &plan(vec![drop("a", "INT")])[0];
            assert!(snap.precondition.as_deref().unwrap().contains("information_schema.TABLES"));
            assert!(snap.precondition.as_deref().unwrap().contains("= 0"));
        }

        /// Java also passes a null list; a slice cannot be null, so only the empty half ports.
        #[test]
        fn an_empty_change_set_produces_no_plan() {
            assert!(migration_planner::plan(DB, T, 1, &[]).unwrap().is_empty());
        }
    }

    mod ordering {
        use super::*;

        #[test]
        fn snapshot_is_always_first() {
            let p = plan(vec![widen("fresh", None, "INT"), drop("legacy", "INT"), narrow("amt", Some("VARCHAR(9)"), "INT")]);
            assert_eq!(p[0].phase, Phase::Snapshot);
        }

        #[test]
        fn contract_never_precedes_its_verify() {
            let p = plan(vec![narrow("amt", Some("VARCHAR(9)"), "INT")]);
            let mut verify: isize = -1;
            for (i, s) in p.iter().enumerate() {
                if matches!(s.phase, Phase::Verify | Phase::Preflight) {
                    verify = i as isize;
                }
                if s.phase == Phase::Contract {
                    assert!(verify >= 0 && verify < i as isize, "CONTRACT at {i} has no preceding VERIFY");
                }
            }
        }
    }
}

// ====================================================================== MySQLNestedStructureTest

mod mysql_nested_structure_test {
    use super::*;

    fn column(storage: &Schema, name: &str) -> MySqlColumn {
        columns(storage).into_iter().find(|c| c.name() == name).unwrap()
    }

    fn note(c: &MySqlColumn) -> &str {
        c.note.as_deref().unwrap()
    }

    mod mapping {
        use super::*;

        #[test]
        fn nested_object() {
            let address = object(vec![("city", string_len("city", 60)), ("pin", string_len("pin", 6))]);
            let c = column(&object(vec![("address", address)]), "address");
            assert_eq!(c.column_type, "JSON");
            assert!(note(&c).contains("2 field(s)"), "{}", note(&c));
        }

        #[test]
        fn note_warns_about_joins() {
            let c = column(&object(vec![("address", object(vec![("city", Schema::of_string("city"))]))]), "address");
            assert!(note(&c).contains("not joinable"), "{}", note(&c));
            assert!(note(&c).contains("Lift a field to the top level"), "{}", note(&c));
        }

        #[test]
        fn array() {
            let tags = Schema::of_array("tags", Schema::of_string("tag"));
            assert_eq!(column(&object(vec![("tags", tags)]), "tags").column_type, "JSON");
        }

        #[test]
        fn properties_imply_object() {
            let loose = Schema { properties: Some([("city".to_string(), Schema::of_string("city"))].into_iter().collect()), ..Default::default() };
            let c = column(&object(vec![("address", loose)]), "address");
            assert_eq!(c.column_type, "JSON");
            assert!(note(&c).contains("it has properties"), "{}", note(&c));
        }

        #[test]
        fn items_imply_array() {
            let loose = Schema { items: Some(Items::Single(Box::new(Schema::of_string("x")))), ..Default::default() };
            assert!(note(&column(&object(vec![("xs", loose)]), "xs")).contains("array"));
        }

        /// `Schema.ofRef`: a schema that is only a ref.
        #[test]
        fn unresolved_ref() {
            let thing = Schema { reference: Some("App.Missing".into()), ..Default::default() };
            let c = column(&object(vec![("thing", thing)]), "thing");
            assert_eq!(c.column_type, "JSON");
            assert!(note(&c).contains("App.Missing"), "{}", note(&c));
        }

        #[test]
        fn listed() {
            let storage = object(vec![
                ("name", string_len("name", 10)),
                ("address", object(vec![("city", Schema::of_string("city"))])),
                ("tags", Schema::of_array("tags", Schema::of_string("t"))),
            ]);
            let mut json: Vec<String> = type_mapper::json_columns(Some(&storage), None).unwrap().into_iter().collect();
            json.sort();
            assert_eq!(json, vec!["address", "tags"]);
        }

        #[test]
        fn column_exists() {
            let storage = object(vec![("address", object(vec![("city", Schema::of_string("city"))]))]);
            assert_eq!(columns(&storage).len(), 1, "a nested field that maps to nothing loses every write to it in silence");
        }
    }

    mod paths {
        use appdata::model::{ComplexCondition, Condition, FilterCondition, FilterOperator};
        use appdata::mysql::field_resolver::FieldResolver;
        use appdata::mysql::filter_builder::{self, FilterError};
        use indexmap::IndexSet;

        fn json() -> IndexSet<String> {
            ["address".to_string()].into_iter().collect()
        }

        fn build(c: Condition) -> Result<String, FilterError> {
            filter_builder::build_json(Some(&c), json()).map(|w| w.inlined())
        }

        fn sql(fc: FilterCondition) -> String {
            build(fc.into()).unwrap()
        }

        #[test]
        fn path() {
            let s = sql(FilterCondition::eq("address.city", "Pune"));
            assert!(s.contains("json_extract"), "{s}");
            assert!(s.contains("$.city"), "{s}");
        }

        #[test]
        fn unquoted() {
            assert!(sql(FilterCondition::eq("address.city", "Pune")).contains("json_unquote"));
        }

        #[test]
        fn deep_path() {
            let s = sql(FilterCondition::eq("address.geo.lat", "18.5"));
            assert!(s.contains("$.geo.lat"), "{s}");
        }

        /// Java's default-dialect `"some.name"` is MySQL's `` `some.name` `` here.
        #[test]
        fn not_json() {
            let s = sql(FilterCondition::eq("some.name", "x"));
            assert!(s.contains("`some.name`"), "{s}");
        }

        #[test]
        fn refuses_junk() {
            assert!(build(FilterCondition::eq("address.c'ty", "x").into()).is_err());
        }

        #[test]
        fn trailing_dot() {
            assert!(sql(FilterCondition::eq("address.", "x")).contains("`address.`"));
        }

        #[test]
        fn in_group() {
            let s = build(
                ComplexCondition::and(vec![FilterCondition::eq("address.city", "Pune").into(), FilterCondition::eq("name", "Asha").into()])
                    .into(),
            )
            .unwrap();
            assert!(s.contains("json_extract"), "{s}");
            assert!(s.contains("`name`"), "{s}");
        }

        /// The single-argument build is a resolver with no JSON columns.
        #[test]
        fn default_is_unchanged() {
            let s = filter_builder::build(Some(&FilterCondition::eq("address.city", "Pune").into()), &FieldResolver::of(IndexSet::new()))
                .unwrap()
                .inlined();
            assert!(s.contains("`address.city`"), "{s}");
        }

        #[test]
        fn in_on_path() {
            let fc = FilterCondition::new("address.city", FilterOperator::In, None).with_multi_value(vec!["Pune".into(), "Mumbai".into()]);
            let s = sql(fc);
            assert!(s.contains("json_extract"), "{s}");
            assert!(s.contains("Mumbai"), "{s}");
        }
    }
}

// ====================================================================== MySQLOverrideChainTest

mod mysql_override_chain_test {
    use super::*;
    use appdata::mysql::table_planner::{self, Kind, SchemaChange};

    /// Child over parent, which is what the override chain resolves to.
    fn merged(parent: &Schema, child: Vec<(&str, Schema)>, child_required: Option<Vec<&str>>) -> Schema {
        let mut props = parent.properties.clone().unwrap_or_default();
        for (k, s) in child {
            props.insert(k.to_string(), s);
        }
        Schema {
            types: Some(vec![SchemaType::Object]),
            properties: Some(props),
            required: match child_required {
                Some(r) => Some(r.into_iter().map(str::to_string).collect()),
                None => parent.required.clone(),
            },
            ..Default::default()
        }
    }

    fn names(cols: &[MySqlColumn]) -> Vec<String> {
        cols.iter().map(|c| c.name().to_string()).collect()
    }

    fn named(cols: Vec<MySqlColumn>, name: &str) -> Option<MySqlColumn> {
        cols.into_iter().find(|c| c.name() == name)
    }

    fn change_for(changes: Vec<SchemaChange>, column: &str) -> Option<SchemaChange> {
        changes.into_iter().find(|c| c.column == column)
    }

    fn diff(before: &Schema, after: &Schema) -> Vec<SchemaChange> {
        table_planner::diff(&columns(before), &columns(after))
    }

    fn system_schema() -> Schema {
        object(vec![("code", string_len("code", 20)), ("amount", string_len("amount", 40))])
    }

    mod three_level_structure {
        use super::*;

        #[test]
        fn inherits_down_the_chain() {
            let system = system_schema();
            let mid = merged(&system, vec![("region", string_len("region", 30))], None);
            let leaf = merged(&mid, vec![("tier", integer("tier"))], None);
            assert_eq!(names(&columns(&system)), vec!["amount", "code"]);
            assert_eq!(names(&columns(&mid)), vec!["amount", "code", "region"]);
            assert_eq!(names(&columns(&leaf)), vec!["amount", "code", "region", "tier"]);
        }

        #[test]
        fn does_not_leak_upward() {
            let system = system_schema();
            let mid = merged(&system, vec![("region", string_len("region", 30))], None);
            assert!(!names(&columns(&system)).contains(&"region".to_string()));
            assert!(names(&columns(&mid)).contains(&"region".to_string()));
        }

        #[test]
        fn siblings_are_independent() {
            let system = system_schema();
            let a = merged(&system, vec![("aOnly", integer("aOnly"))], None);
            let b = merged(&system, vec![("bOnly", integer("bOnly"))], None);
            assert!(!names(&columns(&a)).contains(&"bOnly".to_string()));
            assert!(!names(&columns(&b)).contains(&"aOnly".to_string()));
        }

        #[test]
        fn id_is_uniform_across_the_chain() {
            let system = system_schema();
            let leaf = merged(&merged(&system, vec![("x", integer("x"))], None), vec![("y", integer("y"))], None);
            for s in [system, leaf] {
                assert!(table_planner::create_table("t", &columns(&s)).contains("`_id` CHAR(26) NOT NULL"));
            }
        }
    }

    mod override_type_changes {
        use super::*;

        #[test]
        fn child_narrows_inherited_field() {
            let system = system_schema();
            let mid = merged(&system, vec![("amount", double("amount"))], None);
            let c = change_for(diff(&system, &mid), "amount").unwrap();
            assert_eq!(c.kind, Kind::Narrowing);
            assert!(c.needs_data_check(), "the child's own rows must be counted before this applies");
        }

        #[test]
        fn child_widens_inherited_field() {
            let system = object(vec![("note", string_len("note", 20))]);
            let mid = merged(&system, vec![("note", string_len("note", 500))], None);
            assert_eq!(change_for(diff(&system, &mid), "note").unwrap().kind, Kind::Widening);
        }

        #[test]
        fn most_derived_type_wins() {
            let system = object(vec![("v", string_len("v", 10))]);
            let mid = merged(&system, vec![("v", integer("v"))], None);
            let leaf = merged(&mid, vec![("v", long("v"))], None);
            assert_eq!(named(columns(&system), "v").unwrap().column_type, "VARCHAR(10)");
            assert_eq!(named(columns(&mid), "v").unwrap().column_type, "INT");
            assert_eq!(named(columns(&leaf), "v").unwrap().column_type, "BIGINT");
        }

        #[test]
        fn child_adds_required() {
            let system = object(vec![("code", string_len("code", 20))]);
            let mid = merged(&system, vec![], Some(vec!["code"]));
            let c = change_for(diff(&system, &mid), "code").unwrap();
            assert_eq!(c.kind, Kind::Narrowing);
            assert!(c.reason.contains("null"));
        }

        #[test]
        fn date_typing_survives_the_chain() {
            let system = object(vec![("when", Schema::of_string("when").with_format(StringFormat::DateTime))]);
            let leaf = merged(&merged(&system, vec![("a", integer("a"))], None), vec![("b", integer("b"))], None);
            assert_eq!(named(columns(&leaf), "when").unwrap().column_type, "DATETIME(3)");
        }
    }

    mod base_change_propagation {
        use super::*;

        #[test]
        fn widening_propagates_safely() {
            let before = object(vec![("code", string_len("code", 20))]);
            let after = object(vec![("code", string_len("code", 100))]);
            for adds in [vec![], vec![("region", string_len("region", 5))]] {
                let cs = diff(&merged(&before, adds.clone(), None), &merged(&after, adds, None));
                assert!(cs.iter().all(|c| c.kind == Kind::Widening), "{cs:?}");
            }
        }

        #[test]
        fn narrowing_propagates_as_narrowing_everywhere() {
            let before = object(vec![("amount", string_len("amount", 40))]);
            let after = object(vec![("amount", double("amount"))]);
            let descendants = vec![
                vec![],
                vec![("region", string_len("region", 5))],
                vec![("region", string_len("region", 5)), ("tier", integer("tier"))],
            ];
            for adds in descendants {
                let keys: Vec<&str> = adds.iter().map(|(k, _)| *k).collect();
                let c = change_for(diff(&merged(&before, adds.clone(), None), &merged(&after, adds.clone(), None)), "amount").unwrap();
                assert_eq!(c.kind, Kind::Narrowing, "descendant with {keys:?} must also be checked");
            }
        }

        #[test]
        fn child_override_shields_it_from_the_base() {
            let before = object(vec![("amount", string_len("amount", 40))]);
            let after = object(vec![("amount", double("amount"))]);
            let pins = vec![("amount", long("amount"))];
            let cs = diff(&merged(&before, pins.clone(), None), &merged(&after, pins, None));
            assert!(cs.is_empty(), "a pinned override must absorb the base change: {cs:?}");
        }

        #[test]
        fn base_drop_is_destructive_downstream() {
            let before = object(vec![("code", string_len("code", 20)), ("legacy", string_len("legacy", 10))]);
            let after = object(vec![("code", string_len("code", 20))]);
            let c = change_for(
                diff(&merged(&before, vec![("x", integer("x"))], None), &merged(&after, vec![("x", integer("x"))], None)),
                "legacy",
            )
            .unwrap();
            assert_eq!(c.kind, Kind::Destructive);
            assert!(c.needs_data_check());
        }
    }

    mod draft_and_live {
        use super::*;

        #[test]
        fn draft_may_be_ahead_of_live() {
            let live = system_schema();
            let draft = merged(&live, vec![("experiment", string_len("experiment", 10))], None);
            assert!(!names(&columns(&live)).contains(&"experiment".to_string()));
            assert!(names(&columns(&draft)).contains(&"experiment".to_string()));
        }

        #[test]
        fn publish_applies_the_draft_to_live() {
            let live = system_schema();
            let draft = merged(&live, vec![("experiment", string_len("experiment", 10))], None);
            let cs = diff(&live, &draft);
            assert_eq!(cs.len(), 1);
            assert_eq!(cs[0].column, "experiment");
            assert_eq!(cs[0].kind, Kind::Widening);
        }

        #[test]
        fn draft_clean_does_not_mean_live_clean() {
            let before = object(vec![("amount", string_len("amount", 40))]);
            let after = object(vec![("amount", double("amount"))]);
            let cs = diff(&before, &after);
            assert_eq!(cs[0].kind, Kind::Narrowing);
            assert!(cs[0].needs_data_check(), "the surface does not change the classification");
        }

        #[test]
        fn unchanged_draft_produces_no_ddl() {
            let s = system_schema();
            assert!(diff(&s, &s).is_empty());
        }

        #[test]
        fn reverted_draft_is_a_no_op() {
            let live = system_schema();
            let added = merged(&live, vec![("tmp", integer("tmp"))], None);
            assert!(!diff(&live, &added).is_empty());
            assert!(diff(&live, &system_schema()).is_empty());
        }
    }

    mod recovery {
        use super::*;

        #[test]
        fn plan_is_idempotent() {
            let after = merged(&system_schema(), vec![("extra", integer("extra"))], None);
            let applied = columns(&after);
            assert!(table_planner::diff(&applied, &applied).is_empty(), "re-running must find nothing left to do");
        }

        #[test]
        fn partial_application_leaves_the_rest_visible() {
            let before = object(vec![("a", integer("a"))]);
            let after = object(vec![("a", integer("a")), ("b", integer("b")), ("c", integer("c"))]);
            let halfway = object(vec![("a", integer("a")), ("b", integer("b"))]);
            assert_eq!(diff(&before, &after).len(), 2);
            assert_eq!(diff(&halfway, &after).into_iter().map(|c| c.column).collect::<Vec<_>>(), vec!["c"]);
        }

        #[test]
        fn rename_is_add_then_drop() {
            let cs = diff(&object(vec![("oldName", integer("oldName"))]), &object(vec![("newName", integer("newName"))]));
            assert_eq!(cs.len(), 2);
            assert_eq!(cs[0].column, "newName");
            assert_eq!(cs[1].kind, Kind::Destructive);
            assert_eq!(cs[1].column, "oldName");
        }
    }
}

// ====================================================================== MySQLShapeKeyTest

mod mysql_shape_key_test {
    use super::*;
    use appdata::mysql::table_planner::shape_of;

    fn name() -> MySqlColumn {
        col("name", "VARCHAR(60)")
    }

    fn age() -> MySqlColumn {
        col("age", "INT")
    }

    #[test]
    fn stable() {
        assert_eq!(shape_of(&[name(), age()]), shape_of(&[name(), age()]));
    }

    #[test]
    fn order_independent() {
        assert_eq!(shape_of(&[name(), age()]), shape_of(&[age(), name()]));
    }

    #[test]
    fn type_change() {
        assert_ne!(shape_of(&[name()]), shape_of(&[col("name", "VARCHAR(120)")]));
    }

    #[test]
    fn nullability_change() {
        assert_ne!(shape_of(&[name()]), shape_of(&[not_null("name", "VARCHAR(60)")]));
    }

    #[test]
    fn added_column() {
        assert_ne!(shape_of(&[name()]), shape_of(&[name(), age()]));
    }

    #[test]
    fn renamed_column() {
        assert_ne!(shape_of(&[name()]), shape_of(&[col("title", "VARCHAR(60)")]));
    }

    #[test]
    fn type_case_insensitive() {
        assert_eq!(shape_of(&[name()]), shape_of(&[col("name", "varchar(60)")]));
    }

    #[test]
    fn note_ignored() {
        let noted = MySqlColumn::with_note("name", "VARCHAR(60)", true, Some("declare maxLength".into())).unwrap();
        assert_eq!(shape_of(&[name()]), shape_of(&[noted]));
    }

    /// Java also passes null; a slice cannot be null, so the empty slice stands for both.
    #[test]
    fn empty() {
        assert_eq!(shape_of(&[]).len(), 32);
        assert_ne!(shape_of(&[]), shape_of(&[name()]));
    }
}

// ====================================================================== MySQLTablePlannerTest

mod mysql_table_planner_test {
    use super::*;
    use appdata::mysql::table_planner::{create_table, diff, Kind, SchemaChange};

    fn one(before: Vec<MySqlColumn>, after: Vec<MySqlColumn>) -> SchemaChange {
        let cs = diff(&before, &after);
        assert_eq!(cs.len(), 1, "expected exactly one change, got {cs:?}");
        cs.into_iter().next().unwrap()
    }

    mod create_table {
        use super::*;

        #[test]
        fn always_has_the_ulid_primary_key() {
            let ddl = create_table("sales", &[col("region", "VARCHAR(40)")]);
            assert!(ddl.contains("`_id` CHAR(26) NOT NULL"), "{ddl}");
            assert!(ddl.contains("PRIMARY KEY (`_id`)"), "{ddl}");
        }

        #[test]
        fn is_idempotent_by_construction() {
            assert!(create_table("t", &[]).starts_with("CREATE TABLE IF NOT EXISTS"));
        }

        #[test]
        fn emits_every_column() {
            let ddl = create_table("t", &[col("a", "INT"), not_null("b", "VARCHAR(10)")]);
            assert!(ddl.contains("`a` INT NULL"), "{ddl}");
            assert!(ddl.contains("`b` VARCHAR(10) NOT NULL"), "{ddl}");
        }
    }

    mod widening {
        use super::*;

        #[test]
        fn new_nullable_column_is_safe() {
            assert_eq!(one(vec![], vec![col("a", "INT")]).kind, Kind::Widening);
        }

        #[test]
        fn longer_varchar_is_safe() {
            assert_eq!(one(vec![col("a", "VARCHAR(10)")], vec![col("a", "VARCHAR(50)")]).kind, Kind::Widening);
        }

        #[test]
        fn varchar_to_text_is_safe() {
            assert_eq!(one(vec![col("a", "VARCHAR(10)")], vec![col("a", "TEXT")]).kind, Kind::Widening);
        }

        #[test]
        fn int_to_bigint_is_safe() {
            assert_eq!(one(vec![col("a", "INT")], vec![col("a", "BIGINT")]).kind, Kind::Widening);
        }

        #[test]
        fn dropping_not_null_is_safe() {
            assert_eq!(one(vec![not_null("a", "INT")], vec![col("a", "INT")]).kind, Kind::Widening);
        }

        #[test]
        fn widening_needs_no_data_check() {
            assert!(!one(vec![], vec![col("a", "INT")]).needs_data_check());
        }
    }

    mod narrowing {
        use super::*;

        #[test]
        fn the_case_that_started_all_this() {
            let c = one(vec![col("amount", "VARCHAR(40)")], vec![col("amount", "DOUBLE")]);
            assert_eq!(c.kind, Kind::Narrowing);
            assert!(c.needs_data_check());
        }

        #[test]
        fn shorter_varchar_is_narrowing() {
            assert_eq!(one(vec![col("a", "VARCHAR(50)")], vec![col("a", "VARCHAR(10)")]).kind, Kind::Narrowing);
        }

        #[test]
        fn bigint_to_int_is_narrowing() {
            assert_eq!(one(vec![col("a", "BIGINT")], vec![col("a", "INT")]).kind, Kind::Narrowing);
        }

        #[test]
        fn text_to_varchar_is_narrowing() {
            assert_eq!(one(vec![col("a", "TEXT")], vec![col("a", "VARCHAR(10)")]).kind, Kind::Narrowing);
        }

        #[test]
        fn adding_not_null_is_narrowing() {
            let c = one(vec![col("a", "INT")], vec![not_null("a", "INT")]);
            assert_eq!(c.kind, Kind::Narrowing);
            assert!(c.reason.contains("null"));
        }

        #[test]
        fn a_new_not_null_column_is_narrowing_not_widening() {
            assert_eq!(one(vec![], vec![not_null("a", "INT")]).kind, Kind::Narrowing);
        }

        #[test]
        fn unrecognised_conversions_are_treated_as_unsafe() {
            assert_eq!(one(vec![col("a", "JSON")], vec![col("a", "DATETIME(3)")]).kind, Kind::Narrowing);
        }
    }

    mod destructive {
        use super::*;

        #[test]
        fn removing_a_column_is_destructive() {
            let c = one(vec![col("a", "INT")], vec![]);
            assert_eq!(c.kind, Kind::Destructive);
            assert!(c.needs_data_check());
        }
    }

    mod plan_ordering {
        use super::*;

        #[test]
        fn adds_come_before_drops() {
            let cs = diff(&[col("old", "INT")], &[col("new", "INT")]);
            assert_eq!(cs.len(), 2);
            assert_eq!(cs[0].column, "new");
            assert_eq!(cs[1].kind, Kind::Destructive);
        }

        #[test]
        fn identical_schemas_produce_no_plan() {
            let same = vec![col("a", "INT"), not_null("b", "VARCHAR(5)")];
            assert!(diff(&same, &same).is_empty());
        }

        #[test]
        fn type_comparison_ignores_case() {
            assert!(diff(&[col("a", "int")], &[col("a", "INT")]).is_empty());
        }
    }
}

// ====================================================================== MySQLTypeMapperTest

mod mysql_type_mapper_test {
    use super::*;

    fn obj(props: Vec<(&str, Schema)>) -> Schema {
        object(props)
    }

    fn only(field: Schema) -> MySqlColumn {
        let cols = columns(&obj(vec![("f", field)]));
        assert_eq!(cols.len(), 1);
        cols.into_iter().next().unwrap()
    }

    fn string() -> Schema {
        Schema::of_string("f")
    }

    mod scalars {
        use super::*;

        #[test]
        fn maps_each_numeric_type_distinctly() {
            assert_eq!(only(integer("f")).column_type, "INT");
            assert_eq!(only(long("f")).column_type, "BIGINT");
            assert_eq!(only(typed("f", SchemaType::Float)).column_type, "FLOAT");
            assert_eq!(only(double("f")).column_type, "DOUBLE");
        }

        #[test]
        fn maps_boolean() {
            assert_eq!(only(boolean("f")).column_type, "TINYINT(1)");
        }

        #[test]
        fn nested_data_becomes_json_and_says_why() {
            let c = only(Schema { types: Some(vec![SchemaType::Object]), ..Default::default() });
            assert_eq!(c.column_type, "JSON");
            assert!(c.note.is_some(), "an author should be told JSON is not joinable");
        }
    }

    mod strings {
        use super::*;

        #[test]
        fn declared_length_becomes_varchar() {
            let c = only(string_len("f", 120));
            assert_eq!(c.column_type, "VARCHAR(120)");
            assert!(c.note.is_none(), "a well-specified string needs no caveat");
        }

        #[test]
        fn no_length_becomes_text_with_a_caveat() {
            let c = only(string());
            assert_eq!(c.column_type, "TEXT");
            assert!(c.note.as_deref().unwrap().contains("maxLength"), "the caveat should say how to fix it");
        }

        #[test]
        fn absurd_length_falls_back_to_text() {
            let c = only(string_len("f", 100000));
            assert_eq!(c.column_type, "TEXT");
            assert!(c.note.is_some());
        }

        #[test]
        fn nonsense_length_does_not_produce_nonsense_ddl() {
            let c = only(string_len("f", 0));
            assert_eq!(c.column_type, "VARCHAR(255)");
            assert!(c.note.is_some());
        }

        #[test]
        fn an_enum_is_sized_to_its_longest_value() {
            let c = only(Schema { enums: Some(vec!["OPEN".into(), "IN_PROGRESS".into()]), ..string() });
            assert_eq!(c.column_type, "VARCHAR(11)");
            assert!(c.note.is_none());
        }

        #[test]
        fn a_declared_length_wins_over_an_enum() {
            assert_eq!(only(Schema { enums: Some(vec!["OPEN".into()]), ..string_len("f", 40) }).column_type, "VARCHAR(40)");
        }

        #[test]
        fn an_enum_with_a_non_string_value_is_not_sized_from_it() {
            assert_eq!(only(Schema { enums: Some(vec!["OPEN".into(), Value::Int(3)]), ..string() }).column_type, "TEXT");
        }

        #[test]
        fn an_email_with_no_length_is_still_indexable() {
            let c = only(string().with_format(StringFormat::Email));
            assert_eq!(c.column_type, "VARCHAR(320)");
            assert!(c.note.is_none());
        }
    }

    mod dates {
        use super::*;

        #[test]
        fn declared_date_formats_become_real_date_columns() {
            assert_eq!(only(string().with_format(StringFormat::DateTime)).column_type, "DATETIME(3)");
            assert_eq!(only(string().with_format(StringFormat::Date)).column_type, "DATE");
            assert_eq!(only(string().with_format(StringFormat::Time)).column_type, "TIME(3)");
        }

        #[test]
        fn format_wins_over_length() {
            assert_eq!(only(string_len("f", 40).with_format(StringFormat::DateTime)).column_type, "DATETIME(3)");
        }

        #[test]
        fn a_format_that_is_not_a_date_is_still_a_string() {
            assert_eq!(only(string_len("f", 80).with_format(StringFormat::Email)).column_type, "VARCHAR(80)");
        }
    }

    mod nullability {
        use super::*;

        #[test]
        fn required_fields_are_not_null() {
            let s = Schema { required: Some(vec!["a".into()]), ..obj(vec![("a", integer("a")), ("b", integer("b"))]) };
            let by_name: std::collections::HashMap<String, MySqlColumn> =
                columns(&s).into_iter().map(|c| (c.name().to_string(), c)).collect();
            assert!(by_name["a"].ddl().ends_with("NOT NULL"));
            assert!(by_name["b"].ddl().ends_with("NULL"));
            assert!(!by_name["b"].ddl().ends_with("NOT NULL"));
        }
    }

    mod edges {
        use super::*;

        #[test]
        fn the_id_column_is_never_derived_from_the_schema() {
            let cols = columns(&obj(vec![("_id", Schema::of_string("_id")), ("name", Schema::of_string("name"))]));
            assert_eq!(cols.len(), 1);
            assert_eq!(cols[0].name(), "name");
        }

        #[test]
        fn output_is_ordered_so_ddl_is_stable_across_runs() {
            let cols = columns(&obj(vec![("zebra", integer("zebra")), ("apple", integer("apple")), ("mango", integer("mango"))]));
            assert_eq!(cols.iter().map(|c| c.name()).collect::<Vec<_>>(), vec!["apple", "mango", "zebra"]);
        }

        #[test]
        fn a_union_of_real_types_cannot_be_a_typed_column() {
            let c = only(Schema { types: Some(vec![SchemaType::String, SchemaType::Integer]), ..Default::default() });
            assert_eq!(c.column_type, "JSON");
            assert!(c.note.as_deref().unwrap().contains("several types"));
        }

        #[test]
        fn null_alongside_one_type_is_just_nullability_not_a_union() {
            let c = only(Schema { types: Some(vec![SchemaType::String, SchemaType::Null]), max_length: Some(50), ..Default::default() });
            assert_eq!(c.column_type, "VARCHAR(50)", "NULL in the type list must not force JSON");
        }

        #[test]
        fn empty_and_null_schemas_produce_no_columns() {
            assert!(type_mapper::columns(None, None).unwrap().is_empty());
            assert!(columns(&Schema::default()).is_empty());
            assert!(columns(&obj(vec![])).is_empty());
        }

        #[test]
        fn ddl_quotes_the_column_name() {
            assert_eq!(only(integer("f")).ddl(), "`f` INT NULL");
        }
    }
}

// ====================================================================== MySQLValueCodecTest

mod mysql_value_codec_test {
    use super::*;
    use appdata::mysql::value_codec::{decode, encode, Columns};
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};

    fn set(names: &[&str]) -> Columns {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn json() -> Columns {
        set(&["address", "tags"])
    }

    fn none() -> Columns {
        Columns::new()
    }

    fn row(address: Value) -> Document {
        let mut m = Document::new();
        m.insert("_id".into(), Value::from("01HZZZZZZZZZZZZZZZZZZZZZZZ"));
        m.insert("name".into(), Value::from("Asha"));
        m.insert("address".into(), address);
        m
    }

    fn one(key: &str, value: Value) -> Document {
        let mut m = Document::new();
        m.insert(key.into(), value);
        m
    }

    /// `encode(row, jsonColumns)`.
    fn enc(row: &Document) -> Document {
        encode(row, &json(), &none(), &none())
    }

    /// `decode(row, jsonColumns)`.
    fn dec(row: Document, json: &Columns) -> Document {
        decode(row, json, &none(), &none(), &none())
    }

    mod encoding {
        use super::*;

        #[test]
        fn map_is_serialised() {
            let encoded = enc(&row(v(r#"{"city":"Pune"}"#)));
            assert!(encoded["address"].as_str().unwrap().contains("\"city\""), "{encoded:?}");
        }

        #[test]
        fn list_is_serialised() {
            assert_eq!(enc(&one("tags", v(r#"["a","b"]"#)))["tags"], Value::from(r#"["a","b"]"#));
        }

        #[test]
        fn scalars_untouched() {
            let encoded = enc(&row(v(r#"{"city":"Pune"}"#)));
            assert_eq!(encoded["name"], Value::from("Asha"));
            assert!(encoded["_id"].as_str().is_some());
        }

        #[test]
        fn null_stays_null() {
            assert_eq!(enc(&row(Value::Null))["address"], Value::Null);
        }

        #[test]
        fn already_json() {
            assert_eq!(enc(&row(Value::from(r#"{"city":"Pune"}"#)))["address"], Value::from(r#"{"city":"Pune"}"#));
        }

        #[test]
        fn plain_string_is_quoted() {
            assert_eq!(enc(&row(Value::from("Pune")))["address"], Value::from("\"Pune\""));
        }

        #[test]
        fn almost_json() {
            assert_eq!(enc(&row(Value::from("{not json")))["address"], Value::from("\"{not json\""));
        }
    }

    mod decoding {
        use super::*;

        #[test]
        fn object_round_trips() {
            let decoded = dec(row(Value::from(r#"{"city":"Pune","pin":"411001"}"#)), &json());
            assert_eq!(decoded["address"].as_object().unwrap()["city"], Value::from("Pune"));
        }

        #[test]
        fn array_round_trips() {
            assert_eq!(dec(one("tags", Value::from(r#"["a","b"]"#)), &json())["tags"], v(r#"["a","b"]"#));
        }

        #[test]
        fn numbers_keep_their_type() {
            let floor = dec(one("address", Value::from(r#"{"floor":3}"#)), &json())["address"].as_object().unwrap()["floor"].clone();
            assert_eq!(floor, Value::Int(3));
        }

        #[test]
        fn corrupt_stays() {
            assert_eq!(dec(one("address", Value::from("not json at all")), &json())["address"], Value::from("not json at all"));
        }

        #[test]
        fn blank_is_null() {
            assert_eq!(dec(one("address", Value::from("  ")), &json())["address"], Value::Null);
        }

        #[test]
        fn no_json_columns() {
            let m = row(Value::from(r#"{"city":"Pune"}"#));
            assert_eq!(dec(m.clone(), &none()), m);
        }
    }

    mod dates {
        use super::*;

        fn dates() -> Columns {
            set(&["placedAt"])
        }

        fn dated(value: Value) -> Document {
            one("placedAt", value)
        }

        fn ten_am() -> NaiveDateTime {
            NaiveDate::from_ymd_opt(2026, 1, 15).unwrap().and_hms_opt(10, 0, 0).unwrap()
        }

        fn read(value: Value, dates: &Columns) -> Value {
            decode(dated(value), &none(), dates, &none(), &none())["placedAt"].clone()
        }

        fn write(s: &str, dates: &Columns) -> Value {
            encode(&dated(Value::from(s)), &none(), dates, &none())["placedAt"].clone()
        }

        /// A `java.sql.Timestamp` in Java; sqlx hands a DATETIME back as a NaiveDateTime.
        #[test]
        fn timestamp_to_iso() {
            assert_eq!(read(Value::LocalDateTime(ten_am()), &dates()), Value::from("2026-01-15T10:00:00"));
        }

        #[test]
        fn local_date_time_to_iso() {
            assert_eq!(read(Value::LocalDateTime(ten_am()), &dates()), Value::from("2026-01-15T10:00:00"));
        }

        #[test]
        fn date_only() {
            assert_eq!(read(Value::LocalDate(NaiveDate::from_ymd_opt(2026, 1, 15).unwrap()), &dates()), Value::from("2026-01-15"));
        }

        #[test]
        fn time_only() {
            assert_eq!(read(Value::LocalTime(NaiveTime::from_hms_opt(10, 30, 0).unwrap()), &dates()), Value::from("10:30:00"));
        }

        #[test]
        fn null_stays() {
            assert_eq!(read(Value::Null, &dates()), Value::Null);
        }

        #[test]
        fn offset_to_utc() {
            assert_eq!(write("2026-01-15T10:00:00+05:30", &dates()), Value::from("2026-01-15T04:30:00"));
            assert_eq!(write("2026-01-15T10:00:00.123Z", &dates()), Value::from("2026-01-15T10:00:00.123"));
            assert_eq!(write("2026-01-15T05:00:00+05:30", &dates()), Value::from("2026-01-14T23:30:00"), "the date moves with the instant");
        }

        #[test]
        fn time_offset_to_utc() {
            assert_eq!(write("10:00:00+05:30", &dates()), Value::from("04:30:00"));
        }

        #[test]
        fn no_offset_untouched() {
            assert_eq!(write("2026-01-15T10:00:00", &dates()), Value::from("2026-01-15T10:00:00"));
            assert_eq!(write("2026-01-15", &dates()), Value::from("2026-01-15"));
        }

        #[test]
        fn unparseable_untouched() {
            assert_eq!(write("9:00+05:30", &dates()), Value::from("9:00+05:30"));
        }

        #[test]
        fn offset_outside_dates_untouched() {
            assert_eq!(write("2026-01-15T10:00:00+05:30", &none()), Value::from("2026-01-15T10:00:00+05:30"));
        }

        #[test]
        fn untouched() {
            let ts = Value::LocalDateTime(ten_am());
            assert_eq!(read(ts.clone(), &none()), ts);
        }

        /// Gson renders a Timestamp as locale text; a NaiveDateTime left alone leaves the
        /// service as Jackson writes a LocalDateTime (epoch seconds). Neither is the ISO text.
        #[test]
        fn why_this_exists() {
            let rendered = Value::LocalDateTime(ten_am()).to_java_json();
            assert!(!rendered.contains("2026-01-15T10:00:00"), "{rendered}");
        }
    }

    #[test]
    fn round_trip() {
        let original = v(r#"{"city":"Pune","floor":3,"lines":["a","b"]}"#);
        let written = enc(&row(original.clone()));
        let read_back = dec(written, &json());
        assert_eq!(read_back["address"], original);
    }
}

// ====================================================================== MySQLAppDataServiceNamingTest

mod mysql_app_data_service_naming_test {
    use appdata::engine::{AppDataEngine, DRAFT_DB_SUFFIX};
    use appdata::mysql::service::{client_code_of, database_name, is_draft};
    use appdata::mysql::MySqlAppDataService;

    fn name(client: &str, app: &str, draft: bool) -> String {
        database_name(client, app, draft).unwrap()
    }

    /// Java checks by reflection that every interface method is implemented; here the
    /// compiler does, as long as the service implements the trait at all.
    #[test]
    fn no_method_left_behind() {
        fn implements<E: AppDataEngine>() {}
        implements::<MySqlAppDataService>();
    }

    #[test]
    fn live_name() {
        assert_eq!(name("LZCLA", "leadzump", false), "LZCLA_leadzump");
    }

    #[test]
    fn draft_name() {
        assert_eq!(name("LZCLA", "leadzump", true), format!("LZCLA_leadzump{DRAFT_DB_SUFFIX}"));
    }

    #[test]
    fn client_code_from_database() {
        assert_eq!(client_code_of("LZCLA_leadzump", "leadzump"), "LZCLA");
        assert_eq!(client_code_of("LZCLA_leadzump_draft", "leadzump"), "LZCLA");
        assert_eq!(client_code_of("SYSTEM_kyc", "kyc"), "SYSTEM");
    }

    #[test]
    fn client_code_round_trip() {
        for draft in [false, true] {
            let db = name("LZCLA", "leadzump", draft);
            assert_eq!(client_code_of(&db, "leadzump"), "LZCLA");
            assert_eq!(is_draft(&db), draft);
        }
    }

    #[test]
    fn awkward_client_code() {
        assert_eq!(client_code_of("kyc_team_kyc", "kyc"), "kyc_team");
    }

    #[test]
    fn suffix_is_the_shared_constant() {
        assert!(name("C", "a", true).ends_with(DRAFT_DB_SUFFIX));
        assert_eq!(DRAFT_DB_SUFFIX, "_draft");
    }

    #[test]
    fn surfaces_are_distinct() {
        assert_ne!(name("C", "app", false), name("C", "app", true));
    }

    #[test]
    fn tenants_are_isolated_by_name() {
        assert_ne!(name("CLIENTA", "app", false), name("CLIENTB", "app", false));
    }

    #[test]
    fn apps_are_isolated_by_name() {
        assert_ne!(name("C", "appone", false), name("C", "apptwo", false));
    }

    /// Java's IllegalArgumentException is a 500 here too.
    #[test]
    fn hostile_tenant_name() {
        let e = database_name("a` ; DROP DATABASE x; --", "testapp", false).unwrap_err();
        assert_eq!(e.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(e.message().contains("not a usable tenant schema name"), "{}", e.message());
        assert_eq!(name("SYSTEM", "testapp", false), "SYSTEM_testapp");
        assert_eq!(name("SYSTEM", "testapp", true), "SYSTEM_testapp_draft");
    }
}

// ====================================================================== MySQLDefaultConnectionTest

mod mysql_default_connection_test {
    use super::*;
    use appdata::model::Connection;
    use appdata::mysql::db::{credentials, Credentials};

    const DEF_URL: &str = "r2dbc:mysql://platform-host:3306/core";
    const DEF_USER: &str = "platform";
    const DEF_PASS: &str = "platform-pw";

    fn resolve(details: Option<&str>) -> Credentials {
        let default = Credentials {
            url: Some(DEF_URL.into()),
            username: Some(DEF_USER.into()),
            password: Some(DEF_PASS.into()),
            from_default: false,
        };
        let conn = Connection { id: "c".into(), connection_details: details.map(doc), ..Default::default() };
        credentials(&conn, &default)
    }

    #[test]
    fn takes_the_platform_datasource() {
        let c = resolve(Some(r#"{"useDefaultConnection":true}"#));
        assert_eq!(c.url.as_deref(), Some(DEF_URL));
        assert_eq!(c.username.as_deref(), Some(DEF_USER));
        assert_eq!(c.password.as_deref(), Some(DEF_PASS));
        assert!(c.from_default);
    }

    #[test]
    fn explicit_details_win() {
        let c = resolve(Some(r#"{"url":"r2dbc:mysql://other:3306/","username":"u","password":"p"}"#));
        assert_eq!(c.url.as_deref(), Some("r2dbc:mysql://other:3306/"));
        assert_eq!(c.username.as_deref(), Some("u"));
        assert!(!c.from_default);
    }

    #[test]
    fn default_is_all_or_nothing() {
        let c = resolve(Some(
            r#"{"useDefaultConnection":true,"url":"r2dbc:mysql://stale:3306/","username":"stale","password":"stale-pw"}"#,
        ));
        assert_eq!(c.url.as_deref(), Some(DEF_URL));
        assert_eq!(c.username.as_deref(), Some(DEF_USER));
        assert_eq!(c.password.as_deref(), Some(DEF_PASS));
    }

    #[test]
    fn flag_off_is_unchanged() {
        let c = resolve(Some(r#"{"useDefaultConnection":false,"url":"r2dbc:mysql://mine:3306/"}"#));
        assert_eq!(c.url.as_deref(), Some("r2dbc:mysql://mine:3306/"));
        assert!(!c.from_default);
    }

    #[test]
    fn blank_stays_blank() {
        assert!(resolve(Some("{}")).url.is_none());
        assert!(resolve(None).url.is_none());
        assert!(resolve(Some(r#"{"url":"   "}"#)).url.is_none());
        assert!(!resolve(None).from_default);
    }

    #[test]
    fn accepts_either_json_shape() {
        assert!(resolve(Some(r#"{"useDefaultConnection":true}"#)).from_default);
        assert!(resolve(Some(r#"{"useDefaultConnection":"true"}"#)).from_default);
        assert!(!resolve(Some(r#"{"useDefaultConnection":"false"}"#)).from_default);
        assert!(!resolve(Some(r#"{"useDefaultConnection":null}"#)).from_default);
    }
}

// ====================================================================== MySQLNullAndBooleanTest

mod mysql_null_and_boolean_test {
    use super::*;
    use appdata::model::{AggregateQuery, GroupByField, MySqlColumnDefinition, MySqlColumnType, Storage, StorageColumnDefinition};
    use appdata::mysql::column_names::PhysicalSchema;
    use appdata::mysql::service::{boolean_aliases, merged, nulls_on_required, physical_of, update_values, Decoding};
    use appdata::mysql::sql::Bind;
    use appdata::mysql::value_codec::{self, Columns};
    use appdata::value::Decimal;
    use indexmap::IndexMap;
    use std::collections::BTreeSet;

    fn schema() -> PhysicalSchema {
        let s = object(vec![
            ("name", string_len("name", 100)),
            ("description", string_len("description", 200)),
            ("active", boolean("active")),
            ("optIn", Schema { name: Some("optIn".into()), types: Some(vec![SchemaType::Boolean, SchemaType::Null]), ..Default::default() }),
            ("count", integer("count")),
            ("IFSC Flag", boolean("IFSC Flag")),
        ]);
        physical_of(Schema { required: Some(vec!["name".into()]), ..s })
    }

    fn storage() -> Storage {
        Storage {
            name: "project".into(),
            app_code: "leadzumptwo".into(),
            client_code: "SYSTEM".into(),
            version: 1,
            unique_name: "project_t".into(),
            ..Default::default()
        }
    }

    fn by_name(values: Vec<(String, Bind)>) -> IndexMap<String, Bind> {
        values.into_iter().collect()
    }

    fn set(names: &[&str]) -> Columns {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn sorted<I: IntoIterator<Item = String>>(names: I) -> BTreeSet<String> {
        names.into_iter().collect()
    }

    fn expected(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    mod update_values {
        use super::*;

        #[test]
        fn patch_null() {
            let set = by_name(update_values(&storage(), &schema(), &doc(r#"{"_id":"426","description":null}"#), Some(false)).unwrap());
            assert_eq!(set.len(), 1, "{set:?}");
            assert_eq!(set.get("description"), Some(&Bind::Null));
        }

        #[test]
        fn put_replaces() {
            let set = by_name(
                update_values(&storage(), &schema(), &doc(r#"{"_id":"426","name":"Tower A","active":true}"#), Some(true)).unwrap(),
            );
            assert_eq!(set.get("name"), Some(&Bind::Text("Tower A".into())));
            assert_eq!(set.get("active"), Some(&Bind::Bool(true)));
            for cleared in ["description", "optIn", "count", "IFSC_Flag"] {
                assert_eq!(set.get(cleared), Some(&Bind::Null), "{cleared} not cleared: {set:?}");
            }
            assert!(!set.contains_key("_id"), "the id is never in SET");
        }

        #[test]
        fn null_override_merges() {
            let set = by_name(update_values(&storage(), &schema(), &doc(r#"{"_id":"426","name":"Tower A"}"#), None).unwrap());
            assert_eq!(set.into_iter().collect::<Vec<_>>(), vec![("name".to_string(), Bind::Text("Tower A".into()))]);
        }
    }

    mod merged {
        use super::*;

        #[test]
        fn merged() {
            let out = super::merged(
                &doc(r#"{"_id":"426","name":"Tower A","description":"unlink-test","active":true,"count":null}"#),
                &doc(r#"{"_id":"426","description":null,"active":false}"#),
            );
            assert_eq!(out, doc(r#"{"name":"Tower A","active":false}"#));
        }
    }

    mod required_nulls {
        use super::*;

        #[test]
        fn named() {
            assert_eq!(nulls_on_required(&schema(), &doc(r#"{"name":null,"description":null}"#)).unwrap(), vec!["name"]);
        }

        #[test]
        fn optional() {
            assert!(nulls_on_required(&schema(), &doc(r#"{"description":null,"name":"x"}"#)).unwrap().is_empty());
        }
    }

    mod booleans {
        use super::*;

        #[test]
        fn columns() {
            assert_eq!(
                sorted(type_mapper::boolean_columns(schema().schema(), None).unwrap()),
                expected(&["active", "optIn", "IFSC_Flag"])
            );
        }

        #[test]
        fn retyped_to_text() {
            let mut defs = IndexMap::new();
            defs.insert(
                "active".to_string(),
                StorageColumnDefinition::mysql(MySqlColumnDefinition {
                    column_type: Some(MySqlColumnType::Varchar),
                    length: Some(5),
                    ..Default::default()
                }),
            );
            assert!(!type_mapper::boolean_columns(schema().schema(), Some(&defs)).unwrap().contains("active"));
        }

        /// Java's `(byte) 1` and `0` are both an integer here.
        #[test]
        fn decoded() {
            let out = value_codec::decode(
                doc(r#"{"active":1,"optIn":0,"IFSC_Flag":null,"count":1}"#),
                &Columns::new(),
                &Columns::new(),
                &Columns::new(),
                &set(&["active", "optIn", "IFSC_Flag"]),
            );
            assert_eq!(out["active"], Value::Bool(true));
            assert_eq!(out["optIn"], Value::Bool(false));
            assert!(out.contains_key("IFSC_Flag"));
            assert_eq!(out["IFSC_Flag"], Value::Null);
            assert_eq!(out["count"], Value::Int(1));
        }

        /// Long and short are both `Value::Int`. The `byte[]` case has no counterpart: no
        /// value here is a byte array (a binary column reads as text or base64).
        #[test]
        fn shapes() {
            assert_eq!(value_codec::bool_of(Value::Int(1)), Value::Bool(true));
            assert_eq!(value_codec::bool_of(Value::Int(0)), Value::Bool(false));
            assert_eq!(value_codec::bool_of(Value::Decimal(Decimal::from_i64(1))), Value::Bool(true));
            assert_eq!(value_codec::bool_of(Value::Bool(false)), Value::Bool(false));
            assert_eq!(value_codec::bool_of(Value::Null), Value::Null);
            assert_eq!(value_codec::bool_of(Value::from("yes")), Value::from("yes"));
        }

        #[test]
        fn decoding_row() {
            let physical = schema();
            let decoding = Decoding::of(&physical, None).unwrap();
            let row = decoding.row(doc(r#"{"_id":"426","IFSC_Flag":1,"active":0}"#), &physical);
            assert_eq!(row["IFSC Flag"], Value::Bool(true));
            assert_eq!(row["active"], Value::Bool(false));
            assert_eq!(sorted(decoding.boolean_fields(&physical)), expected(&["active", "optIn", "IFSC Flag"]));
        }

        #[test]
        fn snapshot() {
            let out = value_codec::booleans(doc(r#"{"active":1,"count":0}"#), &set(&["active", "optIn"]));
            assert_eq!(out["active"], Value::Bool(true));
            assert_eq!(out["count"], Value::Int(0));
            assert!(!out.contains_key("optIn"), "an absent field is not invented");
        }

        #[test]
        fn aggregate_groups() {
            let q = AggregateQuery { group_by: Some(vec![GroupByField::new("active"), GroupByField::new("count")]), ..Default::default() };
            assert_eq!(sorted(boolean_aliases(&q, &set(&["active", "optIn"]))), expected(&["active"]));
        }
    }
}

// ====================================================================== MySQLReadNotFoundTest

mod mysql_read_not_found_test {
    use appdata::error::ErrorKind;
    use appdata::AppDataError;

    /// Java's `objectNotFound(storage, id)`; the Rust `read` raises this constructor's error
    /// for a row that is not there. The read itself needs a database.
    #[test]
    fn missing_row_is_storage_object_not_found() {
        let e = AppDataError::object_not_found("orders", "42");
        assert_eq!(e.kind(), ErrorKind::ObjectNotFound);
        assert!(e.is_object_not_found());
        assert_eq!(e.status(), http::StatusCode::NOT_FOUND);
    }
}

// ====================================================================== MySQLReadPageShapingTest

mod mysql_read_page_shaping_test {
    use super::*;
    use appdata::model::{Order, Query, Sort};
    use appdata::mysql::column_names::PhysicalSchema;
    use appdata::mysql::service::{order_plain, physical_of, projection};
    use appdata::mysql::sql::Sql;

    fn storage() -> PhysicalSchema {
        physical_of(object(vec![("region", string_len("region", 20)), ("amount", double("amount")), ("notes", string_len("notes", 100))]))
    }

    fn with_nested() -> PhysicalSchema {
        physical_of(object(vec![("region", string_len("region", 20)), ("address", object(vec![("city", string_len("city", 40))]))]))
    }

    fn rendered(fields: Vec<Sql>) -> Vec<String> {
        fields.iter().map(|f| f.render().0).collect()
    }

    /// `MySQLAppDataService.order(schema, sort)`.
    fn order(schema: &PhysicalSchema, orders: Vec<Order>) -> Vec<String> {
        rendered(order_plain(schema, &Sort::by(orders)).unwrap())
    }

    fn fields(fields: &[&str], exclude: bool) -> Query {
        Query { fields: Some(fields.iter().map(|f| f.to_string()).collect()), exclude_fields: Some(exclude), ..Default::default() }
    }

    mod json_path_ordering {
        use super::*;

        #[test]
        fn json_path_sorts() {
            let out = order(&with_nested(), vec![Order::asc("address.city")]);
            assert_eq!(out.len(), 1, "{out:?}");
            assert!(out[0].contains("json_"), "{}", out[0]);
        }

        #[test]
        fn not_a_qualified_column() {
            let out = order(&with_nested(), vec![Order::desc("address.city")]);
            assert!(!out[0].contains("`address`.`city`"), "{}", out[0]);
            assert!(out[0].contains("desc"), "{}", out[0]);
        }

        #[test]
        fn unknown_head_still_dropped() {
            assert!(order(&with_nested(), vec![Order::asc("nosuch.city")]).is_empty());
            assert!(order(&with_nested(), vec![Order::asc("region.")]).is_empty());
        }

        #[test]
        fn plain_column_unchanged() {
            assert_eq!(order(&with_nested(), vec![Order::asc("region")]), vec!["`region` asc"]);
        }
    }

    mod projection {
        use super::*;

        #[test]
        fn empty_means_all() {
            assert!(projection(&storage(), &Query::default()).unwrap().is_empty());
            assert!(projection(&storage(), &fields(&[], false)).unwrap().is_empty());
        }

        #[test]
        fn include_always_keeps_the_id() {
            assert_eq!(rendered(projection(&storage(), &fields(&["region"], false)).unwrap()), vec!["`_id`", "`region`"]);
        }

        #[test]
        fn id_is_not_duplicated() {
            assert_eq!(rendered(projection(&storage(), &fields(&["_id", "region"], false)).unwrap()), vec!["`_id`", "`region`"]);
        }

        #[test]
        fn exclude_inverts_against_the_schema() {
            assert_eq!(
                rendered(projection(&storage(), &fields(&["notes"], true)).unwrap()),
                vec!["`_id`", "`amount`", "`region`"]
            );
        }

        #[test]
        fn excluding_everything_leaves_the_id() {
            assert_eq!(rendered(projection(&storage(), &fields(&["region", "amount", "notes"], true)).unwrap()), vec!["`_id`"]);
        }
    }

    mod ordering {
        use super::*;

        #[test]
        fn default_sort_on_a_missing_column_is_dropped() {
            assert!(order_plain(&storage(), &Sort::default_query_sort()).unwrap().is_empty());
        }

        #[test]
        fn sorts_on_a_declared_column() {
            assert_eq!(order(&storage(), vec![Order::desc("amount")]), vec!["`amount` desc"]);
        }

        #[test]
        fn ascending_is_the_default_direction() {
            assert_eq!(order(&storage(), vec![Order::asc("region")]), vec!["`region` asc"]);
        }

        #[test]
        fn id_is_sortable() {
            assert_eq!(order(&storage(), vec![Order::asc("_id")]), vec!["char_length(`_id`) asc", "`_id` asc"]);
        }

        #[test]
        fn id_sorts_by_length_first() {
            assert_eq!(
                order(&storage(), vec![Order::desc("_id"), Order::asc("region")]),
                vec!["char_length(`_id`) desc", "`_id` desc", "`region` asc"]
            );
        }

        #[test]
        fn mixed_sort_is_filtered() {
            assert_eq!(order(&storage(), vec![Order::desc("nosuch"), Order::asc("region")]), vec!["`region` asc"]);
        }

        /// The null half has no counterpart: the sort is a value, never null.
        #[test]
        fn unsorted_and_null_produce_no_order_by() {
            assert!(order_plain(&storage(), &Sort::unsorted()).unwrap().is_empty());
        }
    }
}

// ====================================================================== MySQLReceivedFieldNamesReadTest

mod mysql_received_field_names_read_test {
    use super::*;
    use appdata::model::{FilterCondition, Order, Query, Sort};
    use appdata::mysql::column_names::PhysicalSchema;
    use appdata::mysql::field_resolver::FieldResolver;
    use appdata::mysql::filter_builder;
    use appdata::mysql::service::{head, order, physical_of, projection, selected_parent_columns};
    use appdata::mysql::sql::Sql;
    use indexmap::IndexMap;

    /// Physical, as every read path in the service receives it.
    fn schema() -> PhysicalSchema {
        physical_of(object(vec![
            ("IFSC Code", string_len("IFSC Code", 20)),
            ("Virtual Account ", string_len("Virtual Account ", 40)),
            ("Amount", double("Amount")),
            ("Bank Details", Schema { types: Some(vec![SchemaType::Object]), ..Default::default() }),
            ("some_thing", string_len("some_thing", 20)),
        ]))
    }

    fn resolver() -> FieldResolver {
        FieldResolver::of(type_mapper::json_columns(schema().schema(), None).unwrap())
    }

    fn rendered(parts: Vec<Sql>) -> Vec<String> {
        parts.iter().map(|p| p.render().0).collect()
    }

    fn sorted_by(o: Order) -> Vec<String> {
        rendered(order(&schema(), &Sort::by(vec![o]), &resolver()).unwrap())
    }

    fn where_(fc: FilterCondition) -> String {
        filter_builder::build(Some(&fc.into()), &resolver()).unwrap().inlined()
    }

    mod rows {
        use super::*;

        #[test]
        fn keyed_by_field() {
            let out = schema().to_fields(doc(r#"{"_id":"01J","IFSC_Code":"HDFC0000001","Virtual_Account_":"VA-1","Amount":500.0}"#));
            assert_eq!(out.keys().cloned().collect::<Vec<_>>(), vec!["_id", "IFSC Code", "Virtual Account ", "Amount"]);
            assert_eq!(out["IFSC Code"], Value::from("HDFC0000001"));
        }

        #[test]
        fn nested_untouched() {
            let bank = v(r#"{"Branch Name":"Koregaon Park"}"#);
            let mut row = Document::new();
            row.insert("Bank_Details".into(), bank.clone());
            assert_eq!(schema().to_fields(row)["Bank Details"], bank);
        }
    }

    mod filters {
        use super::*;

        #[test]
        fn spaced_field() {
            let w = where_(FilterCondition::eq("IFSC Code", "HDFC0000001"));
            assert!(w.contains("`IFSC_Code`"), "{w}");
        }

        #[test]
        fn json_path() {
            let w = where_(FilterCondition::eq("Bank Details.city", "Pune"));
            assert!(w.contains("`Bank_Details`"), "{w}");
            assert!(w.contains("$.city"), "{w}");
        }
    }

    mod sorting {
        use super::*;

        #[test]
        fn spaced_field() {
            assert_eq!(sorted_by(Order::desc("IFSC Code")), vec!["`IFSC_Code` desc"]);
        }

        #[test]
        fn json_path() {
            let o = sorted_by(Order::asc("Bank Details.city"));
            assert_eq!(o.len(), 1, "{o:?}");
            assert!(o[0].contains("`Bank_Details`"), "{}", o[0]);
        }

        #[test]
        fn dotted_is_not_normalised() {
            assert!(sorted_by(Order::asc("some.thing")).is_empty());
        }
    }

    mod fields {
        use super::*;

        fn query(fields: &[&str], exclude: bool) -> Query {
            Query { fields: Some(fields.iter().map(|f| f.to_string()).collect()), exclude_fields: Some(exclude), ..Default::default() }
        }

        #[test]
        fn include() {
            assert_eq!(rendered(projection(&schema(), &query(&["IFSC Code", "Amount"], false)).unwrap()), vec!["`_id`", "`IFSC_Code`", "`Amount`"]);
        }

        #[test]
        fn exclude() {
            let out = rendered(projection(&schema(), &query(&["IFSC Code"], true)).unwrap());
            assert!(!out.contains(&"`IFSC_Code`".to_string()), "{out:?}");
            assert!(out.contains(&"`Virtual_Account_`".to_string()), "{out:?}");
        }

        #[test]
        fn joined() {
            let mut cols: Vec<String> = selected_parent_columns(&schema(), &query(&["IFSC Code"], false)).unwrap().into_iter().collect();
            cols.sort();
            assert_eq!(cols, vec!["IFSC_Code", "_id"]);
        }
    }

    mod aggregates {
        use super::*;

        #[test]
        fn head() {
            let mut columns = IndexMap::new();
            columns.insert("IFSC_Code".to_string(), "VARCHAR(20)".to_string());
            columns.insert("Bank_Details".to_string(), "JSON".to_string());
            columns.insert("pay.Remitter_Name".to_string(), "VARCHAR(100)".to_string());
            assert_eq!(super::head("IFSC Code", &columns), "IFSC_Code");
            assert_eq!(super::head("Bank Details.city", &columns), "Bank_Details");
            assert_eq!(super::head("pay.Remitter Name", &columns), "pay.Remitter_Name");
        }
    }
}

// ====================================================================== extra (not Java ports)

/// Not ports: the remaining branches of the planner, mapper, codec, journal, inspector,
/// connection and service helpers, each checked against what the Java code does.
mod extra {
    use super::*;

    mod migration_planner {
        use appdata::mysql::filter_builder::FilterError;
        use appdata::mysql::migration_planner::{plan, predicate, preflight, Phase};
        use appdata::mysql::table_planner::{Kind, SchemaChange};

        const DECIMAL_CHECK: &str = r"REGEXP '^[+-]?([0-9]+(\\.[0-9]*)?|\\.[0-9]+)([eE][+-]?[0-9]+)?$'";

        #[test]
        fn char_and_decimal_targets_have_checks() {
            assert_eq!(predicate("a", Some("CHAR(12)")).unwrap(), "CHAR_LENGTH(`a`) <= 12");
            assert_eq!(predicate("a", Some(" char(3) ")).unwrap(), "CHAR_LENGTH(`a`) <= 3");
            assert_eq!(predicate("a", Some("DECIMAL(10,2)")).unwrap(), format!("`a` {DECIMAL_CHECK}"));
            assert_eq!(predicate("a", Some("TINYINT(1)")).unwrap(), "`a` REGEXP '^[01]$'");
            assert_eq!(predicate("a", Some("DATETIME(3)")).unwrap(), "`a` REGEXP '^[0-9]{4}-[0-9]{2}-[0-9]{2}'");
        }

        /// Java's `^VARCHAR\((\d+)\)$` does not match these, so they fall through to the refusal.
        #[test]
        fn a_length_that_is_not_a_number_has_no_check() {
            for t in ["VARCHAR(abc)", "VARCHAR()", "CHAR(1a)"] {
                assert!(matches!(predicate("a", Some(t)), Err(FilterError::Unsupported(_))), "{t}");
            }
            let e = predicate("a", None).unwrap_err();
            assert!(e.detail().contains("for target type null"), "{}", e.detail());
        }

        #[test]
        fn a_narrowing_to_an_unchecked_type_cannot_be_planned() {
            let c = SchemaChange::new(Kind::Narrowing, "doc", Some("TEXT"), Some("BLOB"), "test");
            assert!(matches!(plan("D", "t", 2, &[c]), Err(FilterError::Unsupported(_))));
        }

        /// The exact text Java builds, step by step, so a plan journaled by either side
        /// replays on the other.
        #[test]
        fn a_narrowing_plan_is_the_java_text() {
            let c = SchemaChange::new(Kind::Narrowing, "amount", Some("VARCHAR(40)"), Some("DOUBLE"), "test");
            let p = plan("LZCLA_leadzump", "sales", 7, &[c]).unwrap();
            let q = "`LZCLA_leadzump`.`sales`";
            let cols = "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'LZCLA_leadzump' AND TABLE_NAME = 'sales'";
            let check = format!("`amount` {DECIMAL_CHECK}");
            let expected: Vec<(Phase, Option<String>, Option<String>, Option<String>)> = vec![
                (
                    Phase::Snapshot,
                    Some(format!("CREATE TABLE `LZCLA_leadzump`.`sales__bak_7` AS SELECT * FROM {q}")),
                    Some("SELECT COUNT(*) = 0 FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'LZCLA_leadzump' AND TABLE_NAME = 'sales__bak_7'".into()),
                    None,
                ),
                (Phase::Preflight, None, None, Some(format!("SELECT COUNT(*) FROM {q} WHERE `amount` IS NOT NULL AND NOT ({check})"))),
                (
                    Phase::Expand,
                    Some(format!("ALTER TABLE {q} ADD COLUMN `amount__v7` DOUBLE NULL")),
                    Some(format!("SELECT COUNT(*) = 0 {cols} AND COLUMN_NAME = 'amount__v7'")),
                    None,
                ),
                (
                    Phase::Backfill,
                    Some(format!("UPDATE {q} SET `amount__v7` = `amount` WHERE `amount` IS NOT NULL AND ({check})")),
                    Some(format!("SELECT COUNT(*) {cols} AND COLUMN_NAME = 'amount__v7'")),
                    None,
                ),
                (Phase::Verify, None, None, Some(format!("SELECT COUNT(*) FROM {q} WHERE `amount` IS NOT NULL AND `amount__v7` IS NULL"))),
                (
                    Phase::Contract,
                    Some(format!("ALTER TABLE {q} DROP COLUMN `amount`")),
                    Some(format!("SELECT COUNT(*) {cols} AND COLUMN_NAME = 'amount'")),
                    None,
                ),
                (
                    Phase::Contract,
                    Some(format!("ALTER TABLE {q} CHANGE COLUMN `amount__v7` `amount` DOUBLE")),
                    Some(format!("SELECT COUNT(*) {cols} AND COLUMN_NAME = 'amount__v7'")),
                    None,
                ),
            ];
            let got: Vec<_> = p.iter().map(|s| (s.phase, s.sql.clone(), s.precondition.clone(), s.data_check.clone())).collect();
            assert_eq!(got, expected);
            assert!(p[0].describes.is_none() && p[1..].iter().all(|s| s.describes.is_some()));
            assert_eq!(p.iter().map(|s| s.destructive).collect::<Vec<_>>(), vec![false, false, false, false, false, true, true]);
            assert_eq!(preflight("D", "t", "x", Some("TEXT")).unwrap(), "SELECT COUNT(*) FROM `D`.`t` WHERE `x` IS NOT NULL AND NOT (1 = 1)");
        }

        /// A declared collation rides on every statement that (re)defines the column.
        #[test]
        fn a_collation_is_carried_into_the_ddl() {
            let mut add = SchemaChange::new(Kind::Widening, "code", None, Some("VARCHAR(10)"), "test");
            add.collation = Some("utf8mb4_bin".into());
            let p = plan("D", "t", 3, &[add.clone()]).unwrap();
            assert_eq!(p[0].sql.as_deref(), Some("ALTER TABLE `D`.`t` ADD COLUMN `code` VARCHAR(10) COLLATE utf8mb4_bin NULL"));
            let mut narrow = SchemaChange::new(Kind::Narrowing, "code", None, Some("VARCHAR(10)"), "test");
            narrow.collation = add.collation.clone();
            let p = plan("D", "t", 3, &[narrow]).unwrap();
            assert_eq!(p[2].sql.as_deref(), Some("ALTER TABLE `D`.`t` ADD COLUMN `code` VARCHAR(10) COLLATE utf8mb4_bin NOT NULL"));
            assert_eq!(p[1].data_check.as_deref(), Some("SELECT COUNT(*) FROM `D`.`t`"));
        }
    }

    mod table_planner {
        use super::*;
        use appdata::mysql::table_planner::{diff, is_safe_widening, shape_of, Kind};
        use sha2::{Digest, Sha256};

        fn java_shape(text: &str) -> String {
            hex::encode(&Sha256::digest(text.as_bytes())[..16])
        }

        fn collated(name: &str, t: &str, collation: &str) -> MySqlColumn {
            col(name, t).with_collation(Some(collation.into()))
        }

        /// `shapeOf`: the SHA-256 of `name TYPE NULL [COLLATE C]` lines sorted by name, so
        /// a journal row written by Java is found by Rust.
        #[test]
        fn the_shape_is_the_java_digest() {
            assert_eq!(shape_of(&[]), java_shape(""));
            assert_eq!(
                shape_of(&[col("name", "varchar(60)"), not_null("age", "INT")]),
                java_shape("age INT NOT NULL\nname VARCHAR(60) NULL\n")
            );
            assert_eq!(
                shape_of(&[collated("code", "VARCHAR(10)", "utf8mb4_bin")]),
                java_shape("code VARCHAR(10) NULL COLLATE UTF8MB4_BIN\n")
            );
            assert_eq!(shape_of(&[collated("code", "VARCHAR(10)", "utf8mb4_bin")]), shape_of(&[collated("code", "VARCHAR(10)", "UTF8MB4_BIN")]));
            assert_ne!(shape_of(&[collated("code", "VARCHAR(10)", "utf8mb4_bin")]), shape_of(&[col("code", "VARCHAR(10)")]));
        }

        /// Asymmetric, as in Java: only a declared collation on the desired side counts.
        #[test]
        fn a_collation_change_is_a_widening() {
            let cs = diff(&[col("code", "VARCHAR(10)")], &[collated("code", "VARCHAR(10)", "utf8mb4_bin")]);
            assert_eq!(cs.len(), 1);
            assert_eq!(cs[0].kind, Kind::Widening);
            assert_eq!(cs[0].reason, "collation change to utf8mb4_bin");
            assert_eq!(cs[0].collation.as_deref(), Some("utf8mb4_bin"));
            assert!(diff(&[collated("code", "VARCHAR(10)", "UTF8MB4_BIN")], &[collated("code", "VARCHAR(10)", "utf8mb4_bin")]).is_empty());
            assert!(diff(&[collated("code", "VARCHAR(10)", "utf8mb4_bin")], &[col("code", "VARCHAR(10)")]).is_empty());
            let cs = diff(&[], &[collated("code", "VARCHAR(10)", "utf8mb4_bin")]);
            assert_eq!(cs[0].collation.as_deref(), Some("utf8mb4_bin"));
        }

        #[test]
        fn safe_widenings() {
            assert!(is_safe_widening("int", "INT"));
            assert!(is_safe_widening("INT", "DOUBLE"));
            assert!(is_safe_widening("TINYINT(1)", "BIGINT"));
            assert!(!is_safe_widening("BIGINT", "TINYINT(1)"));
            assert!(is_safe_widening("FLOAT", "double"));
            assert!(!is_safe_widening("DOUBLE", "FLOAT"));
            assert!(!is_safe_widening("VARCHAR(abc)", "TEXT"));
            assert!(!is_safe_widening("VARCHAR()", "VARCHAR(10)"));
            let cs = diff(&[col("n", "INT")], &[col("n", "DOUBLE")]);
            assert_eq!((cs[0].kind, cs[0].reason.as_str()), (Kind::Widening, "widening type change"));
            let cs = diff(&[not_null("n", "INT")], &[col("n", "INT")]);
            assert_eq!(cs[0].reason, "now nullable");
        }
    }

    mod type_mapper_edges {
        use super::*;
        use appdata::mysql::type_mapper::column;

        #[test]
        fn a_field_with_no_type_and_no_shape_is_json() {
            let c = column("f", Some(&Schema::default()), true, None).unwrap();
            assert_eq!(c.column_type, "JSON");
            assert_eq!(c.note.as_deref(), Some("no declared type, stored as JSON. Declare a type to get a real column."));
            let c = column("f", None, true, None).unwrap();
            assert_eq!((c.column_type.as_str(), c.note.as_deref()), ("JSON", Some("no schema for this field")));
            let c = column("f", Some(&Schema { types: Some(vec![SchemaType::Null]), ..Default::default() }), true, None).unwrap();
            assert_eq!(c.note.as_deref(), Some("declares only NULL"));
        }

        #[test]
        fn untyped_shapes_say_what_they_were_taken_for() {
            let props = Schema { properties: Some([("city".to_string(), Schema::of_string("city"))].into_iter().collect()), ..Default::default() };
            assert_eq!(
                column("a", Some(&props), true, None).unwrap().note.as_deref(),
                Some("no declared type but it has properties, so it is treated as a nested object (1 field(s)), stored whole as JSON: readable and filterable by path, but not joinable or indexable. Lift a field to the top level to join on it.")
            );
            let items = Schema { items: Some(Items::Tuple(vec![])), ..Default::default() };
            assert_eq!(
                column("a", Some(&items), true, None).unwrap().note.as_deref(),
                Some("no declared type but it has items, so it is treated as an array")
            );
            let blank_ref = Schema { reference: Some("  ".into()), types: Some(vec![SchemaType::Integer]), ..Default::default() };
            assert_eq!(column("a", Some(&blank_ref), true, None).unwrap().column_type, "INT");
            let union = column("a", Some(&Schema { types: Some(vec![SchemaType::String, SchemaType::Integer]), ..Default::default() }), true, None);
            assert_eq!(union.unwrap().note.as_deref(), Some("declares several types [STRING, INTEGER], so it cannot be a typed column"));
        }
    }

    mod value_codec_edges {
        use super::*;
        use appdata::mysql::value_codec::{bool_of, booleans, decode, encode, exact, iso_text, utc_text, Columns};
        use appdata::value::Decimal;

        fn set(names: &[&str]) -> Columns {
            names.iter().map(|s| s.to_string()).collect()
        }

        /// `exact`: a number through its own text, a decimal string parsed, anything else
        /// passed on for MySQL to refuse.
        #[test]
        fn exact_decimals() {
            assert_eq!(exact(&Value::Null), Value::Null);
            let d = Value::Decimal(Decimal::parse("1.50").unwrap());
            assert_eq!(exact(&d), d);
            assert_eq!(exact(&Value::Int(3)), Value::Decimal(Decimal::parse("3").unwrap()));
            assert_eq!(exact(&Value::from(" 2.25 ")), Value::Decimal(Decimal::parse("2.25").unwrap()));
            assert_eq!(exact(&Value::from("abc")), Value::from("abc"));
            assert_eq!(exact(&Value::Bool(true)), Value::Bool(true));
            let mut row = Document::new();
            row.insert("price".into(), Value::Int(7));
            assert_eq!(encode(&row, &Columns::new(), &Columns::new(), &set(&["price"]))["price"], Value::Decimal(Decimal::from_i64(7)));
        }

        #[test]
        fn offsets_that_do_not_parse_are_left_alone() {
            assert_eq!(utc_text(&Value::from("2026-13-45T10:00:00Z")), Value::from("2026-13-45T10:00:00Z"));
            assert_eq!(utc_text(&Value::from("10:00")), Value::from("10:00"));
            assert_eq!(utc_text(&Value::from("Z")), Value::from("Z"));
            assert_eq!(utc_text(&Value::Int(5)), Value::Int(5));
            assert_eq!(utc_text(&Value::from("10:00:00Z")), Value::from("10:00:00"));
        }

        /// `n.longValue() != 0`: a fraction truncates first.
        #[test]
        fn every_number_reads_as_a_boolean() {
            assert_eq!(bool_of(Value::Decimal(Decimal::zero())), Value::Bool(false));
            assert_eq!(bool_of(Value::Decimal(Decimal::parse("-2").unwrap())), Value::Bool(true));
            assert_eq!(bool_of(Value::Double(1.0)), Value::Bool(true));
            assert_eq!(bool_of(Value::Double(0.5)), Value::Bool(false));
            let row = doc(r#"{"active":1}"#);
            assert_eq!(booleans(row.clone(), &Columns::new()), row);
        }

        /// A `java.util.Date` reads as its UTC wall time.
        #[test]
        fn a_date_reads_as_utc_text() {
            assert_eq!(iso_text(Value::Date(1_768_471_200_000)), Value::from("2026-01-15T10:00:00"));
            assert_eq!(iso_text(Value::Date(i64::MAX)), Value::Date(i64::MAX));
            assert_eq!(iso_text(Value::Int(1)), Value::Int(1));
            let mut row = Document::new();
            row.insert("at".into(), Value::Date(1_768_471_200_123));
            assert_eq!(decode(row, &Columns::new(), &set(&["at"]), &Columns::new(), &Columns::new())["at"], Value::from("2026-01-15T10:00:00.123"));
        }
    }

    mod inspector_and_journal {
        use appdata::mysql::inspector::is_migration_temp;
        use appdata::mysql::journal::{escape, JournalEntry, MigrationState};

        #[test]
        fn migration_temp_columns() {
            assert!(is_migration_temp("amount__v7"));
            assert!(is_migration_temp("a__v1__v12"));
            assert!(!is_migration_temp("amount__v"));
            assert!(!is_migration_temp("amount__v7b"));
            assert!(!is_migration_temp("amount"));
        }

        const ALL: [MigrationState; 6] = [
            MigrationState::Planned,
            MigrationState::Running,
            MigrationState::Applied,
            MigrationState::Failed,
            MigrationState::NeedsAttention,
            MigrationState::Abandoned,
        ];

        #[test]
        fn states_round_trip_by_their_java_names() {
            let names: Vec<&str> = ALL.iter().map(|s| s.name()).collect();
            assert_eq!(names, vec!["PLANNED", "RUNNING", "APPLIED", "FAILED", "NEEDS_ATTENTION", "ABANDONED"]);
            for s in ALL {
                assert_eq!(MigrationState::from_name(s.name()), Some(s));
            }
            assert_eq!(MigrationState::from_name("applied"), None);
        }

        /// Only APPLIED is complete; only FAILED and RUNNING resume (NEEDS_ATTENTION waits
        /// for a human, ABANDONED is written off).
        #[test]
        fn complete_and_resumable() {
            for s in ALL {
                let e = JournalEntry { id: "x".into(), state: s, statement_index: 0, attempt: 1, applied_count: 0, total: 3 };
                assert_eq!(e.is_complete(), s == MigrationState::Applied, "{s:?}");
                assert_eq!(e.is_resumable(), matches!(s, MigrationState::Failed | MigrationState::Running), "{s:?}");
            }
            assert_eq!(escape(r"it's a\b"), r"it''s a\\b");
        }
    }

    mod db {
        use super::*;
        use appdata::model::Connection;
        use appdata::mysql::db::{connect_options, credentials, first_number, is_integrity_violation, message, sql_state, truthy, Credentials};
        use appdata::AppDataError;

        fn creds(url: Option<&str>) -> Credentials {
            Credentials { url: url.map(str::to_string), username: None, password: None, from_default: false }
        }

        /// `BooleanUtil.safeValueOf`.
        #[test]
        fn truthy_is_safe_value_of() {
            for t in ["yes", "Y", "TRUE", "t", "On", "1", "-3", "+2"] {
                assert!(truthy(Some(&Value::from(t))), "{t}");
            }
            for f in ["no", "0", " ", "", " 1", "1.0", "abc", "3000000000"] {
                assert!(!truthy(Some(&Value::from(f))), "{f:?}");
            }
            assert!(truthy(Some(&Value::Int(2))));
            assert!(!truthy(Some(&Value::Int(0))));
            assert!(!truthy(Some(&Value::Double(1.0))));
            assert!(!truthy(Some(&Value::Null)));
            assert!(!truthy(None));
        }

        #[test]
        fn details_that_are_not_text_are_read_as_their_text() {
            let conn = Connection { id: "c".into(), connection_details: Some(doc(r#"{"url":"r2dbc:mysql://h/db","username":7}"#)), ..Default::default() };
            let c = credentials(&conn, &creds(None));
            assert_eq!(c.username.as_deref(), Some("7"));
            assert!(c.password.is_none());
        }

        #[test]
        fn an_r2dbc_url_becomes_connect_options() {
            let o = connect_options(&creds(Some("r2dbc:mysql://us%65r:p%40ss@db-host:3307/core?sslMode=DISABLED"))).unwrap();
            assert_eq!((o.get_host(), o.get_port(), o.get_username()), ("db-host", 3307, "user"));
            assert_eq!(o.get_database(), Some("core"));
            assert_eq!(o.get_charset(), "utf8mb4");

            let o = connect_options(&creds(Some("r2dbc:pool:mysql://h/db"))).unwrap();
            assert_eq!((o.get_host(), o.get_port(), o.get_database()), ("h", 3306, Some("db")));
            let o = connect_options(&creds(Some("r2dbcs:mysql://h:notaport"))).unwrap();
            assert_eq!((o.get_host(), o.get_port(), o.get_database()), ("h", 3306, None));
            let o = connect_options(&creds(Some("mysql://onlyuser@h/"))).unwrap();
            assert_eq!((o.get_username(), o.get_database()), ("onlyuser", None));

            let o = connect_options(&creds(Some("r2dbc:mysql://a%zz:x@h/db"))).unwrap();
            assert_eq!(o.get_username(), "a%zz");
            let o = connect_options(&creds(Some("r2dbc:mysql://ab%4@h/db"))).unwrap();
            assert_eq!(o.get_username(), "ab%4");

            let explicit = Credentials { username: Some("named".into()), ..creds(Some("r2dbc:mysql://inurl:pw@h/db")) };
            assert_eq!(connect_options(&explicit).unwrap().get_username(), "named");
        }

        /// A url that is not MySQL names the host but never the password.
        #[test]
        fn a_bad_url_is_refused_without_its_password() {
            let e = connect_options(&creds(Some("jdbc:mysql://u:secret@h/db"))).unwrap_err();
            assert!(e.message().contains("***@h/db") && !e.message().contains("secret"), "{}", e.message());
            let e = connect_options(&creds(Some("postgres://h/db"))).unwrap_err();
            assert!(e.message().contains("postgres://h/db"), "{}", e.message());

            let missing = connect_options(&creds(None)).unwrap_err();
            assert_eq!(missing.status(), http::StatusCode::NOT_FOUND);
            assert!(missing.message().contains("url"), "{}", missing.message());
            let from_default = connect_options(&Credentials { from_default: true, ..creds(None) }).unwrap_err();
            assert!(from_default.message().contains("spring.r2dbc.url"), "{}", from_default.message());
        }

        #[test]
        fn a_count_is_the_first_value_of_the_first_row() {
            let row = |v: Value| -> Vec<Document> {
                let mut d = Document::new();
                d.insert("COUNT(*)".into(), v);
                d.insert("other".into(), Value::Int(99));
                vec![d]
            };
            assert_eq!(first_number(&row(Value::Int(4))), 4);
            assert_eq!(first_number(&row(Value::Decimal(appdata::value::Decimal::parse("12").unwrap()))), 12);
            assert_eq!(first_number(&row(Value::Double(2.9))), 2);
            assert_eq!(first_number(&row(Value::Bool(true))), 1);
            assert_eq!(first_number(&row(Value::from("5"))), 0);
            assert_eq!(first_number(&[]), 0);
        }

        /// Errors that did not come from the driver have no SQLSTATE and keep their text.
        #[test]
        fn messages_of_errors_that_are_not_the_drivers() {
            let internal = AppDataError::internal("boom");
            assert_eq!(message(&internal), "boom");
            assert_eq!(sql_state(&internal), None);
            assert!(!is_integrity_violation(&internal));
            let nf = AppDataError::object_not_found("orders", "42");
            assert_eq!(message(&nf), nf.message());
            assert_eq!(sql_state(&nf), None);
            assert_eq!(message(&AppDataError::Empty), "");
        }
    }

    mod service_helpers {
        use super::*;
        use appdata::model::{AggregateQuery, DateBucketUnit, GroupByField, Order, Query, Sort, Storage};
        use appdata::mysql::service::{
            boolean_aliases, head, null_column, nulls_on_required, order, order_plain, physical_of, projection, selected_parent_columns,
            update_values,
        };
        use appdata::mysql::field_resolver::FieldResolver;
        use appdata::mysql::sql::Bind;
        use appdata::value::Decimal;
        use indexmap::{IndexMap, IndexSet};

        fn schema() -> appdata::mysql::column_names::PhysicalSchema {
            physical_of(object(vec![
                ("IFSC Code", string_len("IFSC Code", 20)),
                ("Amount", double("Amount")),
                ("placedAt", Schema::of_string("placedAt").with_format(StringFormat::DateTime)),
                ("price", Schema::of_string("price").with_format(StringFormat::Decimal)),
                ("address", object(vec![("city", string_len("city", 40))])),
            ]))
        }

        fn query(fields: &[&str], exclude: bool) -> Query {
            Query { fields: Some(fields.iter().map(|f| f.to_string()).collect()), exclude_fields: Some(exclude), ..Default::default() }
        }

        /// Java's removeIf then add: the id stays first unless it was excluded, and then
        /// comes back last.
        #[test]
        fn joined_selection_with_an_exclude_list() {
            let cols: Vec<String> = selected_parent_columns(&schema(), &query(&["IFSC Code"], true)).unwrap().into_iter().collect();
            assert_eq!(cols, vec!["_id", "Amount", "address", "placedAt", "price"]);
            let cols: Vec<String> = selected_parent_columns(&schema(), &query(&["_id", "Amount"], true)).unwrap().into_iter().collect();
            assert_eq!(cols, vec!["IFSC_Code", "address", "placedAt", "price", "_id"]);
            let all: Vec<String> = selected_parent_columns(&schema(), &Query::default()).unwrap().into_iter().collect();
            assert_eq!(all, vec!["_id", "Amount", "IFSC_Code", "address", "placedAt", "price"]);
            let only: Vec<String> = selected_parent_columns(&schema(), &query(&["nosuch", "Amount"], false)).unwrap().into_iter().collect();
            assert_eq!(only, vec!["_id", "Amount"]);
        }

        /// The SET clause encodes as the codec does: dates to UTC text, decimals exact,
        /// structures as JSON text.
        #[test]
        fn set_values_are_encoded_for_their_columns() {
            let storage = Storage { name: "s".into(), unique_name: "s".into(), ..Default::default() };
            let values: IndexMap<String, Bind> = update_values(
                &storage,
                &schema(),
                &doc(r#"{"_id":"1","placedAt":"2026-01-15T10:00:00+05:30","price":"10.50","address":{"city":"Pune"},"IFSC Code":"X"}"#),
                None,
            )
            .unwrap()
            .into_iter()
            .collect();
            assert_eq!(values["placedAt"], Bind::Text("2026-01-15T04:30:00".into()));
            assert_eq!(values["price"], Bind::Decimal(Decimal::parse("10.50").unwrap()));
            assert_eq!(values["address"], Bind::Text(r#"{"city":"Pune"}"#.into()));
            assert_eq!(values["IFSC_Code"], Bind::Text("X".into()));

            let mut data = Document::new();
            let at = chrono::NaiveDate::from_ymd_opt(2026, 1, 15).unwrap().and_hms_opt(10, 0, 0).unwrap();
            data.insert("Amount".into(), Value::LocalDateTime(at));
            let values = update_values(&storage, &schema(), &data, None).unwrap();
            assert_eq!(values, vec![("Amount".to_string(), Bind::DateTime(at))]);
        }

        /// A list bound to a column that is not JSON: the driver refuses it in Java, a 500.
        #[test]
        fn a_structure_outside_a_json_column_cannot_be_bound() {
            let storage = Storage { name: "s".into(), unique_name: "s".into(), ..Default::default() };
            let e = update_values(&storage, &schema(), &doc(r#"{"Amount":[1,2]}"#), None).unwrap_err();
            assert_eq!(e.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
            assert!(e.message().contains("Cannot encode value"), "{}", e.message());
        }

        #[test]
        fn nothing_sent_is_nothing_refused() {
            assert!(nulls_on_required(&schema(), &Document::new()).unwrap().is_empty());
        }

        #[test]
        fn only_a_not_null_refusal_names_a_column() {
            assert_eq!(null_column("(conn=12) Column 'amount' cannot be null").as_deref(), Some("amount"));
            assert_eq!(null_column("Column 'amount' in field list is ambiguous"), None);
            assert_eq!(null_column("Column 'amount"), None);
            assert_eq!(null_column("Duplicate entry '1' for key 'PRIMARY'"), None);
        }

        #[test]
        fn heads_that_are_not_columns() {
            let mut cols = IndexMap::new();
            cols.insert("region".to_string(), "VARCHAR(20)".to_string());
            assert_eq!(head("region", &cols), "region");
            assert_eq!(head("Due Date", &cols), "Due_Date");
            assert_eq!(head("customer.Full Name", &cols), "customer");
            assert_eq!(head("Bank Details.city", &cols), "Bank_Details");
        }

        #[test]
        fn boolean_aliases_skip_buckets_and_use_the_alias() {
            let bools: IndexSet<String> = ["active".to_string()].into_iter().collect();
            let q = AggregateQuery {
                group_by: Some(vec![
                    GroupByField { alias: Some("isActive".into()), ..GroupByField::new("active") },
                    GroupByField { bucket: Some(DateBucketUnit::Day), ..GroupByField::new("active") },
                    GroupByField { field: None, ..GroupByField::new("x") },
                ]),
                ..Default::default()
            };
            assert_eq!(boolean_aliases(&q, &bools).into_iter().collect::<Vec<_>>(), vec!["isActive"]);
            assert!(boolean_aliases(&q, &IndexSet::new()).is_empty());
            assert!(boolean_aliases(&AggregateQuery::default(), &bools).is_empty());
        }

        /// A path into a JSON column that is not a path fails the sort, as the resolver's
        /// refusal fails Java's `order`.
        #[test]
        fn a_sort_on_a_junk_path_fails() {
            assert!(order_plain(&schema(), &Sort::by(vec![Order::asc("address.c'ty")])).is_err());
            let resolver = FieldResolver::of(IndexSet::new());
            assert!(order(&schema(), &Sort::by(vec![Order::asc("IFSC Code")]), &resolver).is_ok());
        }

        /// A schema whose property is not a usable column (only a schema that skipped
        /// `physical` can hold one) fails the mapping rather than reaching DDL.
        #[test]
        fn an_unusable_column_fails_the_read_shaping() {
            let raw = appdata::mysql::column_names::PhysicalSchema { schema: object(vec![("a b", integer("a b"))]), field_by_column: IndexMap::new() };
            let e = projection(&raw, &query(&["x"], true)).unwrap_err();
            assert_eq!(e.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
            assert!(selected_parent_columns(&raw, &Query::default()).is_err());
            assert!(order_plain(&raw, &Sort::by(vec![Order::asc("a")])).is_err());
            assert!(nulls_on_required(&raw, &doc(r#"{"a":null}"#)).is_err());
        }
    }
}
