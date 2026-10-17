//! `AuthorityExpressionController` / `AuthorityExpressionService`: takes an authority expression
//! apart into the builder's two-level shape (groups of lines), parsing with the KIRun expression
//! parser, as Java does, so the tree (and the text of a node in a refusal) is the evaluator's.

use axum::routing::post;
use axum::Router;
use kirun::runtime::expression::expression::Expression;
use kirun::runtime::expression::expression_token::ExpressionToken;
use kirun::runtime::expression::operation::Operation;
use serde_json::{Map, Value};

use super::common::{object_body, pre_authorize, Fields};
use crate::admin::AdminState;
use crate::jackson::json;

const AND: &str = "and";
const OR: &str = "or";
const TOO_DEEP: &str = "This expression nests brackets more than two levels deep, which the builder cannot draw. Edit it as text.";

/// `AuthorityCondition`: one line.
#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub negated: bool,
    pub atom: String,
}

/// `AuthorityGroup`: `j` joins the group to the one above, `op` joins its lines.
#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub j: String,
    pub op: String,
    pub rows: Vec<Line>,
}

/// `AuthorityExpression`.
#[derive(Debug, Clone, PartialEq)]
pub enum Parsed {
    Supported(Vec<Group>),
    Unsupported(String),
}

impl Parsed {
    /// Jackson's `NON_EMPTY` shape: `supported`, `reason`, `groups` (`rows` left out when empty).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        match self {
            Parsed::Supported(groups) => {
                m.insert("supported".into(), Value::Bool(true));
                if !groups.is_empty() {
                    let gs = groups
                        .iter()
                        .map(|g| {
                            let mut o = Map::new();
                            o.insert("j".into(), Value::from(g.j.clone()));
                            o.insert("op".into(), Value::from(g.op.clone()));
                            if !g.rows.is_empty() {
                                let rows = g
                                    .rows
                                    .iter()
                                    .map(|l| {
                                        let mut r = Map::new();
                                        r.insert("n".into(), Value::Bool(l.negated));
                                        r.insert("a".into(), Value::from(l.atom.clone()));
                                        Value::Object(r)
                                    })
                                    .collect();
                                o.insert("rows".into(), Value::Array(rows));
                            }
                            Value::Object(o)
                        })
                        .collect();
                    m.insert("groups".into(), Value::Array(gs));
                }
            }
            Parsed::Unsupported(reason) => {
                m.insert("supported".into(), Value::Bool(false));
                m.insert("reason".into(), Value::from(reason.clone()));
            }
        }
        Value::Object(m)
    }
}

fn group(j: &str, op: &str) -> Group {
    Group { j: j.to_string(), op: op.to_string(), rows: vec![] }
}

/// The single operation of a parsed node, or `None` for a leaf.
fn op_of(t: &ExpressionToken) -> Option<Operation> {
    match t {
        ExpressionToken::Expression(e) if e.get_operations().len() == 1 => e.get_operations().front().copied(),
        _ => None,
    }
}

fn is_chain(op: Option<Operation>) -> bool {
    op == Some(Operation::AND) || op == Some(Operation::OR)
}

fn tokens(t: &ExpressionToken) -> Option<&Expression> {
    match t {
        ExpressionToken::Expression(e) => Some(e),
        _ => None,
    }
}

/// Strips one `not`.
fn peel_not(t: &ExpressionToken) -> (&ExpressionToken, bool) {
    let op = op_of(t);
    if op == Some(Operation::UNARY_LOGICAL_NOT) || op == Some(Operation::NOT) {
        if let Some(inner) = tokens(t).and_then(|e| e.get_tokens().front()) {
            return (inner, true);
        }
    }
    (t, false)
}

fn valid_atom(text: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if t == "true" || t == "false" {
        return Some(t.to_string());
    }
    let ident = |s: &str| {
        let mut b = s.bytes();
        matches!(b.next(), Some(c) if c.is_ascii_alphabetic() || c == b'_') && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
    };
    t.split('.').all(ident).then(|| t.to_string())
}

/// A dotted token rebuilt from the tree; anything else is `None`.
fn atom_of(t: &ExpressionToken) -> Option<String> {
    let Some(e) = tokens(t) else { return valid_atom(&t.to_string()) };
    let (ops, toks) = (e.get_operations(), e.get_tokens());
    if ops.is_empty() {
        return if toks.len() == 1 { atom_of(&toks[0]) } else { None };
    }
    if ops.len() != 1 || ops[0] != Operation::OBJECT_OPERATOR || toks.len() != 2 {
        return None;
    }
    let left = atom_of(&toks[1])?;
    let right = atom_of(&toks[0])?;
    valid_atom(&format!("{left}.{right}"))
}

/// The left spine of an and/or chain in reading order; a looser-binding left operand stays whole.
fn flatten<'a>(node: &'a ExpressionToken, out: &mut Vec<&'a ExpressionToken>, joins: &mut Vec<Operation>) {
    let op = op_of(node);
    let Some(e) = tokens(node).filter(|_| is_chain(op)) else {
        out.push(node);
        return;
    };
    let op = op.unwrap_or(Operation::AND);
    let toks = e.get_tokens();
    let (right, left) = (&toks[0], &toks[1]);
    let left_op = op_of(left);
    if is_chain(left_op) && left_op.and_then(|o| o.get_priority()) <= op.get_priority() {
        flatten(left, out, joins);
    } else {
        out.push(left);
    }
    joins.push(op);
    out.push(right);
}

fn is_mixed(chain: &[&ExpressionToken], joins: &[Operation]) -> bool {
    if joins.len() < 2 {
        return false;
    }
    if chain.iter().any(|t| is_chain(op_of(peel_not(t).0))) {
        return true;
    }
    joins.iter().any(|j| *j != joins[0])
}

fn to_group(node: &ExpressionToken, join: &str) -> Option<Group> {
    let (mut sub, mut joins) = (vec![], vec![]);
    flatten(node, &mut sub, &mut joins);
    if is_mixed(&sub, &joins) {
        return None;
    }
    let mut g = group(join, joins.first().map(|o| o.get_operator().trim()).unwrap_or(AND));
    for each in sub {
        let (node, negated) = peel_not(each);
        g.rows.push(Line { negated, atom: atom_of(node)? });
    }
    Some(g)
}

/// `AuthorityExpressionService.parseInternal`.
pub fn parse(expression: Option<&str>) -> Parsed {
    let Some(text) = expression.filter(|e| !e.trim().is_empty()) else {
        return Parsed::Supported(vec![group(AND, AND)]);
    };
    let parsed = match Expression::new(text.trim()) {
        Ok(e) => ExpressionToken::Expression(Box::new(e)),
        Err(e) => return Parsed::Unsupported(format!("This is not a valid expression: {e}")),
    };
    let (mut chain, mut joins) = (vec![], vec![]);
    flatten(&parsed, &mut chain, &mut joins);
    let mixed = is_mixed(&chain, &joins);
    let run_op = joins.first().map(|o| o.get_operator().trim()).unwrap_or(AND);

    let mut groups: Vec<Group> = vec![];
    let mut in_run = false;
    for (i, each) in chain.iter().enumerate() {
        let join = if i == 0 { AND } else { joins[i - 1].get_operator().trim() };
        let (node, negated) = peel_not(each);
        if is_chain(op_of(node)) {
            if negated {
                return Parsed::Unsupported("A whole bracket cannot be negated here. Put the not on each line inside it instead.".into());
            }
            match to_group(node, join) {
                Some(g) => groups.push(g),
                None => return Parsed::Unsupported(TOO_DEEP.into()),
            }
            in_run = false;
            continue;
        }
        let Some(atom) = atom_of(node) else {
            return Parsed::Unsupported(format!("\"{node}\" is not an authority token, so the builder cannot show it."));
        };
        if !in_run || (mixed && join == OR) {
            groups.push(group(join, if mixed { AND } else { run_op }));
            in_run = true;
        }
        if let Some(g) = groups.last_mut() {
            g.rows.push(Line { negated, atom });
        }
    }
    Parsed::Supported(groups)
}

crate::web_route!(parse_route, AdminState, "/authorities/parse", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let expression = Fields(&body).string("expression")?;
    pre_authorize(&ca, &["Authorities.Logged_IN"])?;
    Ok(json(&parse(expression.as_deref()).to_json()))
});

pub fn router() -> Router<AdminState> {
    Router::new().route("/api/security/authorities/parse", post(parse_route))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `AuthorityExpressionServiceTest.serialise`: what the builder writes back.
    fn serialise(groups: &[Group]) -> String {
        let mut sb = String::new();
        for (g, group) in groups.iter().enumerate() {
            if group.rows.is_empty() {
                continue;
            }
            let bracket = group.rows.len() > 1 && groups.len() > 1;
            if g > 0 {
                sb.push_str(&format!(" {} ", group.j));
            }
            if bracket {
                sb.push('(');
            }
            for (r, row) in group.rows.iter().enumerate() {
                if r > 0 {
                    sb.push_str(&format!(" {} ", group.op));
                }
                if row.negated {
                    sb.push_str("not ");
                }
                sb.push_str(&row.atom);
            }
            if bracket {
                sb.push(')');
            }
        }
        sb
    }

    fn ok(e: &str) -> Vec<Group> {
        match parse(Some(e)) {
            Parsed::Supported(g) => g,
            Parsed::Unsupported(r) => panic!("expected supported for {e}: {r}"),
        }
    }

    /// The cases of `AuthorityExpressionServiceTest`.
    #[test]
    fn java_cases() {
        let empty = ok("");
        assert!(empty.len() == 1 && empty[0].rows.is_empty());
        assert_eq!(serialise(&ok("Authorities.Logged_IN")), "Authorities.Logged_IN");
        let all = ok("Authorities.A and Authorities.B and Authorities.C");
        assert_eq!((all.len(), all[0].op.as_str(), all[0].rows.len()), (1, "and", 3));
        assert_eq!(serialise(&ok("Authorities.A or Authorities.B or Authorities.C")), "Authorities.A or Authorities.B or Authorities.C");
        assert_eq!(serialise(&ok("(Authorities.A or Authorities.B)")), "Authorities.A or Authorities.B");
        let mixed = ok("Authorities.A and Authorities.B or Authorities.C");
        assert_eq!((mixed.len(), mixed[0].rows.len(), mixed[1].j.as_str()), (2, 2, "or"));
        assert_eq!(serialise(&mixed), "(Authorities.A and Authorities.B) or Authorities.C");
        for e in [
            "Authorities.Logged_IN and (Authorities.LEADZUMP.ROLE_Product_CREATE or Authorities.ROLE_Schema_Manager)",
            "(Authorities.A or Authorities.B) and Authorities.C",
            "(Authorities.A or Authorities.B) and (Authorities.C or Authorities.D)",
            "not Authorities.A and Authorities.B",
        ] {
            assert_eq!(serialise(&ok(e)), e);
        }
        let right = ok("Authorities.Logged_IN and (Authorities.LEADZUMP.ROLE_Product_CREATE or Authorities.ROLE_Schema_Manager)");
        assert_eq!((right[1].j.as_str(), right[1].op.as_str()), ("and", "or"));
        let negated = ok("not Authorities.A and Authorities.B");
        assert!(negated[0].rows[0].negated && !negated[0].rows[1].negated);
        for e in [
            "Authorities.Z and (Authorities.A and Authorities.B or Authorities.C)",
            "Authorities.A and (Authorities.B or (Authorities.C and Authorities.D))",
            "Authorities.A and Store.x = 1",
            "Authorities.A and )(",
        ] {
            assert!(matches!(parse(Some(e)), Parsed::Unsupported(_)), "{e}");
        }
    }

    fn shape(e: &str) -> String {
        parse(Some(e)).to_json().to_string()
    }

    #[test]
    fn groups_like_the_builder() {
        assert_eq!(parse(None).to_json().to_string(), r#"{"supported":true,"groups":[{"j":"and","op":"and"}]}"#);
        assert_eq!(shape("Authorities.A or Authorities.B and Authorities.C"), r#"{"supported":true,"groups":[{"j":"and","op":"or","rows":[{"n":false,"a":"Authorities.A"}]},{"j":"or","op":"and","rows":[{"n":false,"a":"Authorities.B"},{"n":false,"a":"Authorities.C"}]}]}"#);
        assert_eq!(shape("not (Authorities.A and Authorities.B)"), r#"{"supported":false,"reason":"A whole bracket cannot be negated here. Put the not on each line inside it instead."}"#);
        assert!(shape("Authorities.A and (Authorities.B and (Authorities.C or Authorities.D))").contains("more than two levels"));
        assert_eq!(valid_atom("Authorities.1A"), None);
        assert_eq!(shape("Authorities.A[0]"), r#"{"supported":false,"reason":"\"(Authorities.(A[0]))\" is not an authority token, so the builder cannot show it."}"#);
        assert_eq!(shape("(("), r#"{"supported":false,"reason":"This is not a valid expression: (( : Missing a closed parenthesis"}"#);
        assert_eq!(valid_atom(" a.b_c "), Some("a.b_c".into()));
    }
}
