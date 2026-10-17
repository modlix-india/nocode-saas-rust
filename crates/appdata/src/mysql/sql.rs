//! A small SQL builder that renders what jOOQ renders for the MySQL dialect.
//!
//! The Java backend builds its statements with jOOQ and its unit tests pin the rendered
//! text, so the Rust one reproduces jOOQ's spelling: lower-case keywords, backticked
//! names, `(a and b)` for a group, `not (x)` for a negation, `true` for an empty
//! condition that has to be written down, and the same literal escaping when a statement
//! is rendered inlined (`'it''s \\ x'`). With binds, every value is a `?` and travels
//! separately, exactly as jOOQ binds it.

use crate::value::{java_double, Decimal};

/// One bound value.
#[derive(Debug, Clone, PartialEq)]
pub enum Bind {
    Null,
    Bool(bool),
    Int(i64),
    Double(f64),
    /// A `Float` from a caller: inlined as jOOQ inlines one, bound as a double.
    Float(f32),
    Decimal(Decimal),
    Text(String),
    /// A `LocalDateTime`, bound as a DATETIME.
    DateTime(chrono::NaiveDateTime),
}

impl Bind {
    /// The literal jOOQ writes when it inlines this value for MySQL.
    pub fn inline(&self) -> String {
        match self {
            Bind::Null => "null".into(),
            Bind::Bool(b) => b.to_string(),
            Bind::Int(i) => i.to_string(),
            Bind::Double(d) => jooq_double(*d),
            Bind::Float(f) => jooq_double(*f as f64),
            Bind::Decimal(d) => d.to_java_string(),
            Bind::Text(s) => string_literal(s),
            Bind::DateTime(dt) => format!("{{ts '{}'}}", dt.format("%Y-%m-%d %H:%M:%S%.f")),
        }
    }
}

/// jOOQ inlines a double as its `Double.toString` digits in E notation: `1.5E0`, `1E0`.
fn jooq_double(d: f64) -> String {
    if !d.is_finite() {
        return java_double(d);
    }
    let text = java_double(d);
    let (mantissa, exp) = match text.find('E') {
        Some(i) => (text[..i].to_string(), text[i + 1..].parse::<i32>().unwrap_or(0)),
        None => (text.clone(), 0),
    };
    let negative = mantissa.starts_with('-');
    let m = mantissa.trim_start_matches('-');
    let (int, frac) = match m.find('.') {
        Some(i) => (&m[..i], &m[i + 1..]),
        None => (m, ""),
    };
    let mut digits = format!("{int}{frac}");
    let mut point = int.len() as i32 + exp;
    let lead = digits.len() - digits.trim_start_matches('0').len();
    digits.drain(..lead);
    point -= lead as i32;
    let trimmed = digits.trim_end_matches('0').len();
    digits.truncate(trimmed);
    if digits.is_empty() {
        return if negative { "-0E0".into() } else { "0E0".into() };
    }
    let rest = if digits.len() > 1 { format!(".{}", &digits[1..]) } else { String::new() };
    format!("{}{}{}E{}", if negative { "-" } else { "" }, &digits[..1], rest, point - 1)
}

/// A MySQL string literal as jOOQ writes it: quotes doubled, backslashes doubled.
pub fn string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\'' => out.push_str("''"),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// A name in backticks, a backtick inside it doubled.
pub fn quote(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

/// `DSL.name(parts...)`.
pub fn qualified(parts: &[&str]) -> String {
    parts.iter().map(|p| quote(p)).collect::<Vec<_>>().join(".")
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Raw(String),
    Param(Bind),
}

/// A fragment of SQL with its bound values in place.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Sql {
    toks: Vec<Tok>,
}

impl Sql {
    pub fn raw(s: impl Into<String>) -> Sql {
        Sql { toks: vec![Tok::Raw(s.into())] }
    }

    pub fn param(b: Bind) -> Sql {
        Sql { toks: vec![Tok::Param(b)] }
    }

    /// A column or table: `DSL.field(DSL.name(parts...))`.
    pub fn name(parts: &[&str]) -> Sql {
        Sql::raw(qualified(parts))
    }

    pub fn push(&mut self, s: &str) -> &mut Self {
        self.toks.push(Tok::Raw(s.to_string()));
        self
    }

    pub fn push_sql(&mut self, other: &Sql) -> &mut Self {
        self.toks.extend(other.toks.iter().cloned());
        self
    }

    pub fn push_param(&mut self, b: Bind) -> &mut Self {
        self.toks.push(Tok::Param(b));
        self
    }

    pub fn then(mut self, s: &str) -> Sql {
        self.push(s);
        self
    }

    pub fn then_sql(mut self, other: &Sql) -> Sql {
        self.push_sql(other);
        self
    }

    /// `DSL.field(template, args...)`: `{0}`, `{1}` replaced by the arguments.
    pub fn template(template: &str, args: &[Sql]) -> Sql {
        let mut out = Sql::default();
        let mut rest = template;
        while let Some(start) = rest.find('{') {
            let Some(end) = rest[start..].find('}') else { break };
            let index: Option<usize> = rest[start + 1..start + end].parse().ok();
            match index.and_then(|i| args.get(i)) {
                Some(arg) => {
                    out.push(&rest[..start]);
                    out.push_sql(arg);
                }
                None => {
                    out.push(&rest[..start + end + 1]);
                }
            }
            rest = &rest[start + end + 1..];
        }
        out.push(rest);
        out
    }

    /// Join fragments with a separator.
    pub fn join(parts: &[Sql], sep: &str) -> Sql {
        let mut out = Sql::default();
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                out.push(sep);
            }
            out.push_sql(p);
        }
        out
    }

    /// `field.as(alias)`.
    pub fn alias(&self, alias: &str) -> Sql {
        self.clone().then(" as ").then(&quote(alias))
    }

    pub fn asc(&self) -> Sql {
        self.clone().then(" asc")
    }

    pub fn desc(&self) -> Sql {
        self.clone().then(" desc")
    }

    pub fn is_empty(&self) -> bool {
        self.toks.is_empty()
    }

    /// SQL with `?` for every value, and the values in order.
    pub fn render(&self) -> (String, Vec<Bind>) {
        let mut sql = String::new();
        let mut binds = Vec::new();
        for t in &self.toks {
            match t {
                Tok::Raw(s) => sql.push_str(s),
                Tok::Param(b) => {
                    sql.push('?');
                    binds.push(b.clone());
                }
            }
        }
        (sql, binds)
    }

    /// SQL with every value written as a literal, as `DSLContext.renderInlined`.
    pub fn inlined(&self) -> String {
        let mut sql = String::new();
        for t in &self.toks {
            match t {
                Tok::Raw(s) => sql.push_str(s),
                Tok::Param(b) => sql.push_str(&b.inline()),
            }
        }
        sql
    }
}

/// A condition, with jOOQ's rules for combining and negating.
#[derive(Debug, Clone, PartialEq)]
pub enum Cond {
    /// `DSL.noCondition()`: dropped from a WHERE, written `true` anywhere else.
    None,
    True,
    False,
    /// A predicate jOOQ renders bare: `` `a` = ? ``.
    Atom(Sql),
    /// `DSL.condition(template)`: jOOQ wraps plain SQL in parentheses.
    Plain(Sql),
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Not(Box<Cond>),
}

impl Cond {
    /// `DSL.and(parts)`: no-conditions dropped, a single part stands alone, nested ANDs
    /// flattened.
    pub fn and(parts: Vec<Cond>) -> Cond {
        Self::combine(parts, true)
    }

    pub fn or(parts: Vec<Cond>) -> Cond {
        Self::combine(parts, false)
    }

    fn combine(parts: Vec<Cond>, and: bool) -> Cond {
        let mut out = Vec::new();
        for p in parts {
            match p {
                Cond::None => {}
                Cond::And(inner) if and => out.extend(inner),
                Cond::Or(inner) if !and => out.extend(inner),
                other => out.push(other),
            }
        }
        match out.len() {
            0 => Cond::None,
            1 => out.pop().unwrap_or(Cond::None),
            _ => {
                if and {
                    Cond::And(out)
                } else {
                    Cond::Or(out)
                }
            }
        }
    }

    /// `c.and(other)`.
    pub fn and_also(self, other: Cond) -> Cond {
        Cond::and(vec![self, other])
    }

    /// `DSL.not(c)` / `c.not()`.
    pub fn not(self) -> Cond {
        Cond::Not(Box::new(self))
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Cond::None)
    }

    pub fn to_sql(&self) -> Sql {
        match self {
            Cond::None | Cond::True => Sql::raw("true"),
            Cond::False => Sql::raw("false"),
            Cond::Atom(s) => s.clone(),
            Cond::Plain(s) => Sql::raw("(").then_sql(s).then(")"),
            Cond::And(parts) | Cond::Or(parts) => {
                let sep = if matches!(self, Cond::And(_)) { " and " } else { " or " };
                let rendered: Vec<Sql> = parts.iter().map(Cond::to_sql).collect();
                Sql::raw("(").then_sql(&Sql::join(&rendered, sep)).then(")")
            }
            Cond::Not(inner) => match inner.as_ref() {
                Cond::True => Sql::raw("not true"),
                Cond::False => Sql::raw("not false"),
                Cond::None => Sql::raw("not (true)"),
                Cond::Atom(s) | Cond::Plain(s) => Sql::raw("not (").then_sql(s).then(")"),
                Cond::And(_) | Cond::Or(_) => Sql::raw("not ").then_sql(&inner.to_sql()),
                Cond::Not(_) => Sql::raw("not (").then_sql(&inner.to_sql()).then(")"),
            },
        }
    }

    /// ` where <cond>`, or nothing for no condition.
    pub fn where_clause(&self) -> Sql {
        if self.is_none() {
            Sql::default()
        } else {
            Sql::raw(" where ").then_sql(&self.to_sql())
        }
    }

    pub fn inlined(&self) -> String {
        self.to_sql().inlined()
    }
}

/// Predicates on a field, spelled as jOOQ spells them.
pub trait FieldOps {
    fn sql(&self) -> &Sql;

    fn cmp(&self, op: &str, right: Sql) -> Cond {
        Cond::Atom(self.sql().clone().then(&format!(" {op} ")).then_sql(&right))
    }

    fn equal(&self, right: Sql) -> Cond {
        self.cmp("=", right)
    }

    fn is_null(&self) -> Cond {
        Cond::Atom(self.sql().clone().then(" is null"))
    }

    fn is_not_null(&self) -> Cond {
        Cond::Atom(self.sql().clone().then(" is not null"))
    }

    fn in_list(&self, values: Vec<Sql>) -> Cond {
        Cond::Atom(self.sql().clone().then(" in (").then_sql(&Sql::join(&values, ", ")).then(")"))
    }

    fn in_select(&self, select: Sql) -> Cond {
        Cond::Atom(self.sql().clone().then(" in (").then_sql(&select).then(")"))
    }

    fn between(&self, low: Sql, high: Sql) -> Cond {
        Cond::Atom(self.sql().clone().then(" between ").then_sql(&low).then(" and ").then_sql(&high))
    }

    fn like(&self, pattern: Sql) -> Cond {
        Cond::Atom(self.sql().clone().then(" like ").then_sql(&pattern))
    }

    /// `Field.isTrue()` for an untyped field: a text cast against jOOQ's truthy literals,
    /// in the order its HashSet iterates them.
    fn is_true(&self) -> Cond {
        Cond::Atom(
            Sql::raw("cast(").then_sql(self.sql()).then(
                " as char) in ('yes', 'YES', 'TRUE', 'enabled', '1', '1.0', 't', 'T', 'true', 'y', 'Y', 'ENABLED', 'on', 'ON')",
            ),
        )
    }

    fn is_false(&self) -> Cond {
        Cond::Atom(
            Sql::raw("cast(").then_sql(self.sql()).then(
                " as char) in ('no', 'NO', 'f', 'F', 'false', 'n', 'N', 'off', 'OFF', '0', 'DISABLED', '0.0', 'FALSE', 'disabled')",
            ),
        )
    }
}

impl FieldOps for Sql {
    fn sql(&self) -> &Sql {
        self
    }
}

/// A SELECT, with the clauses jOOQ writes in the order it writes them.
#[derive(Debug, Clone, Default)]
pub struct Select {
    /// Empty selects `*`.
    pub fields: Vec<Sql>,
    pub from: Sql,
    pub where_: Option<Cond>,
    pub group_by: Vec<Sql>,
    pub having: Option<Cond>,
    pub order_by: Vec<Sql>,
    /// (limit, offset), bound.
    pub limit: Option<(i64, i64)>,
}

impl Select {
    pub fn star(from: Sql) -> Select {
        Select { from, ..Default::default() }
    }

    pub fn fields(fields: Vec<Sql>, from: Sql) -> Select {
        Select { fields, from, ..Default::default() }
    }

    pub fn count(from: Sql) -> Select {
        Select { fields: vec![Sql::raw("count(*)")], from, ..Default::default() }
    }

    pub fn filter(mut self, c: Cond) -> Select {
        self.where_ = Some(c);
        self
    }

    pub fn order(mut self, o: Vec<Sql>) -> Select {
        self.order_by = o;
        self
    }

    pub fn page(mut self, limit: i64, offset: i64) -> Select {
        self.limit = Some((limit, offset));
        self
    }

    pub fn to_sql(&self) -> Sql {
        let mut s = Sql::raw("select ");
        if self.fields.is_empty() {
            s.push("*");
        } else {
            s.push_sql(&Sql::join(&self.fields, ", "));
        }
        s.push(" from ");
        s.push_sql(&self.from);
        if let Some(w) = &self.where_ {
            s.push_sql(&w.where_clause());
        }
        if !self.group_by.is_empty() {
            s.push(" group by ");
            s.push_sql(&Sql::join(&self.group_by, ", "));
        }
        if let Some(h) = &self.having {
            if !h.is_none() {
                s.push(" having ");
                s.push_sql(&h.to_sql());
            }
        }
        if !self.order_by.is_empty() {
            s.push(" order by ");
            s.push_sql(&Sql::join(&self.order_by, ", "));
        }
        if let Some((limit, offset)) = self.limit {
            s.push(" limit ");
            s.push_param(Bind::Int(limit));
            s.push(" offset ");
            s.push_param(Bind::Int(offset));
        }
        s
    }

    /// `select.asTable(alias)`.
    pub fn as_table(&self, alias: &str) -> Sql {
        Sql::raw("(").then_sql(&self.to_sql()).then(") as ").then(&quote(alias))
    }
}

/// `insert into <table> (<cols>) values (<binds>)`.
pub fn insert(table: &Sql, values: &[(String, Bind)]) -> Sql {
    let cols: Vec<Sql> = values.iter().map(|(c, _)| Sql::raw(quote(c))).collect();
    let binds: Vec<Sql> = values.iter().map(|(_, b)| Sql::param(b.clone())).collect();
    Sql::raw("insert into ")
        .then_sql(table)
        .then(" (")
        .then_sql(&Sql::join(&cols, ", "))
        .then(") values (")
        .then_sql(&Sql::join(&binds, ", "))
        .then(")")
}

/// `update <table> set a = ?, b = ? where ...`.
pub fn update(table: &Sql, values: &[(String, Bind)], cond: &Cond) -> Sql {
    let sets: Vec<Sql> = values
        .iter()
        .map(|(c, b)| Sql::raw(quote(c)).then(" = ").then_sql(&Sql::param(b.clone())))
        .collect();
    Sql::raw("update ")
        .then_sql(table)
        .then(" set ")
        .then_sql(&Sql::join(&sets, ", "))
        .then_sql(&cond.where_clause())
}

/// `delete from <table> where ...`.
pub fn delete(table: &Sql, cond: &Cond) -> Sql {
    Sql::raw("delete from ").then_sql(table).then_sql(&cond.where_clause())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a() -> Sql {
        Sql::name(&["a"])
    }

    fn one() -> Sql {
        Sql::param(Bind::Int(1))
    }

    #[test]
    fn combines_as_jooq_does() {
        let x = a().equal(Sql::param(Bind::Int(1)));
        let y = a().equal(Sql::param(Bind::Int(2)));
        let z = a().equal(Sql::param(Bind::Int(3)));
        assert_eq!(
            Cond::and(vec![Cond::and(vec![x.clone(), y.clone()]), z.clone()]).inlined(),
            "(`a` = 1 and `a` = 2 and `a` = 3)"
        );
        assert_eq!(
            Cond::and(vec![x.clone(), Cond::or(vec![y.clone(), z.clone()])]).inlined(),
            "(`a` = 1 and (`a` = 2 or `a` = 3))"
        );
        assert_eq!(Cond::None.not().inlined(), "not (true)");
        assert_eq!(Cond::and(vec![Cond::True, x.clone()]).inlined(), "(true and `a` = 1)");
        assert_eq!(Cond::and(vec![]).inlined(), "true");
        assert_eq!(Cond::and(vec![x.clone(), Cond::None]).inlined(), "`a` = 1");
        assert_eq!(x.clone().not().not().inlined(), "not (not (`a` = 1))");
        assert_eq!(Cond::True.not().inlined(), "not true");
        assert_eq!(Cond::and(vec![x.clone(), y.clone()]).not().inlined(), "not (`a` = 1 and `a` = 2)");
        let plain = Cond::Plain(Sql::template("json_contains({0}, cast({1} as json))", &[a(), Sql::param(Bind::Text("[1]".into()))]));
        assert_eq!(plain.inlined(), "(json_contains(`a`, cast('[1]' as json)))");
        assert_eq!(plain.clone().not().inlined(), "not (json_contains(`a`, cast('[1]' as json)))");
        assert_eq!(Cond::and(vec![x.clone(), plain.clone()]).inlined(), "(`a` = 1 and (json_contains(`a`, cast('[1]' as json))))");
        assert_eq!(plain.clone().not().not().inlined(), "not (not (json_contains(`a`, cast('[1]' as json))))");
        assert_eq!(a().is_null().not().inlined(), "not (`a` is null)");
        let _ = one();
    }

    #[test]
    fn literals_escape_as_jooq_does() {
        assert_eq!(a().equal(Sql::param(Bind::Text("it's \\ x".into()))).inlined(), "`a` = 'it''s \\\\ x'");
        assert_eq!(Bind::Double(1.5).inline(), "1.5E0");
        assert_eq!(Bind::Float(1.0).inline(), "1E0");
        assert_eq!(Bind::Decimal(Decimal::parse("10.5000").unwrap()).inline(), "10.5000");
    }

    #[test]
    fn selects_render_with_binds() {
        let s = Select::star(Sql::name(&["db", "t"]))
            .filter(a().equal(Sql::param(Bind::Text("x".into()))))
            .order(vec![a().desc()])
            .page(10, 20);
        let (sql, binds) = s.to_sql().render();
        assert_eq!(sql, "select * from `db`.`t` where `a` = ? order by `a` desc limit ? offset ?");
        assert_eq!(binds.len(), 3);
        assert_eq!(
            Select::star(Sql::name(&["db", "t"])).filter(Cond::None).page(10, 0).to_sql().inlined(),
            "select * from `db`.`t` limit 10 offset 0"
        );
    }
}
