"""Writes the oracle's input: the same conditions and aggregates for Java and Rust."""
import json, itertools, sys

ops = ["EQUALS", "LESS_THAN", "GREATER_THAN", "LESS_THAN_EQUAL", "GREATER_THAN_EQUAL", "IS_TRUE", "IS_FALSE",
       "IS_NULL", "BETWEEN", "IN", "LIKE", "STRING_LOOSE_EQUAL", "MATCH", "MATCH_ALL", "TEXT_SEARCH"]
values = [None, 5, -7, 1.5, 3.0, 9007199254740993, "North", "", "it's \\ x", "+91 98", True, "a,b\\,c, d",
          "6ac7d4a11a578c042996bca5", {"city": "Pune"}, ["x", "y"], {"$gt": 1}]

def fc(field, op, value=None, **kw):
    d = {"field": field, "operator": op}
    if value is not None or kw.pop("explicit_null", False):
        d["value"] = value
    d.update(kw)
    return d

filters = []
n = 0
for op in ops:
    for v in values:
        for neg in (False, True):
            c = fc("amount", op, v, negate=neg)
            if op == "BETWEEN":
                c["toValue"] = 10
            filters.append(c)
# a few shapes on top
extra = [
    fc("amount", "BETWEEN", 1),
    fc("amount", "BETWEEN", None, toValue=3),
    fc("s", "IN", None, multiValue=["A", "B", 3]),
    fc("s", "IN", "A", multiValue=[]),
    fc("tags", "MATCH", "red", matchOperator="LIKE"),
    fc("tags", "MATCH", "red", matchOperator="STRING_LOOSE_EQUAL"),
    fc("tags", "MATCH", 5, matchOperator="GREATER_THAN"),
    fc("tags", "MATCH", "b", matchOperator="LESS_THAN_EQUAL"),
    fc("tags", "MATCH", "x", matchOperator="IN"),
    fc("tags", "MATCH_ALL", None, multiValue=["a", "b\"q"]),
    fc("address.city", "EQUALS", "Pune"),
    fc("address.city", "LIKE", "Pu%"),
    fc("address.geo.lat", "GREATER_THAN", 18),
    fc("address.c'ty", "EQUALS", "x"),
    fc("address.tags", "MATCH", "x"),
    fc("other.tags", "MATCH", "x"),
    fc("IFSC Code", "EQUALS", "HDFC"),
    fc("a", "EQUALS", "b", valueField=True),
    fc("_id", "EQUALS", "6ac7d4a11a578c042996bca5"),
    fc("_id", "IN", "6ac7d4a11a578c042996bca5,6ac7d4a11a578c042996bca6"),
    fc("_id", "BETWEEN", "6ac7d4a11a578c042996bca5", toValue="6ac7d4a11a578c042996bca6"),
    fc("owner", "EQUALS", "6ac7d4a11a578c042996bca5"),
    fc("owner", "MATCH", "6ac7d4a11a578c042996bca5"),
    fc("$where", "EQUALS", 1),
    fc("a.$x", "EQUALS", 1),
    fc("title", "TEXT_SEARCH", "southern regions guides"),
    fc("title", "TEXT_SEARCH", "+++ ---"),
    fc("title", "TEXT_SEARCH", "C++ (best) ~thing"),
    {"field": "a"},
    {"field": "a", "operator": None, "value": 1},
]
filters += extra

def cc(op, conds, neg=False):
    return {"operator": op, "conditions": conds, "negate": neg}

groups = [
    cc("AND", [fc("a", "EQUALS", 1), fc("b", "EQUALS", 2)]),
    cc("OR", [fc("a", "EQUALS", 1), fc("b", "EQUALS", 2)]),
    cc("AND", [fc("a", "EQUALS", 1), fc("b", "EQUALS", 2)], True),
    cc("OR", [fc("a", "EQUALS", 1), fc("b", "GREATER_THAN", 2)], True),
    cc("AND", [fc("a", "EQUALS", 1), cc("OR", [fc("b", "EQUALS", 2), fc("c", "IS_NULL")])]),
    cc("AND", [fc("a", "EQUALS", 1), cc("OR", [fc("b", "EQUALS", 2), fc("c", "LIKE", "x")], True)], True),
    cc("AND", []),
    cc("OR", [fc("a", "EQUALS", None), fc("b", "IN", None)]),
    cc("AND", [fc("a", "EQUALS", 1), fc("b", "EQUALS", None)], True),
    cc("AND", [fc("a", "EQUALS", 1), {}]),
    cc("AND", [fc("a", "EQUALS", 1), {"aggregateFunction": "SUM", "condition": {"field": "x", "value": 1}}]),
    cc("AND", [fc("a", "STRING_LOOSE_EQUAL", "x"), fc("tags", "MATCH_ALL", "y")], True),
    {"aggregateFunction": "MAX", "condition": {"field": "x", "value": 1}},
    {"havingConditions": [], "fields": ["x"]},
]
for g in groups:
    filters.append(g)

mysql = []
for i, f in enumerate(filters):
    for mode in ("read", "delete"):
        mysql.append({"name": f"m{i}-{mode}", "condition": f, "mode": mode, "json": ["address", "tags"],
                      "text": ["title", "body"], "stemming": True})
mysql.append({"name": "nostem", "condition": fc("title", "TEXT_SEARCH", "guides"), "json": [], "text": ["title"], "stemming": False})
mysql.append({"name": "notext", "condition": fc("title", "TEXT_SEARCH", "guides"), "json": [], "text": []})
mysql.append({"name": "null", "condition": None})

mongo = [{"name": f"g{i}", "condition": f, "relations": ["owner"]} for i, f in enumerate(filters)]
mongo.append({"name": "null", "condition": None, "relations": []})

def agg(groupBy=None, aggs=None, **kw):
    q = {"aggregations": aggs or [{"function": "COUNT"}]}
    if groupBy is not None:
        q["groupBy"] = groupBy
    q.update(kw)
    return q

aggregates = [
    agg(),
    agg([{"field": "region"}], [{"function": "SUM", "field": "amount", "alias": "total"}, {"function": "COUNT"}]),
    agg([{"field": "region", "alias": "r"}], [{"function": "AVG", "field": "amount"}, {"function": "MIN", "field": "code"},
        {"function": "MAX", "field": "code"}, {"function": "COUNT_DISTINCT", "field": "ticketId", "alias": "deals"},
        {"function": "COUNT", "field": "amount", "alias": "n"}]),
    agg([{"field": "createdAt", "bucket": "MONTH"}]),
    agg([{"field": "ts", "bucket": "DAY", "encoding": "EPOCH_SECONDS"}]),
    agg([{"field": "ts", "bucket": "WEEK", "encoding": "EPOCH_MILLIS", "timezone": "Asia/Kolkata", "alias": "wk"}]),
    agg([{"field": "ts", "bucket": "ISO_WEEK", "encoding": "EPOCH_SECONDS", "timezone": "Asia/Kolkata"}]),
    agg([{"field": "createdAt", "bucket": "QUARTER", "timezone": "America/New_York"}]),
    agg([{"field": "createdAt", "bucket": "YEAR"}, {"field": "region"}]),
    agg([{"field": "createdAt", "bucket": "HOUR"}]),
    agg([{"field": "address.city", "alias": "city"}]),
    agg([{"field": "region"}], [{"function": "SUM", "field": "amount", "alias": "total"}],
        having={"field": "total", "operator": "GREATER_THAN", "value": 100}, sort=[{"property": "total", "direction": "DESC"}],
        size=5000, page=2, condition={"field": "status", "value": "won"}),
    agg([{"field": "region"}], [{"function": "SUM", "field": "address.amount"}], size=0,
        condition={"operator": "AND", "conditions": [{"field": "a", "value": 1}, {"field": "b", "value": None}]}),
]
mysql_aggs = [{"name": f"a{i}", "query": q, "json": ["address"]} for i, q in enumerate(aggregates)]
mongo_aggs = [{"name": f"a{i}", "query": q} for i, q in enumerate(aggregates)]

json.dump({"mysqlFilters": mysql, "mongoFilters": mongo, "mysqlAggregates": mysql_aggs, "mongoAggregates": mongo_aggs},
          open(sys.argv[1], "w"), indent=1)
print(len(mysql), len(mongo), len(mysql_aggs), len(mongo_aggs))
