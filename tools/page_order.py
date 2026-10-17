"""A Spring `Page`'s own key order, which the parity scripts do not hold against Rust.

Java's Jackson writes a page's properties in the order `getDeclaredMethods` gives its getters,
and that order holds only for one load of the class: a restart or a devtools reload can change
it (seen 2026-10-17, same process: `last` moved ahead of `totalPages`). Rust writes one order
(crates/security/src/web.rs `page_json`). A page whose keys and values match Rust's but come in
another order is EXPECTED, with `NOTE`; everything else about it is still compared.
"""

NOTE = "a page's key order follows Java's getter order, which changes when its classes load again (crates/security/src/web.rs page_json)"


def is_page(v):
    return isinstance(v, dict) and "pageable" in v and "totalElements" in v


def align(java, rust):
    """(java, rust, reordered): Java's page, and its `pageable`, put in Rust's key order when both
    are pages with the same keys in another order; `reordered` says whether that was needed."""
    if not (is_page(java) and is_page(rust)) or set(java) != set(rust):
        return java, rust, False
    reordered = list(java) != list(rust)
    out = {k: java[k] for k in rust}
    pj, pr = java.get("pageable"), rust.get("pageable")
    if isinstance(pj, dict) and isinstance(pr, dict) and set(pj) == set(pr) and list(pj) != list(pr):
        out["pageable"] = {k: pj[k] for k in pr}
        reordered = True
    return out, rust, reordered


if __name__ == "__main__":
    j = {"content": [1], "pageable": {"b": 1, "a": 2}, "last": True, "totalElements": 1}
    r = {"content": [1], "pageable": {"a": 2, "b": 1}, "totalElements": 1, "last": True}
    a, _, moved = align(j, r)
    assert moved and list(a) == list(r) and list(a["pageable"]) == ["a", "b"], a
    assert align(r, r) == (r, r, False)
    assert align({"x": 1}, {"x": 1})[2] is False
    assert align(dict(j, extra=1), r)[2] is False
    print("ok")
