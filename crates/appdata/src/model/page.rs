//! Spring's `PageImpl`, built the way `PageableExecutionUtils.getPage` builds it and written
//! the way Jackson writes it.

use super::query::Pageable;
use crate::value::{Document, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct Page<T> {
    pub content: Vec<T>,
    pub pageable: Pageable,
    pub total: i64,
}

impl<T> Page<T> {
    /// `PageableExecutionUtils.getPage(content, pageable, totalSupplier)`.
    ///
    /// The total is only consulted when the content cannot answer it; the callers still
    /// compute it first, as the Java engines run the count before building the page.
    pub fn of(content: Vec<T>, pageable: Pageable, total: impl FnOnce() -> i64) -> Page<T> {
        let size = content.len() as i64;
        let offset = pageable.offset();
        let page_size = pageable.page_size();

        let total = if offset == 0 {
            if page_size > size {
                size
            } else {
                total()
            }
        } else if size != 0 && page_size > size {
            offset + size
        } else {
            total()
        };

        Page::with_total(content, pageable, total)
    }

    /// `new PageImpl(content, pageable, total)`, which corrects a total the content
    /// proves too small.
    pub fn with_total(content: Vec<T>, pageable: Pageable, total: i64) -> Page<T> {
        let size = content.len() as i64;
        let total = if size != 0 && pageable.offset() + pageable.page_size() > total {
            pageable.offset() + size
        } else {
            total
        };
        Page { content, pageable, total }
    }

    pub fn total_pages(&self) -> i64 {
        let size = self.pageable.page_size();
        if size == 0 {
            1
        } else {
            (self.total + size - 1) / size
        }
    }

    pub fn number(&self) -> i64 {
        self.pageable.page as i64
    }

    pub fn is_first(&self) -> bool {
        self.number() == 0
    }

    pub fn is_last(&self) -> bool {
        self.number() + 1 >= self.total_pages()
    }

    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        Page { content: self.content.into_iter().map(f).collect(), pageable: self.pageable, total: self.total }
    }
}

impl Page<Document> {
    /// The JSON `PageImpl` serialises to, in the order Jackson writes its properties. The
    /// services' ObjectMapper leaves out empty properties (`NON_EMPTY`), so an empty page
    /// has no `content` at all.
    pub fn to_value(&self) -> Value {
        let mut d = Document::new();
        if !self.content.is_empty() {
            d.insert(
                "content".into(),
                Value::Array(self.content.iter().cloned().map(Value::Object).collect()),
            );
        }
        d.insert("pageable".into(), self.pageable.to_value());
        d.insert("last".into(), Value::Bool(self.is_last()));
        d.insert("totalPages".into(), Value::Int(self.total_pages()));
        d.insert("totalElements".into(), Value::Int(self.total));
        d.insert("first".into(), Value::Bool(self.is_first()));
        d.insert("numberOfElements".into(), Value::Int(self.content.len() as i64));
        d.insert("sort".into(), self.pageable.sort.to_value());
        d.insert("size".into(), Value::Int(self.pageable.page_size()));
        d.insert("number".into(), Value::Int(self.number()));
        d.insert("empty".into(), Value::Bool(self.content.is_empty()));
        Value::Object(d)
    }

    pub fn to_java_json(&self) -> String {
        self.to_value().to_java_json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::query::Sort;

    #[test]
    fn a_short_first_page_is_its_own_total() {
        let p = Page::of(vec![1, 2], Pageable::of(0, 10, Sort::unsorted()).unwrap(), || 99);
        assert_eq!(p.total, 2);
        let p = Page::of(vec![1, 2], Pageable::of(0, 2, Sort::unsorted()).unwrap(), || 5);
        assert_eq!(p.total, 5);
        assert_eq!(p.total_pages(), 3);
        assert!(!p.is_last());
        let p = Page::of(vec![1], Pageable::of(2, 2, Sort::unsorted()).unwrap(), || 99);
        assert_eq!(p.total, 5);
        let p: Page<i32> = Page::of(vec![], Pageable::of(3, 2, Sort::unsorted()).unwrap(), || 5);
        assert_eq!(p.total, 5);
    }
}
