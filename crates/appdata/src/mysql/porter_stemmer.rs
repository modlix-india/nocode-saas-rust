//! `PorterStemmer`: Porter (1980) stemming for MySQL full-text search, which InnoDB does
//! not stem on its own. Kept in the reference implementation's shape (a buffer and two
//! cursors) so it can be checked against the paper, as the Java one is.

const BOOLEAN_OPERATORS: &str = "+-><()~*\"@";

/// One token, stemmed and lowercased; returned unchanged when shorter than three letters
/// or when it holds anything but letters.
pub fn stem(word: &str) -> String {
    let lower = word.trim().to_lowercase();
    if lower.chars().count() < 3 {
        return lower;
    }
    if !lower.chars().all(char::is_alphabetic) {
        return lower;
    }
    Work::new(&lower).stem()
}

/// The longest prefix of `word` its stem still agrees with.
pub fn search_prefix(word: &str) -> String {
    let token = word.trim().to_lowercase();
    if token.is_empty() {
        return String::new();
    }
    let stemmed: Vec<char> = stem(&token).chars().collect();
    let chars: Vec<char> = token.chars().collect();
    let mut i = 0;
    while i < stemmed.len() && i < chars.len() && stemmed[i] == chars[i] {
        i += 1;
    }
    chars[..i].iter().collect()
}

/// A whole query, split on anything that is not a letter or digit, as search prefixes.
pub fn search_prefixes(query: &str) -> Vec<String> {
    let mut out = Vec::new();
    if query.trim().is_empty() {
        return out;
    }
    for raw in query.split(|c: char| !(c.is_alphabetic() || c.is_numeric())) {
        let token: String = raw.chars().filter(|c| !BOOLEAN_OPERATORS.contains(*c)).collect();
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let prefix = search_prefix(token);
        if !prefix.is_empty() {
            out.push(prefix);
        }
    }
    out
}

struct Work {
    b: Vec<char>,
    k: usize,
    j: isize,
}

impl Work {
    fn new(word: &str) -> Work {
        let mut b: Vec<char> = word.chars().collect();
        let k = b.len() - 1;
        b.extend(std::iter::repeat_n('\0', 4));
        Work { b, k, j: 0 }
    }

    fn stem(mut self) -> String {
        self.step1ab();
        if self.k > 0 {
            self.step1c();
            self.step2();
            self.step3();
            self.step4();
            self.step5();
        }
        self.b[..=self.k].iter().collect()
    }

    fn consonant(&self, i: usize) -> bool {
        match self.b[i] {
            'a' | 'e' | 'i' | 'o' | 'u' => false,
            'y' => i == 0 || !self.consonant(i - 1),
            _ => true,
        }
    }

    /// Porter's "m": consonant-vowel sequences in b[0..=j].
    fn measure(&self) -> usize {
        let j = self.j;
        let mut n = 0;
        let mut i: isize = 0;
        loop {
            if i > j {
                return n;
            }
            if !self.consonant(i as usize) {
                break;
            }
            i += 1;
        }
        i += 1;
        loop {
            loop {
                if i > j {
                    return n;
                }
                if self.consonant(i as usize) {
                    break;
                }
                i += 1;
            }
            i += 1;
            n += 1;
            loop {
                if i > j {
                    return n;
                }
                if !self.consonant(i as usize) {
                    break;
                }
                i += 1;
            }
            i += 1;
        }
    }

    fn vowel_in_stem(&self) -> bool {
        (0..=self.j).any(|i| i >= 0 && !self.consonant(i as usize))
    }

    fn double_consonant(&self, i: isize) -> bool {
        if i < 1 {
            return false;
        }
        let i = i as usize;
        if self.b[i] != self.b[i - 1] {
            return false;
        }
        self.consonant(i)
    }

    fn cvc(&self, i: isize) -> bool {
        if i < 2 {
            return false;
        }
        let i = i as usize;
        if !self.consonant(i) || self.consonant(i - 1) || !self.consonant(i - 2) {
            return false;
        }
        !matches!(self.b[i], 'w' | 'x' | 'y')
    }

    fn ends(&mut self, s: &str) -> bool {
        let chars: Vec<char> = s.chars().collect();
        let length = chars.len() as isize;
        let offset = self.k as isize - length + 1;
        if offset < 0 {
            return false;
        }
        for (i, c) in chars.iter().enumerate() {
            if self.b[offset as usize + i] != *c {
                return false;
            }
        }
        self.j = self.k as isize - length;
        true
    }

    fn set_to(&mut self, s: &str) {
        let chars: Vec<char> = s.chars().collect();
        let start = (self.j + 1) as usize;
        for (i, c) in chars.iter().enumerate() {
            if start + i >= self.b.len() {
                self.b.push(*c);
            } else {
                self.b[start + i] = *c;
            }
        }
        self.k = (self.j + chars.len() as isize) as usize;
    }

    fn replace_if_measured(&mut self, s: &str) {
        if self.measure() > 0 {
            self.set_to(s);
        }
    }

    fn step1ab(&mut self) {
        if self.b[self.k] == 's' {
            if self.ends("sses") || self.ends("ies") {
                self.k -= 2;
            } else if self.k >= 1 && self.b[self.k - 1] != 's' {
                self.k -= 1;
            }
        }

        if self.ends("eed") {
            if self.measure() > 0 {
                self.k -= 1;
            }
            return;
        }

        if (self.ends("ed") || self.ends("ing")) && self.vowel_in_stem() {
            self.k = self.j as usize;

            if self.ends("at") {
                self.set_to("ate");
            } else if self.ends("bl") {
                self.set_to("ble");
            } else if self.ends("iz") {
                self.set_to("ize");
            } else if self.double_consonant(self.k as isize) {
                self.k -= 1;
                let ch = self.b[self.k];
                if ch == 'l' || ch == 's' || ch == 'z' {
                    self.k += 1;
                }
            } else if self.measure() == 1 && self.cvc(self.k as isize) {
                self.set_to("e");
            }
        }
    }

    fn step1c(&mut self) {
        if self.ends("y") && self.vowel_in_stem() {
            self.b[self.k] = 'i';
        }
    }

    fn step2(&mut self) {
        if self.k == 0 {
            return;
        }
        match self.b[self.k - 1] {
            'a' => {
                if self.ends("ational") {
                    self.replace_if_measured("ate");
                } else if self.ends("tional") {
                    self.replace_if_measured("tion");
                }
            }
            'c' => {
                if self.ends("enci") {
                    self.replace_if_measured("ence");
                } else if self.ends("anci") {
                    self.replace_if_measured("ance");
                }
            }
            'e' => {
                if self.ends("izer") {
                    self.replace_if_measured("ize");
                }
            }
            'l' => {
                if self.ends("bli") {
                    self.replace_if_measured("ble");
                } else if self.ends("alli") {
                    self.replace_if_measured("al");
                } else if self.ends("entli") {
                    self.replace_if_measured("ent");
                } else if self.ends("eli") {
                    self.replace_if_measured("e");
                } else if self.ends("ousli") {
                    self.replace_if_measured("ous");
                }
            }
            'o' => {
                if self.ends("ization") {
                    self.replace_if_measured("ize");
                } else if self.ends("ation") || self.ends("ator") {
                    self.replace_if_measured("ate");
                }
            }
            's' => {
                if self.ends("alism") {
                    self.replace_if_measured("al");
                } else if self.ends("iveness") {
                    self.replace_if_measured("ive");
                } else if self.ends("fulness") {
                    self.replace_if_measured("ful");
                } else if self.ends("ousness") {
                    self.replace_if_measured("ous");
                }
            }
            't' => {
                if self.ends("aliti") {
                    self.replace_if_measured("al");
                } else if self.ends("iviti") {
                    self.replace_if_measured("ive");
                } else if self.ends("biliti") {
                    self.replace_if_measured("ble");
                }
            }
            'g' => {
                if self.ends("logi") {
                    self.replace_if_measured("log");
                }
            }
            _ => {}
        }
    }

    fn step3(&mut self) {
        match self.b[self.k] {
            'e' => {
                if self.ends("icate") {
                    self.replace_if_measured("ic");
                } else if self.ends("ative") {
                    self.replace_if_measured("");
                } else if self.ends("alize") {
                    self.replace_if_measured("al");
                }
            }
            'i' => {
                if self.ends("iciti") {
                    self.replace_if_measured("ic");
                }
            }
            'l' => {
                if self.ends("ical") {
                    self.replace_if_measured("ic");
                } else if self.ends("ful") {
                    self.replace_if_measured("");
                }
            }
            's' => {
                if self.ends("ness") {
                    self.replace_if_measured("");
                }
            }
            _ => {}
        }
    }

    fn step4(&mut self) {
        if self.k == 0 {
            return;
        }
        let matched = match self.b[self.k - 1] {
            'a' => self.ends("al"),
            'c' => self.ends("ance") || self.ends("ence"),
            'e' => self.ends("er"),
            'i' => self.ends("ic"),
            'l' => self.ends("able") || self.ends("ible"),
            'n' => self.ends("ant") || self.ends("ement") || self.ends("ment") || self.ends("ent"),
            'o' => {
                (self.ends("ion") && self.j >= 0 && matches!(self.b[self.j as usize], 's' | 't'))
                    || self.ends("ou")
            }
            's' => self.ends("ism"),
            't' => self.ends("ate") || self.ends("iti"),
            'u' => self.ends("ous"),
            'v' => self.ends("ive"),
            'z' => self.ends("ize"),
            _ => false,
        };
        if matched && self.measure() > 1 {
            self.k = self.j as usize;
        }
    }

    fn step5(&mut self) {
        self.j = self.k as isize;
        if self.b[self.k] == 'e' {
            let m = self.measure();
            if m > 1 || (m == 1 && !self.cvc(self.k as isize - 1)) {
                self.k -= 1;
            }
        }
        if self.b[self.k] == 'l' && self.double_consonant(self.k as isize) {
            self.j = self.k as isize;
            if self.measure() > 1 {
                self.k -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLISHED: [(&str, &str); 80] = [
        ("caresses", "caress"), ("ponies", "poni"), ("ties", "ti"), ("caress", "caress"), ("cats", "cat"),
        ("feed", "feed"), ("agreed", "agre"), ("plastered", "plaster"), ("bled", "bled"), ("motoring", "motor"),
        ("sing", "sing"), ("conflated", "conflat"), ("troubled", "troubl"), ("sized", "size"), ("hopping", "hop"),
        ("tanned", "tan"), ("falling", "fall"), ("hissing", "hiss"), ("fizzed", "fizz"), ("failing", "fail"),
        ("filing", "file"), ("happy", "happi"), ("sky", "sky"), ("relational", "relat"), ("conditional", "condit"),
        ("valenci", "valenc"), ("digitizer", "digit"), ("conformabli", "conform"), ("radicalli", "radic"),
        ("differentli", "differ"), ("analogousli", "analog"), ("predication", "predic"), ("operator", "oper"),
        ("feudalism", "feudal"), ("decisiveness", "decis"), ("hopefulness", "hope"), ("formaliti", "formal"),
        ("sensitiviti", "sensit"), ("triplicate", "triplic"), ("formative", "form"), ("formalize", "formal"),
        ("electriciti", "electr"), ("electrical", "electr"), ("hopeful", "hope"), ("goodness", "good"),
        ("revival", "reviv"), ("allowance", "allow"), ("inference", "infer"), ("airliner", "airlin"),
        ("gyroscopic", "gyroscop"), ("adjustable", "adjust"), ("defensible", "defens"), ("irritant", "irrit"),
        ("replacement", "replac"), ("adjustment", "adjust"), ("dependent", "depend"), ("adoption", "adopt"),
        ("homologou", "homolog"), ("communism", "commun"), ("activate", "activ"), ("angulariti", "angular"),
        ("homologous", "homolog"), ("effective", "effect"), ("bowdlerize", "bowdler"), ("probate", "probat"),
        ("rate", "rate"), ("cease", "ceas"), ("controll", "control"), ("roll", "roll"), ("", ""), ("a", "a"),
        ("is", "is"), ("c3po", "c3po"), ("  GUIDES  ", "guid"), ("Guides", "guid"), ("quarterly", "quarterli"),
        ("guides", "guid"), ("generalization", "gener"), ("oscillators", "oscil"), ("running", "run"),
    ];

    #[test]
    fn the_published_examples() {
        for (word, expected) in PUBLISHED {
            assert_eq!(stem(word), expected, "{word}");
        }
    }

    #[test]
    fn what_the_search_path_depends_on() {
        assert_eq!(stem("guide"), stem("guides"));
        assert_eq!(stem("plan"), stem("planning"));
        assert_eq!(stem("expansion"), stem("expansions"));
        assert!(!"quarterly".starts_with(&stem("quarterly")));
        for w in ["guides", "planning", "expansions", "quarterly", "revenues", "reporting", "happy"] {
            assert!(w.starts_with(&search_prefix(w)), "{w}");
        }
        assert!("guide".starts_with(&search_prefix("guides")));
        assert!("plans".starts_with(&search_prefix("planning")));
        assert!("expansion".starts_with(&search_prefix("expansions")));
        for w in ["caresses", "ponies", "plastered", "formalize", "adjustable"] {
            let once = stem(w);
            assert_eq!(stem(&once), once, "{w}");
        }
    }

    #[test]
    fn queries() {
        assert_eq!(search_prefixes("southern regions"), vec!["southern", "region"]);
        for term in search_prefixes("C++ >best< (thing) ~x* \"quoted\" a@b") {
            for ch in "+-><()~*\"@".chars() {
                assert!(!term.contains(ch), "{term}");
            }
        }
        assert!(search_prefixes("+++ --- ***").is_empty());
    }
}
