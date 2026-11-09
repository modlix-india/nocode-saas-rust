"""Formats a Word template's field can ask for (`{{ x|inr }}`), so a builder's clause reads the way
their lawyer wrote it. A value a format cannot read (text where a number is expected, a date in
another shape) is shown as it is, never an error: a document must still be made.

- `inr`: 1,42,80,000.00 (Indian grouping); `inr0`: 1,42,80,000
- `words`: Fourteen Lakh Twenty Eight Thousand (Indian words; paise when there are any)
- `num_words`: 1 (One)
- `date_dmy`: 09-11-2026; `date_long`: 9 November 2026;
  `date_words`: 9th Day of November, Two Thousand Twenty-Six
"""

import datetime
import re
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

ONES = ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Eleven", "Twelve",
        "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen"]
TENS = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
          "November", "December"]


def _number(v):
    if isinstance(v, bool) or v is None:
        return None
    try:
        return Decimal(str(v).replace(",", "").strip())
    except InvalidOperation:
        return None


def _group_indian(n):
    s = str(n)
    if len(s) <= 3:
        return s
    head, tail = s[:-3], s[-3:]
    parts = []
    while len(head) > 2:
        parts.insert(0, head[-2:])
        head = head[:-2]
    if head:
        parts.insert(0, head)
    return ",".join(parts + [tail])


def inr(v, places=2):
    d = _number(v)
    if d is None:
        return v
    q = d.quantize(Decimal(1) if places == 0 else Decimal("0.01"), rounding=ROUND_HALF_UP)
    sign = "-" if q < 0 else ""
    whole, _, frac = str(abs(q)).partition(".")
    return sign + _group_indian(int(whole)) + (("." + frac) if places else "")


def inr0(v):
    return inr(v, 0)


def _below_hundred(n):
    return ONES[n] if n < 20 else TENS[n // 10] + ("" if n % 10 == 0 else " " + ONES[n % 10])


def _below_thousand(n):
    h, r = divmod(n, 100)
    out = []
    if h:
        out.append(ONES[h] + " Hundred")
    if r:
        out.append(_below_hundred(r))
    return " ".join(out)


def indian_words(n):
    n = int(n)
    if n == 0:
        return "Zero"
    out = []
    for name, size in (("Crore", 10_000_000), ("Lakh", 100_000), ("Thousand", 1000)):
        k, n = divmod(n, size)
        if k:
            out.append((indian_words(k) if k >= 100 else _below_hundred(k)) + " " + name)
    if n:
        out.append(_below_thousand(n))
    return " ".join(out)


def words(v):
    d = _number(v)
    if d is None:
        return v
    d = abs(d).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    whole, paise = int(d), int((d - int(d)) * 100)
    text = indian_words(whole)
    return text + (f" and {_below_hundred(paise)} Paise" if paise else "")


def num_words(v):
    d = _number(v)
    if d is None or d != d.to_integral_value():
        return v
    return f"{int(d)} ({indian_words(abs(int(d)))})"


def _date(v):
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v if isinstance(v, datetime.date) else v.date()
    m = re.match(r"^\s*(\d{4})-(\d{2})-(\d{2})", str(v or ""))
    if m:
        try:
            return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None
    m = re.match(r"^\s*(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})\s*$", str(v or ""))
    if m:
        try:
            return datetime.date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
        except ValueError:
            return None
    return None


def _ordinal(n):
    return f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def date_dmy(v):
    d = _date(v)
    return d.strftime("%d-%m-%Y") if d else v


def date_long(v):
    d = _date(v)
    return f"{d.day} {MONTHS[d.month - 1]} {d.year}" if d else v


def _year_words(y):
    head, tail = divmod(y, 100)
    if y >= 2000 and y < 2100:
        return "Two Thousand" + ("" if tail == 0 else " " + _below_hundred(tail).replace(" ", "-"))
    return indian_words(y)


def date_words(v):
    d = _date(v)
    return f"{_ordinal(d.day)} Day of {MONTHS[d.month - 1]}, {_year_words(d.year)}" if d else v


ALL = {"inr": inr, "inr0": inr0, "words": words, "num_words": num_words,
       "date_dmy": date_dmy, "date_long": date_long, "date_words": date_words}
