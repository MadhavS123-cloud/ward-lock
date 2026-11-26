"""Romanize Hindi names to the plain spelling used in English records.

रमेश कुमार becomes ramesh kumar. Latin letters are left as they are, so an
English name still normalizes to the same string and keeps the same PSN- id.

The inherent schwa is dropped at the end of a word (कुमार -> kumar). It is
kept when the word ends in a conjunct (कृष्ण -> krishna). Long vowels fold
to short ones (ा -> a, ी -> i) so the result matches ordinary spelling.
"""

from __future__ import annotations

_VIRAMA = "\u094d"
_NUKTA = "\u093c"
_ANUSVARA = "\u0902"
_CHANDRA = "\u0901"
_VISARGA = "\u0903"
# Inherent "a". A written ा is "aa" and is not deleted with the schwa.
_SCHWA = "\u0001"

_CONSONANTS = {
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "ng",
    "च": "ch", "छ": "chh", "ज": "j", "झ": "jh", "ञ": "ny",
    "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n",
    "त": "t", "थ": "th", "द": "d", "ध": "dh", "न": "n",
    "प": "p", "फ": "ph", "ब": "b", "भ": "bh", "म": "m",
    "य": "y", "र": "r", "ल": "l", "व": "v",
    "श": "sh", "ष": "sh", "स": "s", "ह": "h",
    "ळ": "l", "ऱ": "r", "ऩ": "n", "ऴ": "l",
}

# A nukta (़) changes the consonant. Precomposed forms are one code point.
_NUKTA_ALT = {
    "क": "q", "ख": "kh", "ग": "g", "ज": "z", "ड": "d", "ढ": "dh",
    "फ": "f", "त": "t", "य": "y", "न": "n",
}
_PRECOMPOSED = {
    "\u0958": "q", "\u0959": "kh", "\u095a": "g", "\u095b": "z",
    "\u095c": "d", "\u095d": "dh", "\u095e": "f", "\u095f": "y",
}

_VOWELS = {
    "अ": "a", "आ": "aa", "इ": "i", "ई": "ii", "उ": "u", "ऊ": "uu",
    "ऋ": "ri", "ॠ": "ri", "ऌ": "li", "ए": "e", "ऐ": "ai",
    "ओ": "o", "औ": "au", "ऑ": "o", "ऍ": "e", "ऒ": "o",
}
_MATRA = {
    "ा": "aa", "ि": "i", "ी": "ii", "ु": "u", "ू": "uu",
    "ृ": "ri", "ॄ": "ri", "ॢ": "ri", "ॣ": "ri",
    "े": "e", "ै": "ai", "ो": "o", "ौ": "au",
    "ॉ": "o", "ॅ": "e", "ॊ": "o",
}

_LABIAL = set("पफबभम")
_DIGITS = {chr(0x0966 + i): str(i) for i in range(10)}


def to_latin(text: str) -> str:
    """Return text with Devanagari names rewritten in plain ASCII."""
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char in _DIGITS:
            out.append(_DIGITS[char])
            index += 1
            continue
        if _is_letter(char):
            end = index + 1
            while end < len(text) and (_is_letter(text[end]) or text[end] in "\u200c\u200d"):
                end += 1
            out.append(_word(text[index:end]))
            index = end
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _is_letter(char: str) -> bool:
    code = ord(char)
    if 0x0900 <= code <= 0x0954:
        return True
    if 0x0958 <= code <= 0x095F:
        return True
    return 0x097B <= code <= 0x097F


def _cons(char: str) -> str | None:
    if char in _PRECOMPOSED:
        return _PRECOMPOSED[char]
    return _CONSONANTS.get(char)


def _word(text: str) -> str:
    """Romanize one Devanagari word."""
    syllables: list[tuple[str, str, str, bool]] = []
    index = 0
    size = len(text)
    while index < size:
        char = text[index]
        if char in "\u200c\u200d":
            index += 1
            continue
        if char in _VOWELS:
            vowel = _VOWELS[char]
            index += 1
            nasal, index = _nasal(text, index)
            syllables.append(("", vowel, nasal, False))
            continue
        if _cons(char) is None:
            index += 1
            continue
        parts: list[str] = []
        count = 0
        while index < size:
            current = text[index]
            roman = _cons(current)
            if roman is None:
                break
            index += 1
            count += 1
            if index < size and text[index] == _NUKTA:
                roman = _NUKTA_ALT.get(current, roman)
                index += 1
            parts.append(roman)
            if index < size and text[index] == _VIRAMA:
                index += 1
                if index >= size or _cons(text[index]) is None:
                    syllables.append((_join(parts), "", "", count > 1))
                    parts = []
                    break
                continue
            break
        if not parts:
            continue
        vowel = _SCHWA
        if index < size and text[index] in _MATRA:
            vowel = _MATRA[text[index]]
            index += 1
        nasal, index = _nasal(text, index)
        syllables.append((_join(parts), vowel, nasal, count > 1))
    return _render(syllables)


def _join(parts: list[str]) -> str:
    """Join a conjunct. ज्ञ is gya, the spelling used in names such as Gyan."""
    out: list[str] = []
    index = 0
    while index < len(parts):
        if parts[index] == "j" and index + 1 < len(parts) and parts[index + 1] == "ny":
            out.append("gy")
            index += 2
            continue
        out.append(parts[index])
        index += 1
    return "".join(out)


def _nasal(text: str, index: int) -> tuple[str, int]:
    """Read ं, ँ, or ः. सिंह uses ng before ह so the word is singh."""
    if index >= len(text) or text[index] not in (_ANUSVARA, _CHANDRA, _VISARGA):
        return "", index
    mark = text[index]
    index += 1
    if mark == _VISARGA:
        return "h", index
    nxt = _next_cons(text, index)
    if nxt == "ह":
        return "ng", index
    if nxt in _LABIAL:
        return "m", index
    return "n", index


def _next_cons(text: str, index: int) -> str:
    while index < len(text):
        if _cons(text[index]) is not None:
            return text[index]
        if text[index] in _VOWELS or not _is_letter(text[index]):
            return ""
        index += 1
    return ""


def _render(syllables: list[tuple[str, str, str, bool]]) -> str:
    if not syllables:
        return ""
    body, vowel, nasal, cluster = syllables[-1]
    earlier = any(item[1] for item in syllables[:-1])
    # Word-final schwa goes (kumar, ramesh). A final conjunct keeps it (krishna).
    if vowel == _SCHWA and not cluster and earlier:
        syllables[-1] = (body, "", nasal, cluster)
    parts: list[str] = []
    for body, vowel, nasal, _cluster in syllables:
        parts.append(body + _fold(vowel) + nasal)
    return "".join(parts)


def _fold(vowel: str) -> str:
    if vowel == _SCHWA or vowel == "aa":
        return "a"
    if vowel == "ii":
        return "i"
    if vowel == "uu":
        return "u"
    return vowel
