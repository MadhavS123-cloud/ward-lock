"""Medical protect-list. A disease or a medicine is never a personal tag.

The list is local. If every real word in a tagged span is on this list,
the tag is cancelled and the sanitizer leaves the words as written.
Doses and units (650, mg, tablet) do not count as their own words.
"""

from __future__ import annotations

import re

from utils.translit import to_latin

# Diseases, symptoms, and medicines seen on Indian hospital notes.
# Parkinson's, bukhar, Dolo, Ramipril, sugar, and bp are the required ones.
# Hindi spellings are the plain forms produced by utils.translit.
_TERMS = {
    "parkinson", "parkinsons", "parkinsonism", "parkinsan",
    "alzheimer", "alzheimers", "dementia",
    "diabetes", "diabetic", "sugar", "shugar", "madhumeh",
    "hypertension", "hypotension", "bp", "bipi", "raktachap",
    "blood", "pressure", "cholesterol",
    "fever", "bukhar", "bukhaar", "jwar", "jvara", "jvar",
    "dengue", "malaria", "typhoid", "chikungunya", "covid", "influenza",
    "tuberculosis", "asthma", "copd", "pneumonia", "bronchitis",
    "cancer", "tumour", "tumor", "arthritis", "thyroid",
    "hypothyroidism", "hyperthyroidism", "goiter", "goitre",
    "anemia", "anaemia", "thalassemia",
    "migraine", "epilepsy", "stroke", "paralysis",
    "hepatitis", "jaundice", "cirrhosis",
    "diarrhea", "diarrhoea", "dysentery", "constipation", "vomiting",
    "nausea", "acidity", "gastritis", "gerd", "ulcer",
    "cough", "cold", "pain", "abdomen", "abdominal", "headache", "bodyache", "weakness",
    "dizziness", "chakkar", "khansi", "dard", "darda",
    "infection", "inflammation", "sepsis", "allergy",
    "fracture", "injury", "wound",
    "kidney", "ckd", "liver", "cardiac", "angina", "heart",
    "uti", "pcos", "pcod", "pregnancy",
    "disease", "disorder", "syndrome", "chronic", "acute",
    "dolo", "paracetamol", "crocin", "calpol", "combiflam", "brufen",
    "ibuprofen", "diclofenac", "meftal", "flexon", "sumo", "tramadol",
    "ramipril", "enalapril", "lisinopril", "amlodipine", "telmisartan",
    "losartan", "olmesartan", "metoprolol", "atenolol", "bisoprolol",
    "nifedipine", "metformin", "glimepiride", "gliclazide", "insulin",
    "thyroxine", "levothyroxine", "thyronorm",
    "atorvastatin", "rosuvastatin", "aspirin", "clopidogrel", "warfarin",
    "ecosprin", "pantoprazole", "omeprazole", "rabeprazole", "pantop",
    "domperidone", "ondansetron", "cetirizine", "levocetirizine",
    "montelukast", "salbutamol", "azithromycin", "amoxicillin",
    "amoxycillin", "cefixime", "ceftriaxone", "ofloxacin", "ciprofloxacin",
    "levofloxacin", "metronidazole", "albendazole", "doxycycline",
    "levodopa", "carbidopa", "syndopa", "gabapentin", "pregabalin",
    "furosemide", "spironolactone", "hydrochlorothiazide", "torsemide",
    "digoxin", "vitamin", "multivitamin", "calcium", "folic", "folate",
    "ors", "zinc",
}

# Ignored inside a span so "Dolo 650" and "Ramipril 5 mg" stay protected.
_UNITS = {
    "mg", "mcg", "gm", "g", "ml", "iu", "kg", "l", "tab", "tablet",
    "cap", "capsule", "inj", "injection", "syp", "syrup",
    "od", "bd", "tds", "hs", "sos", "prn", "stat",
}

_WORD = re.compile(r"[0-9A-Za-z\u0900-\u097F]+(?:['’][A-Za-z]+)?")


def is_medical_token(token: str) -> bool:
    """True when this one word is a disease, symptom, or medicine."""
    key = _key(token)
    return bool(key) and key in _TERMS


def is_medical_span(text: str) -> bool:
    """True when the tag covers only medical words, doses, and units."""
    keys = [_key(word) for word in _WORD.findall(text)]
    meaningful = [key for key in keys if key and not key.isdigit() and key not in _UNITS]
    return bool(meaningful) and all(key in _TERMS for key in meaningful)


def cancel_protected(findings: list[dict]) -> list[dict]:
    """Drop any tag that landed on a medical term."""
    return [item for item in findings if not is_medical_span(str(item.get("text") or ""))]


def _key(token: str) -> str:
    text = token.replace("’", "'").replace("‘", "'")
    text = to_latin(text).lower()
    return re.sub(r"[^a-z0-9]", "", text)
