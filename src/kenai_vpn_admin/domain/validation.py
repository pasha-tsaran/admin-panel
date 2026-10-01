import re
import unicodedata

SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def normalize_username(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().casefold()


def validate_slug(value: str) -> str:
    normalized = value.strip().lower()
    if not SLUG_PATTERN.fullmatch(normalized):
        raise ValueError("Use lowercase Latin letters, digits, and single hyphens")
    if len(normalized) > 64:
        raise ValueError("Slug must not exceed 64 characters")
    return normalized


def validate_display_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not 1 <= len(normalized) <= 120:
        raise ValueError("Display name must contain 1 to 120 characters")
    return normalized
