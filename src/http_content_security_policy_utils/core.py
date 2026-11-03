"""Core parsing logic for the Content-Security-Policy header.

Design decisions:
- The grammar is whitespace-delimited. Directives are separated by semicolons.
- Directive names are case-insensitive per the spec, so we lowercase them.
- Source lists are case-sensitive in practice (URLs, nonces, hashes), so we
  preserve their original casing.
- Duplicate directives are merged: the first occurrence wins for the directive
  name, but all source tokens from duplicates are appended in order. This
  matches how browsers combine multiple policy headers.
- Empty directives (e.g. trailing semicolon) are ignored.
- A directive with no sources maps to an empty list.
"""

from __future__ import annotations


def parse_csp(header: str) -> dict[str, list[str]]:
    """Parse a Content-Security-Policy header into a directive mapping.

    Args:
        header: The raw header value, e.g.
            "default-src 'self'; script-src 'self' https://cdn.example"

    Returns:
        A dict mapping lowercased directive names to lists of source tokens.
        Directives with no sources map to an empty list.
    """
    result: dict[str, list[str]] = {}

    for part in header.split(";"):
        tokens = part.split()
        if not tokens:
            continue

        name = tokens[0].lower()
        sources = tokens[1:]

        if name in result:
            result[name].extend(sources)
        else:
            result[name] = sources

    return result


def serialize_csp(directives: dict[str, list[str]]) -> str:
    """Serialize a directive mapping back into a header string.

    Round-trips with :func:`parse_csp` for the canonical form produced by
    parsing: directive names are lowercased, sources keep their order, and
    directives are joined with ``; ``.

    Args:
        directives: Mapping of directive names to source lists.

    Returns:
        A header string. Empty mapping yields an empty string.
    """
    parts = []
    for name, sources in directives.items():
        directive = name.lower()
        if sources:
            parts.append(directive + " " + " ".join(sources))
        else:
            parts.append(directive)
    return "; ".join(parts)
