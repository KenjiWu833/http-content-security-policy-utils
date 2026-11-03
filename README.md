# http-content-security-policy-utils

Parse and serialize the HTTP `Content-Security-Policy` header into a structured mapping of directives and source lists.

```python
from http_content_security_policy_utils import parse_csp, serialize_csp

header = "default-src 'self'; script-src 'self' https://cdn.example; style-src 'unsafe-inline'"
directives = parse_csp(header)
# {
#   'default-src': ["'self'"],
#   'script-src': ["'self'", 'https://cdn.example'],
#   'style-src': ["'unsafe-inline'"],
# }

serialize_csp(directives)
# "default-src 'self'; script-src 'self' https://cdn.example; style-src 'unsafe-inline'"
```

The library exposes exactly two functions:

- `parse_csp(header: str) -> dict[str, list[str]]`
- `serialize_csp(directives: dict[str, list[str]]) -> str`

## Why this exists

CSP headers are often built by concatenating strings, and the resulting policy is hard to inspect or modify programmatically. This library turns the header into a plain dict so callers can add, remove, or inspect directives without string surgery. The trade-off is that it does not validate policy semantics: it does not check that source expressions are well-formed, that nonces are base64, or that directives are known. It is a parser, not a policy engine. That keeps the surface small and the behaviour predictable.

## The awkward edge

Directive names are case-insensitive per the specification, but source expressions are not. `parse_csp` lowercases directive names and preserves source tokens exactly as written. It also merges duplicate directives: if the same directive appears more than once, the first occurrence supplies the name and all source tokens are appended in the order they appear. This matches how browsers combine multiple `Content-Security-Policy` header lines into one policy.

## Notes

- Empty directives (for example, a trailing semicolon) are ignored.
- A directive with no sources maps to an empty list.
- `serialize_csp` round-trips the canonical form produced by `parse_csp`.
- No third-party dependencies; standard library only.
