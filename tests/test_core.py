import unittest

from http_content_security_policy_utils import parse_csp, serialize_csp


class ParseCspTests(unittest.TestCase):
    def test_simple_directive(self):
        self.assertEqual(
            parse_csp("default-src 'self'"),
            {"default-src": ["'self'"]},
        )

    def test_multiple_directives(self):
        header = "default-src 'self'; script-src 'self' https://cdn.example; style-src 'unsafe-inline'"
        self.assertEqual(
            parse_csp(header),
            {
                "default-src": ["'self'"],
                "script-src": ["'self'", "https://cdn.example"],
                "style-src": ["'unsafe-inline'"],
            },
        )

    def test_directive_without_sources(self):
        self.assertEqual(parse_csp("upgrade-insecure-requests"), {"upgrade-insecure-requests": []})

    def test_extra_whitespace_is_tolerated(self):
        header = "  default-src   'self'  ;  script-src  https://cdn.example  "
        self.assertEqual(
            parse_csp(header),
            {
                "default-src": ["'self'"],
                "script-src": ["https://cdn.example"],
            },
        )

    def test_empty_header(self):
        self.assertEqual(parse_csp(""), {})

    def test_trailing_semicolon_ignored(self):
        self.assertEqual(
            parse_csp("default-src 'self';"),
            {"default-src": ["'self'"]},
        )

    def test_duplicate_directive_sources_merged(self):
        # Browsers merge repeated directives from multiple header lines.
        # We keep the first name and append later sources to preserve order.
        header = "script-src 'self'; script-src https://cdn.example"
        self.assertEqual(
            parse_csp(header),
            {"script-src": ["'self'", "https://cdn.example"]},
        )

    def test_directive_names_are_lowercased(self):
        self.assertEqual(
            parse_csp("DEFAULT-SRC 'self'"),
            {"default-src": ["'self'"]},
        )

    def test_source_casing_is_preserved(self):
        header = "script-src 'Nonce-AbC123' https://CDN.Example"
        self.assertEqual(
            parse_csp(header),
            {"script-src": ["'Nonce-AbC123'", "https://CDN.Example"]},
        )


class SerializeCspTests(unittest.TestCase):
    def test_round_trip(self):
        header = "default-src 'self'; script-src 'self' https://cdn.example; style-src 'unsafe-inline'"
        self.assertEqual(serialize_csp(parse_csp(header)), header)

    def test_empty_mapping(self):
        self.assertEqual(serialize_csp({}), "")

    def test_directive_without_sources(self):
        self.assertEqual(serialize_csp({"upgrade-insecure-requests": []}), "upgrade-insecure-requests")

    def test_lowercases_directive_names(self):
        self.assertEqual(
            serialize_csp({"DEFAULT-SRC": ["'self'"]}),
            "default-src 'self'",
        )


if __name__ == "__main__":
    unittest.main()
