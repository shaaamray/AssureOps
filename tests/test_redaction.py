import pytest

from assureops.redaction import REDACTED, looks_like_secret, redact


class TestKeyNameRedaction:
    """A random password matches no pattern, so key names must be covered too."""

    @pytest.mark.parametrize(
        "key", ["password", "Password", "client_secret", "api_key", "apiKey",
                "authorization", "token", "private_key", "credential", "cookie"]
    )
    def test_redacts_by_key_name(self, key):
        assert redact({key: "xK9#mQ2vLp"})[key] == REDACTED

    def test_redacts_nested_keys(self):
        data = {"azure": {"tenant": "abc", "client_secret": "not-a-token-shape"}}
        assert redact(data)["azure"]["client_secret"] == REDACTED
        assert redact(data)["azure"]["tenant"] == "abc"

    def test_redacts_inside_lists(self):
        data = {"items": [{"password": "plain"}, {"safe": "value"}]}
        result = redact(data)
        assert result["items"][0]["password"] == REDACTED
        assert result["items"][1]["safe"] == "value"

    def test_leaves_ordinary_keys_alone(self):
        assert redact({"vendor": "acme", "score": 0.9}) == {"vendor": "acme", "score": 0.9}


class TestValueShapeRedaction:
    @pytest.mark.parametrize(
        "value",
        [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_016C7869F4B4B1B2C3D4E5F6a7b8c9d0e1f2",
            "xoxb-1234567890-abcdefghij",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVPmB92K27u",
            "-----BEGIN RSA PRIVATE KEY-----",
        ],
    )
    def test_detects_credential_shapes(self, value):
        assert looks_like_secret(value)
        assert REDACTED in redact({"note": value})["note"]

    def test_ordinary_strings_are_not_secrets(self):
        assert not looks_like_secret("vendor-a.example")
        assert not looks_like_secret("A.5.19")

    def test_redacts_secret_embedded_in_sentence(self):
        text = "deploy used AKIAIOSFODNN7EXAMPLE for access"
        assert "AKIA" not in redact({"log": text})["log"]


class TestStructurePreservation:
    def test_preserves_non_string_types(self):
        data = {"count": 3, "ratio": 0.5, "flag": True, "missing": None}
        assert redact(data) == data

    def test_preserves_tuples_as_tuples(self):
        assert isinstance(redact({"t": ("a", "b")})["t"], tuple)
