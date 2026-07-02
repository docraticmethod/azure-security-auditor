"""HCL normalization + traversal.

python-hcl2 (v8) wraps scalar values AND some keys in literal double quotes, so a
Terraform attribute like `destination_port_range = "22"` parses to the Python
string `'"22"'`. Every rule comparison must strip those quotes first. This module
is the single choke point for that quirk — rules should never call hcl2 directly.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import Any, Iterator


def unq(value: Any) -> Any:
    """Strip the literal quotes python-hcl2 wraps around scalars/keys.

    Non-strings pass through untouched. Only a single leading+trailing pair of
    matching quotes is removed, so an already-clean value is safe to pass twice.
    """
    if not isinstance(value, str):
        return value
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("\"", "'"):
        return value[1:-1]
    return value


def get(mapping: dict, key: str, default: Any = KeyError) -> Any:
    """Fetch `key` from an hcl2 dict, matching against unquoted keys.

    Raises KeyError if absent and no default is supplied.
    """
    for k, v in mapping.items():
        if unq(k) == key:
            return v
    if default is KeyError:
        raise KeyError(f"{key!r} not in {[unq(k) for k in mapping]}")
    return default


@dataclass
class Resource:
    """One Terraform resource block, normalized for rule consumption."""

    type: str                       # e.g. "azurerm_network_security_rule"
    name: str                       # e.g. "allow_ssh_any"
    file: str                       # source .tf path
    attributes: dict = field(default_factory=dict)  # raw hcl2 attribute dict

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"

    def attr(self, key: str, default: Any = None) -> Any:
        """Return a normalized (unquoted) scalar attribute value."""
        raw = get(self.attributes, key, default=default)
        return unq(raw)

    def has(self, key: str) -> bool:
        try:
            get(self.attributes, key)
            return True
        except KeyError:
            return False


def _iter_resource_blocks(parsed: dict, source_file: str) -> Iterator[Resource]:
    """Yield Resource objects from a parsed hcl2 document.

    hcl2 shapes `resource` as a list of dicts, each: {type: {name: {attrs}}}.
    Both the type and name keys can be quote-wrapped.
    """
    for block in parsed.get("resource", []):
        for rtype, named in block.items():
            rtype = unq(rtype)
            for rname, attrs in named.items():
                yield Resource(
                    type=rtype,
                    name=unq(rname),
                    file=source_file,
                    attributes=attrs if isinstance(attrs, dict) else {},
                )


def load_resources(tf_text: str, source_file: str = "<memory>") -> list[Resource]:
    """Parse Terraform text and return normalized Resource objects."""
    parsed = hcl2_load(io.StringIO(tf_text))
    return list(_iter_resource_blocks(parsed, source_file))


def hcl2_load(stream) -> dict:
    """Thin wrapper so hcl2 is imported lazily and mockable in tests."""
    import hcl2

    return hcl2.load(stream)
