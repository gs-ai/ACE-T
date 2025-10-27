from __future__ import annotations

from typing import Any, Iterable


class YamlError(RuntimeError):
    """Simple YAML parsing error."""


class YAMLError(YamlError):
    """Compatibility alias matching PyYAML's exception name."""


def _parse_scalar(value: str) -> Any:
    if value in {"null", "Null", "NULL", "~"}:
        return None
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value.startswith(("'", '"')) and value.endswith(("'", '"')):
        return value[1:-1]
    try:
        if value.startswith("0") and value != "0" and not value.startswith("0."):
            # treat as string to preserve leading zeros
            raise ValueError
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def safe_load(text: str | bytes) -> Any:
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as exc:  # pragma: no cover - defensive guard
            raise YAMLError("Binary files are not supported; please provide UTF-8 text.") from exc
    if not isinstance(text, str):  # pragma: no cover - type guard
        raise YAMLError("Unsupported input type for YAML parsing.")
    lines = text.splitlines()
    root: Any = {}
    stack: list[tuple[int, Any]] = [(-1, root)]

    index = 0
    total = len(lines)
    while index < total:
        raw_line = lines[index]
        stripped = raw_line.strip()
        index += 1
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        container = stack[-1][1]
        if stripped.startswith("- "):
            if not isinstance(container, list):
                raise YamlError("List item without list container")
            item_text = stripped[2:].strip()
            if item_text:
                container.append(_parse_scalar(item_text))
            else:
                new_item: Any = {}
                container.append(new_item)
                stack.append((indent, new_item))
            continue
        if ":" not in stripped:
            raise YamlError(f"Invalid line: {raw_line}")
        key, value_text = stripped.split(":", 1)
        key = key.strip()
        value_text = value_text.strip()
        if not isinstance(container, dict):
            raise YamlError("Mapping entry without dict container")
        if value_text == "":
            # Determine container type by looking ahead.
            container_type: Any = {}
            lookahead_index = index
            while lookahead_index < total:
                look_line = lines[lookahead_index]
                lookahead_index += 1
                look_stripped = look_line.strip()
                if not look_stripped or look_stripped.startswith("#"):
                    continue
                look_indent = len(look_line) - len(look_line.lstrip(" "))
                if look_indent <= indent:
                    container_type = {}
                else:
                    container_type = [] if look_stripped.startswith("- ") else {}
                break
            if isinstance(container_type, list):
                container[key] = []
                stack.append((indent, container[key]))
            else:
                container[key] = {}
                stack.append((indent, container[key]))
        else:
            container[key] = _parse_scalar(value_text)
    return root


def _dump_lines(value: Any, indent: int = 0) -> Iterable[str]:
    pad = " " * indent
    if isinstance(value, dict):
        for key, val in value.items():
            if isinstance(val, (dict, list)):
                yield f"{pad}{key}:"
                yield from _dump_lines(val, indent + 2)
            else:
                scalar = _format_scalar(val)
                yield f"{pad}{key}: {scalar}"
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                yield f"{pad}-"
                yield from _dump_lines(item, indent + 2)
            else:
                yield f"{pad}- {_format_scalar(item)}"
    else:
        yield f"{pad}{_format_scalar(value)}"


def _format_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if any(ch.isspace() for ch in text) or text == "":
        return f'"{text}"'
    return text


def safe_dump(data: Any, sort_keys: bool = True) -> str:
    if isinstance(data, dict) and sort_keys:
        data = {key: data[key] for key in sorted(data)}
    return "\n".join(_dump_lines(data)) + "\n"


__all__ = ["safe_load", "safe_dump", "YamlError", "YAMLError"]
