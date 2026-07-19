import re
from pathlib import Path


CSS = (Path(__file__).parents[1] / "app" / "static" / "style.css").read_text()


def _luminance(color: str) -> float:
    channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        channel / 12.92
        if channel <= 0.04045
        else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first: str, second: str) -> float:
    lighter, darker = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def test_error_message_meets_wcag_contrast_in_dark_mode():
    dark_rules = re.findall(
        r"@media \(prefers-color-scheme: dark\)\s*\{(.*?)\n\}",
        CSS,
        re.DOTALL,
    )
    error_rule = next(
        (
            match
            for rules in dark_rules
            if (
                match := re.search(
                    r"#message\.error\s*\{\s*color:\s*(#[0-9a-fA-F]{6});\s*\}",
                    rules,
                )
            )
        ),
        None,
    )

    assert error_rule is not None
    assert _contrast(error_rule.group(1), "#121212") >= 4.5
