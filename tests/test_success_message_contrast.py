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


def test_success_message_meets_wcag_contrast_in_light_and_dark_modes():
    light_rule = re.search(
        r"#message\.ok\s*\{\s*color:\s*(#[0-9a-fA-F]{6});\s*\}",
        CSS,
    )
    dark_rules = re.search(
        r"@media \(prefers-color-scheme: dark\)\s*\{(?P<body>.*?)\n\}",
        CSS,
        re.DOTALL,
    )

    assert light_rule is not None
    assert dark_rules is not None
    dark_rule = re.search(
        r"#message\.ok\s*\{\s*color:\s*(#[0-9a-fA-F]{6});\s*\}",
        dark_rules.group("body"),
    )
    assert dark_rule is not None

    assert _contrast(light_rule.group(1), "#ffffff") >= 4.5
    assert _contrast(dark_rule.group(1), "#121212") >= 4.5
