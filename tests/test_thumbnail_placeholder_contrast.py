import re
from pathlib import Path


CSS = (Path(__file__).parents[1] / "app" / "static" / "style.css").read_text()


def _luminance(channel: float) -> float:
    value = channel / 255
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def _contrast(first: float, second: float) -> float:
    lighter, darker = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def test_thumbnail_placeholder_text_meets_wcag_contrast():
    rule = re.search(
        r"\.txn \.thumb\.placeholder\s*\{(?P<body>.*?)\}",
        CSS,
        re.DOTALL,
    )
    assert rule is not None
    opacity_match = re.search(r"opacity:\s*([0-9.]+)", rule.group("body"))
    assert opacity_match is not None
    opacity = float(opacity_match.group(1))

    # The placeholder inherits black text and an 18%-black border background.
    # Its group opacity composites both colors onto the white page canvas.
    text_channel = 255 * (1 - opacity)
    background_channel = 255 * (1 - 0.18 * opacity)
    assert _contrast(text_channel, background_channel) >= 4.5
