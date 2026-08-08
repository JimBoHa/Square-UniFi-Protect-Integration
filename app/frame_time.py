"""Read UniFi Protect's burned-in whole-second frame timestamp."""

from __future__ import annotations

import io
import logging
import warnings
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Callable

from PIL import Image, UnidentifiedImageError

if TYPE_CHECKING:
    from pathlib import Path

    from .store import Store

logger = logging.getLogger("spi.frame_time")

NORMALIZED_GLYPH_WIDTH = 24
NORMALIZED_GLYPH_HEIGHT = 36
NORMALIZED_GLYPH_BYTES = NORMALIZED_GLYPH_WIDTH * NORMALIZED_GLYPH_HEIGHT
PREFIX_DIGIT_COUNT = 12
TIMESTAMP_DIGIT_COUNT = 14
MAX_CLASSIFICATION_DISTANCE = 0.12
MIN_CLASSIFICATION_MARGIN = 1 / NORMALIZED_GLYPH_BYTES
MAX_ABSOLUTE_OFFSET_MS = 10_000
TEMPLATE_LEARNING_STABILITY_MS = MAX_ABSOLUTE_OFFSET_MS
FRAME_OFFSET_BACKFILL_BATCH_SIZE = 50
FRAME_OFFSET_MAX_ATTEMPTS = 3


@dataclass(frozen=True)
class FrameGlyphExtraction:
    learned_templates: dict[str, tuple[bytes, ...]]
    second_glyphs: tuple[bytes, bytes]


@dataclass(frozen=True)
class FrameTimeMeasurement:
    frame_ts_ms: int
    offset_ms: int
    confidence: int


@dataclass(frozen=True)
class FrameTimeAnalysis:
    learned_templates: dict[str, tuple[bytes, ...]]
    measurement: FrameTimeMeasurement | None
    error: str = ""


def _stable_timestamp_prefix_digits(
    requested_ts_ms: int,
) -> tuple[str | None, ...]:
    # Protect renders the console's local wall time. The appliance and this
    # LAN host are expected to share a timezone; classification fails closed
    # if the known prefix does not match learned glyphs.
    candidates = (
        datetime.fromtimestamp(
            (requested_ts_ms - TEMPLATE_LEARNING_STABILITY_MS) / 1000
        ),
        datetime.fromtimestamp(requested_ts_ms / 1000),
        datetime.fromtimestamp(
            (requested_ts_ms + TEMPLATE_LEARNING_STABILITY_MS) / 1000
        ),
    )
    prefixes = [candidate.strftime("%Y%m%d%I%M") for candidate in candidates]
    return tuple(
        values[0] if len(set(values)) == 1 else None
        for values in zip(*prefixes)
    )


def _connected_components(image: Image.Image) -> list[set[tuple[int, int]]]:
    rgb = image.convert("RGB")
    width, height = rgb.size
    pixels = rgb.load()
    remaining = {
        (x, y)
        for y in range(height)
        for x in range(width)
        if min(pixels[x, y]) >= 210
        and max(pixels[x, y]) - min(pixels[x, y]) <= 40
    }
    components: list[set[tuple[int, int]]] = []
    while remaining:
        seed = remaining.pop()
        component = {seed}
        queue = [seed]
        for x, y in queue:
            for neighbor_x in range(max(0, x - 1), min(width, x + 2)):
                for neighbor_y in range(max(0, y - 1), min(height, y + 2)):
                    neighbor = (neighbor_x, neighbor_y)
                    if neighbor in remaining:
                        remaining.remove(neighbor)
                        component.add(neighbor)
                        queue.append(neighbor)
        components.append(component)
    return components


def _normalized_component(component: set[tuple[int, int]]) -> bytes:
    x_values = [point[0] for point in component]
    y_values = [point[1] for point in component]
    left, top = min(x_values), min(y_values)
    width = max(x_values) - left + 1
    height = max(y_values) - top + 1
    bitmap = bytearray(width * height)
    for x, y in component:
        bitmap[(y - top) * width + (x - left)] = 255
    glyph = Image.frombytes("L", (width, height), bytes(bitmap)).resize(
        (NORMALIZED_GLYPH_WIDTH, NORMALIZED_GLYPH_HEIGHT),
        Image.Resampling.NEAREST,
    )
    values = (
        glyph.get_flattened_data()
        if hasattr(glyph, "get_flattened_data")
        else glyph.getdata()
    )
    return bytes(1 if value >= 128 else 0 for value in values)


def extract_frame_glyphs(
    image: bytes,
    requested_ts_ms: int,
) -> FrameGlyphExtraction:
    """Segment the first fourteen tall glyphs in Protect's top-left overlay."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(image)) as source:
                source.load()
                image_width, image_height = source.size
                crop_width = min(
                    image_width,
                    max(700, int(image_width * 0.20)),
                )
                crop_height = min(
                    image_height,
                    max(75, int(image_height * 0.045)),
                )
                overlay = source.crop((0, 0, crop_width, crop_height))
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
        ValueError,
    ) as exc:
        raise ValueError(f"Could not decode frame timestamp: {exc}") from exc

    minimum_height = max(12, int(image_height * 0.010))
    minimum_pixels = max(20, minimum_height * 2)
    digit_components: list[tuple[int, set[tuple[int, int]]]] = []
    for component in _connected_components(overlay):
        x_values = [point[0] for point in component]
        y_values = [point[1] for point in component]
        height = max(y_values) - min(y_values) + 1
        if height >= minimum_height and len(component) >= minimum_pixels:
            digit_components.append((min(x_values), component))
    digit_components.sort(key=lambda item: item[0])
    if len(digit_components) < TIMESTAMP_DIGIT_COUNT:
        raise ValueError("UniFi frame timestamp overlay was not detected")

    glyphs = tuple(
        _normalized_component(component)
        for _left, component in digit_components[:TIMESTAMP_DIGIT_COUNT]
    )
    prefix = _stable_timestamp_prefix_digits(requested_ts_ms)
    learned: dict[str, list[bytes]] = {}
    for digit, glyph in zip(prefix, glyphs[:PREFIX_DIGIT_COUNT]):
        if digit is None:
            continue
        learned.setdefault(digit, []).append(glyph)
    return FrameGlyphExtraction(
        learned_templates={
            digit: tuple(dict.fromkeys(samples))
            for digit, samples in learned.items()
        },
        second_glyphs=(glyphs[12], glyphs[13]),
    )


def _glyph_distance(left: bytes, right: bytes) -> float:
    if len(left) != NORMALIZED_GLYPH_BYTES or len(right) != len(left):
        return 1.0
    return sum(a != b for a, b in zip(left, right)) / len(left)


def _classify_digit(
    glyph: bytes,
    templates: dict[str, tuple[bytes, ...] | list[bytes]],
) -> tuple[str, float, float]:
    scores = sorted(
        (
            min(_glyph_distance(glyph, template) for template in samples),
            digit,
        )
        for digit, samples in templates.items()
        if digit in "0123456789" and samples
    )
    if len(scores) < 2:
        raise ValueError("Not enough learned UniFi timestamp digits")
    best, second_best = scores[0], scores[1]
    margin = second_best[0] - best[0]
    if (
        best[0] > MAX_CLASSIFICATION_DISTANCE
        or margin < MIN_CLASSIFICATION_MARGIN
    ):
        raise ValueError("UniFi frame timestamp digit was ambiguous")
    return best[1], best[0], margin


def measure_extracted_frame_time(
    extraction: FrameGlyphExtraction,
    requested_ts_ms: int,
    existing_templates: dict[str, tuple[bytes, ...] | list[bytes]] | None = None,
) -> FrameTimeMeasurement:
    templates: dict[str, list[bytes]] = {
        digit: list(samples)
        for digit, samples in (existing_templates or {}).items()
    }
    for digit, samples in extraction.learned_templates.items():
        known = templates.setdefault(digit, [])
        known.extend(sample for sample in samples if sample not in known)

    classified = [
        _classify_digit(glyph, templates)
        for glyph in extraction.second_glyphs
    ]
    displayed_second = int("".join(result[0] for result in classified))
    if displayed_second > 59:
        raise ValueError("UniFi frame timestamp seconds were invalid")

    minute_start = (int(requested_ts_ms) // 60_000) * 60_000
    candidates = (
        minute_start - 60_000 + displayed_second * 1000,
        minute_start + displayed_second * 1000,
        minute_start + 60_000 + displayed_second * 1000,
    )
    frame_ts_ms = min(
        candidates,
        key=lambda candidate: (abs(candidate - requested_ts_ms), candidate),
    )
    offset_ms = frame_ts_ms - int(requested_ts_ms)
    if abs(offset_ms) > MAX_ABSOLUTE_OFFSET_MS:
        raise ValueError("UniFi frame timestamp was too far from the transaction")

    worst_distance = max(result[1] for result in classified)
    narrowest_margin = min(result[2] for result in classified)
    confidence = max(
        0,
        min(
            10_000,
            round((1 - worst_distance) * narrowest_margin * 10_000),
        ),
    )
    return FrameTimeMeasurement(
        frame_ts_ms=frame_ts_ms,
        offset_ms=offset_ms,
        confidence=confidence,
    )


def analyze_frame_time(
    image: bytes,
    requested_ts_ms: int,
    existing_templates: dict[str, tuple[bytes, ...] | list[bytes]] | None = None,
) -> FrameTimeAnalysis:
    try:
        extraction = extract_frame_glyphs(image, requested_ts_ms)
    except ValueError as exc:
        return FrameTimeAnalysis({}, None, str(exc))
    try:
        measurement = measure_extracted_frame_time(
            extraction,
            requested_ts_ms,
            existing_templates,
        )
    except ValueError as exc:
        return FrameTimeAnalysis(
            extraction.learned_templates,
            None,
            str(exc),
        )
    return FrameTimeAnalysis(extraction.learned_templates, measurement)


def backfill_frame_offsets(
    store: Store,
    read_file: Callable[[Path, str], bytes],
    *,
    batch_size: int = FRAME_OFFSET_BACKFILL_BATCH_SIZE,
) -> dict[str, int]:
    """Measure a bounded local batch, learning camera glyphs before classifying."""
    assets = store.list_pending_frame_offset_assets(batch_size)
    extracted: list[tuple[dict, FrameGlyphExtraction | None, str]] = []
    for asset in assets:
        try:
            with store.integration_guard():
                current = store.get_transaction(asset["id"])
                if (
                    current is None
                    or current.get("thumbnail_path") != asset["thumbnail_path"]
                    or current.get("camera_id") != asset["camera_id"]
                ):
                    continue
                image = read_file(store.thumbnail_dir, asset["thumbnail_path"])
                extraction = extract_frame_glyphs(image, asset["ts_ms"])
                store.add_frame_digit_templates(
                    asset["camera_id"],
                    extraction.learned_templates,
                )
        except (OSError, ValueError) as exc:
            extracted.append((asset, None, str(exc)))
            continue
        extracted.append((asset, extraction, ""))

    measured = 0
    unavailable = 0
    pending = 0
    template_cache: dict[str, dict[str, tuple[bytes, ...]]] = {}
    for asset, extraction, extraction_error in extracted:
        measurement = None
        error = extraction_error
        if extraction is not None:
            templates = template_cache.setdefault(
                asset["camera_id"],
                store.get_frame_digit_templates(asset["camera_id"]),
            )
            try:
                measurement = measure_extracted_frame_time(
                    extraction,
                    asset["ts_ms"],
                    templates,
                )
            except ValueError as exc:
                error = str(exc)
        status = store.record_frame_offset_attempt(
            asset["id"],
            asset["thumbnail_path"],
            measurement,
            error,
            max_attempts=FRAME_OFFSET_MAX_ATTEMPTS,
        )
        measured += int(status == "measured")
        unavailable += int(status == "unavailable")
        pending += int(status == "pending")
    return {
        "processed_count": len(extracted),
        "measured_count": measured,
        "unavailable_count": unavailable,
        "pending_count": pending,
    }
