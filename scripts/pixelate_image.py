#!/usr/bin/env python3
# /// script
# dependencies = ["Pillow==12.3.0"]
# ///
"""Rebuild the README banner: uv run scripts/pixelate_image.py.

One global 320x180 grid and 128-color palette are applied to the source.
Nearest-neighbor sampling preserves hard edges; dithering is disabled.
The 6x enlargement produces a 1920x1080 PNG with uniform 6x6 pixel blocks.
"""

import argparse
from pathlib import Path

from PIL import Image, ImageOps


ROOT = Path(__file__).resolve().parents[1]


def positive_integer(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path,
        default=ROOT / "assets/source/blacksite-homestead.png",
    )
    parser.add_argument(
        "--output", type=Path,
        default=ROOT / "assets/blacksite-homestead.png",
    )
    parser.add_argument("--width", type=positive_integer, default=320)
    parser.add_argument("--height", type=positive_integer, default=180)
    parser.add_argument("--scale", type=positive_integer, default=6)
    parser.add_argument("--colors", type=int, choices=range(2, 257), default=128,
                        metavar="2..256")
    args = parser.parse_args()
    if args.width * 9 != args.height * 16:
        parser.error("the pixel grid must have a 16:9 aspect ratio")
    if args.source.resolve() == args.output.resolve():
        parser.error("source and output must be different files")

    with Image.open(args.source) as source:
        # The same grid and palette cover the entire image, including the developer.
        pixels = ImageOps.fit(
            source.convert("RGB"),
            (args.width, args.height),
            method=Image.Resampling.NEAREST,
            centering=(0.5, 0.5),
        )
        pixels = pixels.quantize(
            colors=args.colors,
            method=Image.Quantize.MEDIANCUT,
            dither=Image.Dither.NONE,
        ).convert("RGB")

    output = pixels.resize(
        (args.width * args.scale, args.height * args.scale),
        Image.Resampling.NEAREST,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output.save(args.output, format="PNG", optimize=True)
    print(
        f"{args.output}: {args.width}x{args.height} grid, "
        f"{args.colors} colors, {args.scale}x{args.scale} blocks, "
        f"{output.width}x{output.height} output"
    )


if __name__ == "__main__":
    main()
