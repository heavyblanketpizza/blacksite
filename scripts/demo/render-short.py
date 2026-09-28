"""Render a short MP4 from record-term.mjs's genuine capture and timestamps.

Requires ffmpeg, ffprobe, and Pillow. Ordinary interactions play at --speed (their
recorded speed by default); the live inference interval is compressed to fill the
remaining --duration. Every sped-up interval carries a visible speed label.
Private capture metadata and credentials are never copied into the output folder.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

from PIL import Image, ImageDraw, ImageFont


def probe(path: Path) -> dict:
    return json.loads(subprocess.check_output([
        "ffprobe", "-v", "error", "-show_format", "-show_streams", "-of", "json", str(path),
    ], text=True))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--font", type=Path, default=Path("/System/Library/Fonts/Menlo.ttc"))
    parser.add_argument("--crf", type=int, default=30, help="H.264 quality (lower is larger; default 30)")
    parser.add_argument("--duration", type=float, default=120, help="output length in seconds (default 120)")
    parser.add_argument("--speed", type=float, default=1, help="playback speed outside inference (default 1)")
    args = parser.parse_args()
    metadata = json.loads((args.capture / "capture-metadata.json").read_text())
    if metadata["status"] != "complete" or metadata["mode"] != "new-investigation":
        raise SystemExit("A completed fresh investigation is required for this edit.")
    raw = args.capture / "capture" / "flow.webm"
    duration = float(probe(raw)["format"]["duration"])
    marks = {item["name"]: item["seconds"] for item in metadata["marks"]}
    start, end = marks["investigation-start"], marks["investigation-complete"]
    tail = duration - end
    pace = args.speed
    compressed = args.duration - (start + tail) / pace
    if not 15 <= compressed < (end - start) / pace:
        raise SystemExit(f"Cannot preserve the surrounding interactions: inference budget is {compressed:.2f}s.")
    speed = (end - start) / compressed
    font = ImageFont.truetype(str(args.font), 16)

    def speed_label(name: str, caption: str) -> Path:
        path = args.capture / "qa" / name
        width = int(font.getlength(caption)) + 28
        im = Image.new("RGBA", (width, 34), (3, 6, 4, 242))
        draw = ImageDraw.Draw(im)
        draw.rectangle((0, 0, width - 1, 33), outline="#39ff7a")
        draw.text((14, 7), caption, font=font, fill="#cdf7d6")
        im.save(path)
        return path

    provider = metadata.get("backend_status", {}).get("provider")
    backend = {"llamacpp": "LLAMA.CPP", "ollama": "OLLAMA"}.get(provider, "LOCAL")
    label = speed_label("inference-speed.png", f"{backend} INFERENCE  /  {speed:.1f}x SPEED")
    inputs = ["-i", str(raw), "-loop", "1", "-i", str(label)]
    # Drop frames after changing timestamps, before encoding. At the default pace
    # the completed guide and evidence views retain their recorded reading time.
    graph = (
        f"[0:v]split=3[a][b][c];"
        f"[a]trim=end={start},setpts=(PTS-STARTPTS)/{pace},fps=30[pre];"
        f"[b]trim=start={start}:end={end},setpts=(PTS-STARTPTS)/{speed},fps=30[live];"
        f"[live][1:v]overlay=x=W-w-8:y=H-h-42:shortest=1[mid];"
        f"[c]trim=start={end},setpts=(PTS-STARTPTS)/{pace},fps=30[post];"
    )
    if pace != 1:
        inputs += ["-loop", "1", "-i", str(speed_label("playback-speed.png", f"{pace:.1f}x SPEED"))]
        graph = graph.replace("[pre];", "[pre0];").replace("[post];", "[post0];") + (
            "[2:v]split=2[l0][l1];"
            "[pre0][l0]overlay=x=W-w-8:y=H-h-42:shortest=1[pre];"
            "[post0][l1]overlay=x=W-w-8:y=H-h-42:shortest=1[post];"
        )
    graph += (
        "[pre][mid][post]concat=n=3:v=1:a=0,tpad=stop_mode=clone:stop_duration=1,"
        f"trim=duration={args.duration},format=yuv420p[v]"
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        "ffmpeg", "-hide_banner", "-loglevel", "warning", "-n", *inputs,
        "-filter_complex", graph, "-map", "[v]",
        "-an", "-c:v", "libx264", "-crf", str(args.crf), "-preset", "slow",
        "-movflags", "+faststart", "-t", str(args.duration), str(args.output),
    ], check=True)
    result = probe(args.output)
    actual = float(result["format"]["duration"])
    if abs(actual - args.duration) > 0.05:
        raise SystemExit(f"Unexpected output duration: {actual}")
    report = {
        "output": str(args.output), "duration_seconds": actual,
        "size_bytes": args.output.stat().st_size,
        "source_duration_seconds": duration,
        "inference_source_seconds": end - start,
        "inference_shown_seconds": compressed,
        "inference_speed": speed,
        "surrounding_interactions_speed": pace,
        "model": metadata.get("provenance", {}).get("model"),
        "codec": result["streams"][0]["codec_name"],
        "width": result["streams"][0]["width"], "height": result["streams"][0]["height"],
    }
    (args.capture / "edit-metadata.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
