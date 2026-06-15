"""Generate ``ui/public/logo.ico`` from the brand-mark design.

Cairo / librsvg aren't available in this Windows venv, so instead of
re-rendering ``brand-mark.svg`` we re-draw the same composition with
Pillow primitives — the brand mark is geometrically simple (rounded
square + polygonal shield + checkmark polyline + accent dots) and
this avoids dragging a native cairo dependency onto every dev
workstation.

Run with::

    cd backend
    uv run python ../ui/scripts/build-icon.py

The output is a multi-resolution Windows ICO (16, 24, 32, 48, 64, 128,
256 px) consumed by Electron's ``BrowserWindow`` ``icon:`` option to
replace the default Electron taskbar / window-frame mark.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

# Canvas color palette — kept in lockstep with brand-mark.svg so the
# in-app sidebar mark and the OS-level taskbar icon read as the same
# brand. If brand-mark.svg changes color tokens, mirror the change here.
NAVY_TOP = (14, 44, 74, 255)  # #0e2c4a
NAVY_BOTTOM = (6, 26, 48, 255)  # #061a30
SHIELD_WHITE = (255, 255, 255, 255)
SHIELD_FILL = (255, 255, 255, 12)  # ~5% white overlay for depth
CHECK_BLUE = (59, 130, 246, 255)  # #3b82f6
NODE_BLUE = (96, 165, 250, 255)  # #60a5fa
INNER_HIGHLIGHT = (255, 255, 255, 20)  # subtle inner stroke


def _vertical_gradient(
    size: int, top: tuple[int, int, int, int], bottom: tuple[int, int, int, int]
) -> Image.Image:
    """Build a vertical 2-stop gradient `size`x`size`."""
    gradient = Image.new("RGBA", (1, size))
    for y in range(size):
        t = y / max(1, size - 1)
        r = int(top[0] + (bottom[0] - top[0]) * t)
        g = int(top[1] + (bottom[1] - top[1]) * t)
        b = int(top[2] + (bottom[2] - top[2]) * t)
        gradient.putpixel((0, y), (r, g, b, 255))
    return gradient.resize((size, size))


def _rounded_mask(size: int, radius: int) -> Image.Image:
    """L-mode mask for the rounded-square container."""
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    return mask


def _shield_points(size: int) -> list[tuple[float, float]]:
    """Same 5-point shield outline used in brand-mark.svg, scaled to ``size``.

    The SVG path is::

        M 128 52  L 188 78  L 188 138
        C 188 178 160 202 128 214
        C  96 202  68 178  68 138
        L  68  78  Z

    The Bezier shoulders are approximated with extra polyline anchor
    points — close enough at icon resolutions and avoids hauling in a
    full Bezier rasterizer.
    """
    s = size / 256.0

    def p(x: float, y: float) -> tuple[float, float]:
        return (x * s, y * s)

    pts = [
        p(128, 52),
        p(188, 78),
        p(188, 138),
        # right Bezier shoulder — sampled
        p(186, 162),
        p(176, 184),
        p(156, 202),
        p(128, 214),
        # left Bezier shoulder — sampled (mirror)
        p(100, 202),
        p(80, 184),
        p(70, 162),
        p(68, 138),
        p(68, 78),
    ]
    return pts


def render(size: int) -> Image.Image:
    """Render the brand mark at a square pixel size."""
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    # Rounded-square background with vertical gradient — match SVG rx=44 of 256.
    radius = int(round(44 * size / 256))
    bg = _vertical_gradient(size, NAVY_TOP, NAVY_BOTTOM)
    mask = _rounded_mask(size, radius)
    canvas.paste(bg, (0, 0), mask)

    draw = ImageDraw.Draw(canvas, "RGBA")

    # Inner highlight stroke for depth (offset 1px in from the rounded edge).
    if size >= 32:
        draw.rounded_rectangle(
            (1, 1, size - 2, size - 2),
            radius=max(0, radius - 1),
            outline=INNER_HIGHLIGHT,
            width=1,
        )

    # Shield silhouette.
    shield = _shield_points(size)
    shield_stroke = max(2, int(round(18 * size / 256)))
    # Fill first (subtle white overlay) so the stroke sits on top crisp.
    draw.polygon(shield, fill=SHIELD_FILL)
    draw.line(
        list(shield) + [shield[0]],
        fill=SHIELD_WHITE,
        width=shield_stroke,
        joint="curve",
    )

    # Checkmark polyline: (94,134) → (120,160) → (166,108) scaled.
    s = size / 256.0
    check_pts = [(94 * s, 134 * s), (120 * s, 160 * s), (166 * s, 108 * s)]
    check_stroke = max(2, int(round(20 * size / 256)))
    draw.line(check_pts, fill=CHECK_BLUE, width=check_stroke, joint="curve")
    # Round the endpoints so the check doesn't look chiseled at low res.
    end_r = max(1, check_stroke // 2)
    for (cx, cy) in (check_pts[0], check_pts[-1]):
        draw.ellipse(
            (cx - end_r, cy - end_r, cx + end_r, cy + end_r), fill=CHECK_BLUE
        )

    # Accent nodes on the shield's vertical axis (top + bottom tip).
    node_r = max(1, int(round(10 * size / 256)))
    for (nx, ny) in ((128 * s, 52 * s), (128 * s, 214 * s)):
        draw.ellipse(
            (nx - node_r, ny - node_r, nx + node_r, ny + node_r),
            fill=NODE_BLUE,
        )

    return canvas


def main() -> None:
    ui_root = Path(__file__).resolve().parents[1]
    out_dir = ui_root / "public"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Windows requires a multi-res .ico; the Electron docs further
    # recommend at least 256x256 so the icon stays sharp in the
    # taskbar's "large icons" view and the Alt-Tab switcher.
    # Pillow's ICO encoder reads dimensions from the *first* image and
    # ignores larger frames passed via append_images — so we hand it the
    # 256x256 master first and let sizes= produce the smaller frames.
    # Rendering each size natively (rather than downscaling from 256)
    # keeps the checkmark crisp at 16/24 px instead of going muddy.
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images_by_size = {s: render(s) for s in sizes}
    sizes_desc = sorted(sizes, reverse=True)
    images = [images_by_size[s] for s in sizes_desc]

    ico_path = out_dir / "logo.ico"
    images[0].save(
        ico_path,
        format="ICO",
        sizes=[(s, s) for s in sizes_desc],
        append_images=images[1:],
    )
    print(f"wrote {ico_path}  ({len(sizes)} resolutions)")

    # Also drop a 512x512 PNG for any place that wants a raster master
    # (PDF reports, splash screen, etc.).
    master = render(512)
    png_path = out_dir / "logo.png"
    master.save(png_path, format="PNG")
    print(f"wrote {png_path}  (512x512 master)")


if __name__ == "__main__":
    main()
