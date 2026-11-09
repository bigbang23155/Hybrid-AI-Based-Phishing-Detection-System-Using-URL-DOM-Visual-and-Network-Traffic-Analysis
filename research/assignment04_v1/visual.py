"""Fixed, non-learned screenshot descriptor. No OCR, labels, or network calls."""
import hashlib
import io
import warnings
import numpy as np
from PIL import Image, ImageOps

VERSION = 'visual-rgb16-grid4-gradient8-v1'
NAMES = tuple([f'{c}_hist_{i:02d}' for c in 'rgb' for i in range(16)] +
              [f'grid_{y}_{x}_{c}_mean' for y in range(4) for x in range(4) for c in 'rgb'] +
              [f'gradient_orientation_{i}' for i in range(8)])
MAX_BYTES = 20_000_000
MAX_PIXELS = 16_000_000


def extract(data):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_BYTES:
        raise ValueError('image_byte_limit')
    with warnings.catch_warnings():
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        try:
            with Image.open(io.BytesIO(data)) as im:
                if im.format not in ('PNG', 'JPEG', 'WEBP') or getattr(im, 'n_frames', 1) != 1:
                    raise ValueError('unsupported_image')
                if im.width * im.height > MAX_PIXELS:
                    raise ValueError('image_pixel_limit')
                original = list(im.size)
                im = ImageOps.exif_transpose(im).convert('RGBA')
                canvas = Image.new('RGBA', im.size, 'white')
                canvas.alpha_composite(im)
                # Fixed 128x128 resize: aspect distortion is an explicit limitation.
                a = np.asarray(canvas.convert('RGB').resize((128, 128), Image.Resampling.BILINEAR), dtype=float) / 255
        except (Image.DecompressionBombWarning, Image.DecompressionBombError) as exc:
            raise ValueError('image_pixel_limit') from exc
    values = []
    for c in range(3):
        values.extend((np.histogram(a[:, :, c], bins=16, range=(0, 1))[0] / (128*128)).tolist())
    for y in range(4):
        for x in range(4):
            values.extend(a[y*32:(y+1)*32, x*32:(x+1)*32].mean(axis=(0, 1)).tolist())
    gray = a @ np.array([0.299, 0.587, 0.114])
    dy, dx = np.gradient(gray)
    mag = np.hypot(dx, dy)
    angle = np.mod(np.arctan2(dy, dx), np.pi)
    hist = np.histogram(angle, bins=8, range=(0, np.pi), weights=mag)[0]
    values.extend((hist / hist.sum() if hist.sum() > 0 else np.zeros(8)).tolist())
    return {'registry_version': VERSION, 'feature_order': list(NAMES),
            'values': dict(zip(NAMES, values)), 'missing_reasons': {}, 'support': {},
            'audit': {'source_sha256': hashlib.sha256(data).hexdigest(), 'dimensions': original,
                      'flat_image': bool(gray.std() < 0.01), 'semantic_embedding': False}}
