"""Download keyboard phrase blocklists from Apple's MobileAsset servers.

Apple's asset catalog (gdmf.apple.com) lists the LinguisticData assets it currently serves to an
iOS device. Each asset is a large ZIP, but the blocklist files inside are a few kilobytes, so they
are read with HTTP range requests instead of downloading the archive.
"""
from __future__ import annotations

import base64
import io
import json
import urllib.request
import zipfile
from pathlib import Path

CATALOG = 'https://gdmf.apple.com/v2/assets'
DEVICE = {  # what an iPhone running iOS 27.0 sends; the response is the public asset list
    'ClientVersion': 2, 'AssetType': 'com.apple.MobileAsset.LinguisticData',
    'AssetAudience': '0c88076f-c292-4dad-95e7-304db9d29d34',
    'ProductType': 'iPhone17,1', 'HWModelStr': 'D93AP', 'DeviceName': 'iPhone',
    'ProductVersion': '27.0', 'DeviceOSVersion': '27.0', 'BuildVersion': '24A434',
}
SURFACES = {'default': 'blocklist.bundle', 'quickpath': 'qp_blocklist.bundle'}


def catalog() -> list[dict]:
    request = urllib.request.Request(CATALOG, json.dumps(DEVICE).encode(), {'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        token = response.read().decode()
    payload = token.split('.')[1]  # the response is a signed JWS; its payload is base64url JSON
    return json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))['Assets']


def versions(lang: str) -> list[tuple[str, str]]:
    """(label, ZIP URL) of every served iOS asset version with a keyboard model for lang, newest first."""
    found = {}
    for asset in catalog():
        paths = {item['ContentPath'] for item in asset.get('Contents', [])}
        if asset.get('AssetLocale') == lang and f'{lang}.lm' in paths and 'iOS' in asset['_SupportedPlatforms']:
            label = f"c{asset['_CompatibilityVersion']}-{asset['_ContentVersion']}"
            found[label] = (asset['_ContentVersion'], asset['__BaseURL'] + asset['__RelativePath'])
    return [(label, url) for label, (_, url) in sorted(found.items(), key=lambda item: -item[1][0])]


class RemoteFile(io.RawIOBase):
    """Seekable read-only view of a URL through HTTP range requests, enough for zipfile."""

    def __init__(self, url: str, block: int = 1 << 16):
        self.url, self.block, self.pos, self.cache_at, self.cache = url, block, 0, 0, b''
        with urllib.request.urlopen(urllib.request.Request(url, method='HEAD'), timeout=60) as response:
            self.size = int(response.headers['Content-Length'])

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.pos

    def seek(self, offset, whence=0):
        self.pos = (offset, self.pos + offset, self.size + offset)[whence]
        return self.pos

    def readinto(self, buffer):
        want = min(len(buffer), self.size - self.pos)
        if want <= 0:
            return 0
        if not self.cache_at <= self.pos <= self.pos + want <= self.cache_at + len(self.cache):
            end = min(self.size, self.pos + max(want, self.block)) - 1
            request = urllib.request.Request(self.url, headers={'Range': f'bytes={self.pos}-{end}'})
            with urllib.request.urlopen(request, timeout=120) as response:
                self.cache_at, self.cache = self.pos, response.read()
        start = self.pos - self.cache_at
        buffer[:want] = self.cache[start:start + want]
        self.pos += want
        return want


def download(lang: str, label: str, url: str, cache: Path) -> dict[str, Path]:
    """Fetch the blocklist bundles of one asset into cache/lang/label/<surface>/; return them by surface."""
    dest = cache / lang / label
    if not (dest / 'source-url.txt').exists():
        archive = zipfile.ZipFile(RemoteFile(url))
        for surface, bundle in SURFACES.items():
            prefix = f'AssetData/{lang}.lm/{bundle}/'
            for name in archive.namelist():
                if name.startswith(prefix) and name.endswith('.dat') and '/' not in name[len(prefix):]:
                    (dest / surface).mkdir(parents=True, exist_ok=True)
                    (dest / surface / name[len(prefix):]).write_bytes(archive.read(name))
        dest.mkdir(parents=True, exist_ok=True)
        (dest / 'source-url.txt').write_text(url + '\n')
    return {s: dest / s for s in SURFACES if (dest / s / 'blocklist.dat').exists()}
