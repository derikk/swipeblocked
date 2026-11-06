#!/usr/bin/env python3
"""Extract a keyboard lexicon into the small text file recover.py reads.

usage: python3 extract_lexicon.py LANG OUT.tsv.gz Unigrams-xx.dat [Delta-xx_YY.dat ...] [--all]

Some downloadable assets have no word list of their own: their blocklist ID map points at token
IDs of the lexicon built into iOS. Older versions of most languages are like that, so they need
this file to serve as witnesses, and every language needs it for word-flags.csv. The files in
data/ come from the newest built-in lexicon available for each language: iOS 27.0 for
English, otherwise iOS 26.3 or 17.x (data/SOURCES.tsv has each file and its SHA-256), e.g.

  A=.../RequiredAssets_en.bundle/AssetData
  python3 extract_lexicon.py en data/en-lexicon.tsv.gz $A/Unigrams-en.dat $A/Delta-en_US.dat

By default only entries the package can use are kept: token IDs in the served ID maps of LANG,
spellings in its served embedded word lists, and every V/O/S-labeled or categorized word.
Re-extract if Apple starts serving new tokens. --all keeps the whole lexicon.

Output lines: token_id<TAB>labels<TAB>categories<TAB>word. labels are any of V (vulgar),
O (offensive), S (sensitive); categories is the hex category mask (see lexicon.CATEGORIES) or empty.
Later files override earlier ones for the same token and spelling. Checked against macOS 15.7's
Lexicon.framework on its own en_US lexicon (format v21): words, V/O/S and category masks all agree,
including all 4,746 categorized entries. That framework misreads iOS 27's newer v22 files (duplicate
rows, skipped entries), so it cannot serve as a reference for them.
"""
import gzip
import struct
import sys
from pathlib import Path

import fetch
import lexicon

args = [a for a in sys.argv[1:] if a != '--all']
lang, out, *paths = args
entries = {}
for path in paths:
    for token, word, meta, categories in lexicon.entries(path):
        labels = ''.join(label for bit, label in lexicon.LABELS.items() if meta & bit)
        entries[token, word] = labels, f'{categories:#x}' if categories else ''
if '--all' not in sys.argv:
    tokens, words = set(), set()
    for label, url in fetch.versions(lang):
        for bundle in fetch.download(lang, label, url, Path(__file__).parent / 'cache').values():
            if (bundle / 'blocklistidmap.dat').exists():
                raw = (bundle / 'blocklistidmap.dat').read_bytes()
                start, count = struct.unpack_from('<2I', raw, 12)
                tokens |= {t for t, _ in struct.iter_unpack('<2I', raw[start:start + 8 * count])}
            for embedded in bundle.glob('Unigrams-*.dat'):
                words |= {w for _, w, *_ in lexicon.entries(embedded)}
    entries = {k: v for k, v in entries.items() if any(v) or k[0] in tokens or k[1] in words}
with gzip.open(out, 'wt', encoding='utf-8') as f:
    f.writelines(f'{token}\t{labels}\t{categories}\t{word}\n' for (token, word), (labels, categories) in sorted(entries.items()))
print(f'{lang}: {len(entries):,} entries, {sum(bool(v[0]) for v in entries.values()):,} labeled, '
      f'{sum(bool(v[1]) for v in entries.values()):,} categorized')
