"""Read Apple keyboard lexicons (Unigrams-*.dat, Delta-*.dat) without Apple's frameworks.

A lexicon is a 0x80-byte big-endian header followed by length-prefixed entries stored back to
back. Each entry holds optional fields chosen by a flag byte, a Huffman-coded string and a 24-bit
token ID. Several entries can share a token ID (inflections, spelling variants), so the walk below
reads every entry rather than going through the file's one-entry-per-ID index.
"""
from __future__ import annotations

VULGAR, OFFENSIVE, SENSITIVE = 0x00800000, 0x01000000, 0x02000000
LABELS = {VULGAR: 'V', OFFENSIVE: 'O', SENSITIVE: 'S'}
CATEGORY_BITS = 0x0007FF00  # attribute bits Apple reports as category flags, not meta flags
# The sensitive (S) policy applies per category. Apple does not name the bits; these are the
# groupings observed in the iOS 26.3.1 English lexicon. They are approximate, and a word can
# carry several.
CATEGORIES = {0x100: 'bodily', 0x200: 'anatomy', 0x400: 'derogatory', 0x800: 'disease', 0x1000: 'drugs',
              0x2000: 'politics', 0x4000: 'religion', 0x8000: 'sex', 0x10000: 'violence',
              0x20000: 'weapons', 0x40000: 'mixed'}


def entries(path):
    """Yield (token_id, word, meta_flags, category_flags) for every entry of a lexicon file."""
    d = open(path, 'rb').read()
    u32 = lambda o: int.from_bytes(d[o:o + 4], 'big')
    start, end, huffman, codebook_at = u32(0x44), u32(0x48), u32(0x4c), u32(0x50)
    codebook = [int.from_bytes(d[codebook_at + 4 + 4 * i:][:4], 'little')
                for i in range(u32(codebook_at) // 4)] if codebook_at else []
    decode = _huffman_decoder(d, huffman, [x for x in (codebook_at, u32(0x40), len(d)) if x > huffman])
    p = start
    while p < end and d[p]:
        q, flags = p + 2, d[p + 1]
        q += bool(flags & 0x04)                 # quantized probability
        attribute = 0
        if flags & 0x20:                        # attribute codebook index
            attribute, q = d[q], q + 1
        case = 0
        if flags & 0x01:                        # explicit per-letter case mask
            case, q = u32(q), q + 4
        q += 4 * bool(flags & 0x40)             # affix data
        if flags & 0x10:
            word, q = decode(q)
            attributes = codebook[attribute] if attribute < len(codebook) else 0
            meta, categories = attributes & ~CATEGORY_BITS, attributes & CATEGORY_BITS
            if case:
                word = ''.join(c.upper() if case >> i & 1 else c for i, c in enumerate(word))
            elif meta & 1:
                word = word[:1].upper() + word[1:]
            if word:
                yield int.from_bytes(d[q:q + 3], 'big'), word, meta, categories
        p += d[p]


def _huffman_decoder(d, at, section_ends):
    """Canonical Huffman code; bits are read LSB-first and symbol 0 ends a string."""
    maxlen, end = d[at], min(section_ends)
    for width in (2, 1):                        # per-length counts are u16, or u8 in old files
        counts = [int.from_bytes(d[at + 1 + width * i:][:width], 'big') for i in range(maxlen)]
        symbols_at = at + 1 + width * maxlen
        if symbols_at + 4 * sum(counts) == end:
            break
    symbols = [int.from_bytes(d[symbols_at + 4 * i:][:4], 'big') for i in range(sum(counts))]
    first, index, code, total = [], [], 0, 0
    for count in counts:
        first.append(code)
        index.append(total)
        code, total = (code + count) << 1, total + count

    def decode(p):
        chars, bit = [], 0
        while True:
            code = length = 0
            while True:
                code = code << 1 | d[p + (bit >> 3)] >> (bit & 7) & 1
                bit += 1
                if 0 <= code - first[length] < counts[length]:
                    symbol = symbols[index[length] + code - first[length]]
                    break
                length += 1
            if not symbol:
                return ''.join(chars), p + (bit + 7 >> 3)
            chars.append(chr(symbol))
    return decode
