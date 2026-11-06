#!/usr/bin/env python3
"""Recover the iOS keyboard's phrase blocklists from the newest asset on Apple's servers.

usage: python3 recover.py [--lang en] [--out out] [--lexicon FILE] [--budget 1e12]

Writes to out/<lang>-<version>/:
  <surface>-tokens.csv       blocklist ID -> its spellings, e.g. 920,acid/acids
  <surface>-phrases.csv      every recovered key, with how its slot was resolved
  <surface>-condensed.md     the selected readable keys, factored as {a / b} c
  word-flags.csv             lexicon words labeled V (vulgar), O (offensive) or S (sensitive), with
                             their sensitive-policy categories (drugs, sex, violence, ...)
  summary.md                 per-length coverage
Surfaces are `default` (typing predictions) and `quickpath` (swipe), when the asset has them.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import itertools
import math
import shutil
import struct
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

import condense
import fetch
import lexicon

ROOT = Path(__file__).resolve().parent
SCAN = ROOT / 'build' / 'scan'
FULL_RANGE = 1e11  # also try compact IDs missing from the ID map when the search is this small
SELECTED = ('unique', 'single', 'cross-checked')  # statuses kept; 'unconfirmed', 'rejected' and 'ambiguous' are not


def build_scan():
    if SCAN.exists() and SCAN.stat().st_mtime > (ROOT / 'scan.c').stat().st_mtime:
        return
    SCAN.parent.mkdir(exist_ok=True)
    cc = shutil.which('cc') or shutil.which('clang') or shutil.which('gcc')
    base = [cc, '-O3', '-pthread', str(ROOT / 'scan.c'), '-o', str(SCAN)]
    if subprocess.run(base[:2] + ['-march=native'] + base[2:], capture_output=True).returncode:
        subprocess.run(base, check=True)


def run_scan(path, n, ids, seeds=()):
    """{tuple: slot} for the length-n tuples the table accepts (see scan.c for the modes)."""
    with tempfile.TemporaryDirectory() as tmp:
        id_file, seed_file = Path(tmp, 'ids'), Path(tmp, 'seeds')
        id_file.write_text(''.join(f'{i}\n' for i in ids))
        args = [SCAN, path, str(n), id_file]
        if seeds:
            seed_file.write_text(''.join(' '.join(map(str, s)) + '\n' for s in seeds))
            args.append(seed_file)
        out = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    return parse(out)


def run_pattern(path, domains):
    """Accepted tuples whose i-th ID comes from domains[i] (each a list of IDs or an 'a-b' range)."""
    with tempfile.TemporaryDirectory() as tmp:
        spec = Path(tmp, 'domains')
        spec.write_text(''.join((d if isinstance(d, str) else ' '.join(map(str, d))) + '\n' for d in domains))
        return parse(subprocess.run([SCAN, path, 'pattern', spec], check=True, capture_output=True, text=True).stdout)


def check(path, tuples):
    text = ''.join(' '.join(map(str, t)) + '\n' for t in tuples)
    return parse(subprocess.run([SCAN, path, 'check'], input=text, check=True, capture_output=True, text=True).stdout)


def parse(out):
    return {tuple(map(int, ids.split())): int(slot) for slot, ids in (line.split('\t') for line in out.splitlines())}


class Lexicon:
    """Token ID -> spellings, and spelling -> (V/O/S labels, category mask), from an extracted lexicon."""

    def __init__(self, path):
        self.words, self.flags, self.rank = defaultdict(list), {}, {}
        if path and Path(path).exists():
            with gzip.open(path, 'rt', encoding='utf-8') as source:
                for line in source:
                    token, labels, categories, word = line.rstrip('\n').split('\t')
                    self.words[int(token)].append(word)
                    if labels or categories:
                        self.flags[word] = labels, int(categories or '0', 16)
                    self.rank.setdefault(word, int(token))  # lower IDs are more frequent words

    def order(self, words):
        return sorted(dict.fromkeys(words), key=lambda w: (self.rank.get(w, math.inf), len(w), w))


class Table:
    """One packed blocklist (blocklist.dat) with its compact-ID -> spellings map."""

    def __init__(self, name, bundle, lex):
        self.name, self.path, self.lex = name, bundle / 'blocklist.dat', lex
        data = self.path.read_bytes()
        self.max_len, self.bound = struct.unpack_from('<I', data, 8)[0], struct.unpack_from('<I', data, 35)[0]
        self.slots, self.mph = {}, {}
        for n in range(1, self.max_len + 1):  # per-length descriptor; offsets count from byte 32
            mph_at, mph_size, _, row_size = struct.unpack_from('<4I', data, 39 + 20 * (n - 1))
            bits = sum(data[39 + 20 * (n - 1) + 17:][:3])
            if bits and row_size:
                self.slots[n] = row_size * 8 // bits
                self.mph[n] = hashlib.sha256(data[32 + mph_at:32 + mph_at + mph_size]).hexdigest()
        words = defaultdict(list)
        self.tokens = defaultdict(set)  # compact ID -> LM token IDs (assets with an ID map)
        self.by_token = {}              # LM token ID -> compact ID
        if (bundle / 'blocklistidmap.dat').exists():  # LM token ID -> compact ID, named by the lexicon
            raw = (bundle / 'blocklistidmap.dat').read_bytes()
            start, count = struct.unpack_from('<2I', raw, 12)
            for token, compact in sorted(struct.iter_unpack('<2I', raw[start:start + 8 * count])):
                words[compact] += lex.words.get(token, [])
                self.tokens[compact].add(token)
                self.by_token[token] = compact
        else:  # newer assets embed their own small lexicon whose token IDs are the compact IDs
            for path in bundle.glob('Unigrams-*.dat'):
                for compact, word, *_ in lexicon.entries(path):
                    words[compact].append(word)
        self.words = {c: lex.order(w) for c, w in words.items()}  # every mapped ID, spellings by frequency
        self.compacts = defaultdict(set)                          # spelling -> compact IDs
        for compact, spellings in self.words.items():
            for word in spellings:
                self.compacts[word].add(compact)

    def spell(self, compact):
        return self.words.get(compact, [])

    def show(self, compact):
        return (self.spell(compact) or [f'<{compact}>'])[0]


def recover(table, witnesses, budget, siblings=()):
    """Find keys length by length; return rows (length, slot, status, tuple, witnesses).

    siblings: (table, selected keys) of tables whose lists contain this one's (QuickPath's keys are
    a subset of the default list's), used to seed lengths too long to enumerate.
    """
    mapped, rows, selected = sorted(table.words), [], set()
    for n, slots in table.slots.items():
        exhaustive = True
        if (table.bound + 1) ** n <= FULL_RANGE:
            hits = run_scan(table.path, n, range(table.bound + 1))
        elif len(mapped) ** n <= budget:
            hits = run_scan(table.path, n, mapped)
        else:
            hits, exhaustive = grow(table, n, mapped, selected, budget, witnesses, siblings), False
        by_slot = defaultdict(list)
        for t, slot in hits.items():
            by_slot[slot].append(t)
        # Without exhaustive search a lone key is not guaranteed: a search over T tuples admits
        # about T / 2^32 random fingerprint matches, and those in empty slots look like keys. So a
        # lone key there needs another table's support or a family of 3+ keys one token apart.
        support = cross_support(table, [t for ts in by_slot.values() if len(ts) > 1 or not exhaustive
                                        for t in ts], witnesses)
        family = set() if exhaustive else families(hits)
        for slot, ts in sorted(by_slot.items()):
            backed = [t for t in ts if support[t]]
            for t in sorted(ts):
                if len(ts) == 1:
                    status = 'unique' if exhaustive else 'single' if support[t] or t in family else 'unconfirmed'
                elif len(backed) == 1:
                    status = 'cross-checked' if backed == [t] else 'rejected'
                else:
                    status = 'ambiguous'
                if status in SELECTED:
                    selected.add(t)
                rows.append((n, slot, status, t, support[t]))
        print(f'  {table.name} n={n}: {len(by_slot)}/{slots} slots, {len(hits)} keys, '
              f'{sum(len(ts) > 1 for ts in by_slot.values())} contested', flush=True)
    return rows


def grow(table, n, mapped, selected, budget, witnesses, siblings):
    """Keys too long to enumerate over the whole vocabulary.

    1. Keys of a containing table (QuickPath from default), translated and checked.
    2. Long keys are templates built from the words of shorter ones (`smoke a lot of weed`), and a
       token in the ID map that no key uses yet must occur in some unrecovered key. So every n-tuple
       over the tokens of the (n-1)-token keys plus the unused tokens is tried.
    3. One-token insertions into (n-1)-token keys and substitutions, until nothing new appears.
    4. ID pairs. Apple numbers compact IDs in order of first appearance in its phrase list
       (`pandemic of such scale destruction` is 1940 1198 1942 1943 1944), so two still-unused
       tokens with nearby IDs probably entered with the same phrase. Each pair is placed at every
       two positions, in ID order, with the rest over the mapped vocabulary. This search admits many
       random collisions, so a hit is kept only if another table accepts it or it belongs to a
       family of three or more keys one token apart. (Found the English `{Australia / India / ...}
       {is / was / ...} a very {bad / poor}` family.)
    """
    shorter = [t for t in selected if len(t) == n - 1]
    hits = check(table.path, {q for other, keys in siblings for t in keys if len(t) == n
                              for q in itertools.product(*(translate(other, table, x) for x in t))})
    used = {x for t in selected for x in t}
    domain = sorted({x for t in shorter for x in t} | (set(mapped) - used))
    if shorter and len(domain) ** n <= budget:
        hits |= run_scan(table.path, n, domain)
    hits = close(table, n, mapped, hits | (run_scan(table.path, n, mapped, shorter) if shorter else {}))
    # Tokens of random (unconfirmed) hits must not count as used, or real pairs are never tried.
    backed, family = cross_support(table, hits, witnesses), families(hits)
    unused = sorted(set(mapped) - used - {x for t in hits if backed[t] or t in family for x in t})
    places = list(itertools.combinations(range(n), 2))
    # The other positions range over the mapped vocabulary: a key using an ID absent from the map
    # could never be produced by typing, and the full compact range would cost ~100x more.
    rest = mapped if len(places) * len(mapped) ** (n - 2) <= budget else None
    found = {}
    for u, v in ((u, v) for u in unused for v in unused if 0 < v - u <= 4 and rest):
        for i, j in places:
            domains = [rest] * n
            domains[i], domains[j] = [u], [v]
            found |= {t: s for t, s in run_pattern(table.path, domains).items() if s not in hits.values()}
    backed, family = cross_support(table, found, witnesses), families(found)
    return close(table, n, mapped, hits | {t: s for t, s in found.items() if backed[t] or t in family})


def close(table, n, mapped, hits):
    """Add one-token substitutions of keys in hits, until nothing new appears."""
    frontier = hits
    while frontier:
        frontier = {t: s for t, s in run_scan(table.path, n, mapped, frontier).items() if t not in hits}
        hits = hits | frontier
    return hits


def families(tuples, size=3):
    """Tuples in connected groups of >= size whose members differ from another member in one place."""
    parent = {t: t for t in tuples}
    def root(t):
        while parent[t] != t:
            t = parent[t]
        return t
    groups = defaultdict(list)
    for t in tuples:
        for i in range(len(t)):
            groups[t[:i] + (None,) + t[i + 1:]].append(t)
    for group in groups.values():
        for t in group[1:]:
            parent[root(t)] = root(group[0])
    count = defaultdict(int)
    for t in tuples:
        count[root(t)] += 1
    return {t for t in tuples if count[root(t)] >= size}


def translate(table, other, compact):
    """IDs in another table for the same token: shared spellings, or shared LM token IDs."""
    return ({c for w in table.spell(compact) for c in other.compacts[w]} |
            {other.by_token[k] for k in table.tokens[compact] if k in other.by_token})


def cross_support(table, tuples, witnesses):
    """Which other tables also accept each tuple, after translating it into their compact IDs.

    Every occupied slot holds one real key, but a 32-bit fingerprint lets random tuples collide
    with it. A differently built table (another version or surface, with a different MPH for that
    length) is an independent membership test: real keys tend to recur there, collisions do not.
    IDs are translated through shared spellings and, between ID-map assets, shared LM token IDs,
    which also carries tokens that have no spelling.
    """
    support = defaultdict(list)
    for witness in witnesses:
        queries = defaultdict(set)
        for t in tuples:
            if witness.mph.get(len(t), table.mph[len(t)]) == table.mph[len(t)]:
                continue  # length absent there, or the very same table
            options = [translate(table, witness, x) for x in t]
            if 0 < math.prod(map(len, options)) <= 512:
                for q in itertools.product(*options):
                    queries[q].add(t)
        for q in check(witness.path, queries):
            for t in queries[q]:
                support[t].append(witness.name)
    return support


def write_outputs(out, lang, label, surface, table, rows):
    prefix = out / surface
    with open(f'{prefix}-tokens.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['blocklist_id', 'words'])
        w.writerows([c, '/'.join(table.words[c])] for c in sorted(table.words))
    with open(f'{prefix}-phrases.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['tokens', 'slot', 'status', 'phrase', 'blocklist_ids', 'also_in'])
        for n, slot, status, t, also in rows:
            w.writerow([n, slot, status, ' '.join(map(table.show, t)), ' '.join(map(str, t)), ' '.join(also)])
    chosen = [t for _, _, status, t, _ in rows if status in SELECTED]
    readable = {tuple(map(table.show, t)) for t in chosen if all(map(table.spell, t))}
    intro = (f'Recovered keys of the {surface} phrase blocklist in Apple\'s `{lang}` keyboard asset {label}: '
             f'{len(readable):,} readable keys. {len(chosen) - len(readable):,} more selected keys contain a '
             f'token without a known spelling and are only in `{surface}-phrases.csv`. Each token is shown by '
             f'one spelling; `{surface}-tokens.csv` lists all spellings that share its ID. `{{a / b}} {{c / d}}` '
             'expands to four phrases; lines are unioned.')
    Path(f'{prefix}-condensed.md').write_text(
        condense.markdown(f'{lang} {label} {surface} phrase blocklist', intro, readable), encoding='utf-8')


def summarize(table, rows):
    lines = [f'### {table.name}', '', '| tokens | slots | slots with a key | settled by other tables | '
             'still ambiguous | lone keys from non-exhaustive search (with support) | unconfirmed (left out) |',
             '|---:|---:|---:|---:|---:|---:|---:|']
    for n, slots in table.slots.items():
        mine = [r for r in rows if r[0] == n]
        single = [r for r in mine if r[2] == 'single']
        lines.append(f'| {n} | {slots:,} | {len({r[1] for r in mine if r[2] in SELECTED}):,} | '
                     f'{sum(r[2] == "cross-checked" for r in mine):,} | {len({r[1] for r in mine if r[2] == "ambiguous"}):,} | '
                     f'{len(single):,} ({sum(bool(r[4]) for r in single):,}) | {sum(r[2] == "unconfirmed" for r in mine):,} |')
    used = {x for r in rows if r[2] in SELECTED for x in r[3]}
    unused = [c for c in sorted(table.words) if c not in used]
    short = lambda c: '/'.join(table.words[c][:3]) + ('/…' if len(table.words[c]) > 3 else '') or '(no spelling)'
    lines += ['', f'ID-map tokens in no selected key ({len(unused)}): ' + ', '.join(f'{c} {short(c)}' for c in unused)]
    unmapped = sorted({x for x in used if x not in table.words})
    if unmapped:
        lines.append(f'IDs used by keys but absent from the ID map, so no typed word can produce them ({len(unmapped)}): ' +
                     ', '.join(map(str, unmapped)))
    return lines + ['']


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--lang', default='en', help='asset language, e.g. en, es, fr, de')
    parser.add_argument('--out', type=Path, default=ROOT / 'out')
    parser.add_argument('--lexicon', type=Path, help='extracted lexicon (default: data/<lang>-lexicon.tsv.gz)')
    parser.add_argument('--budget', type=float, default=1e12, help='largest exhaustive search, in tuples')
    parser.add_argument('--bundle', type=Path, help='recover a local <lang>.lm directory (e.g. from an iOS '
                        'release) instead of the newest served asset, which then serves as a witness')
    parser.add_argument('--label', default='local', help='version label for --bundle')
    args = parser.parse_args()
    lex = Lexicon(args.lexicon or ROOT / 'data' / f'{args.lang}-lexicon.tsv.gz')
    build_scan()

    tables = {}
    if args.bundle:
        for surface, bundle in fetch.SURFACES.items():
            if (args.bundle / bundle / 'blocklist.dat').exists():
                tables[args.label, surface] = Table(f'{args.label}-{surface}', args.bundle / bundle, lex)
    served = fetch.versions(args.lang)
    for label, url in served:
        print(f'fetching {args.lang} {label}', flush=True)
        for surface, bundle in fetch.download(args.lang, label, url, ROOT / 'cache').items():
            tables[label, surface] = Table(f'{label}-{surface}', bundle, lex)
    if not tables:
        raise SystemExit(f'no keyboard blocklist for {args.lang!r}')
    subject = next(iter(tables))[0]  # --bundle, else the newest served version
    out = args.out / f'{args.lang}-{subject}'
    out.mkdir(parents=True, exist_ok=True)

    results = {}
    for (label, surface), table in tables.items():
        if label == subject:
            witnesses = [t for key, t in tables.items() if key != (label, surface)]
            siblings = [(t, {k for _, _, st, k, _ in rows if st in SELECTED}) for t, rows in results.values()]
            results[surface] = table, recover(table, witnesses, args.budget, siblings)
    summary = [f'# {args.lang} {subject}', '',
               f'Witness tables: {", ".join(t.name for (label, _), t in tables.items() if label != subject) or "none"}.', '']
    for surface, (table, rows) in results.items():
        write_outputs(out, args.lang, subject, surface, table, rows)
        summary += summarize(table, rows)

    if {'default', 'quickpath'} <= results.keys():  # QuickPath's list should be a subset of the default list
        (qp, rows), default = results['quickpath'], results['default'][0]
        keys = [t for _, _, status, t, _ in rows if status in SELECTED]
        testable = [t for t in keys if all(translate(qp, default, x) for x in t)]
        also = cross_support(qp, testable, [default])
        summary.append(f'QuickPath keys also in the default table: {sum(map(bool, also.values())):,} of {len(testable):,} '
                       f'translatable ({len(keys) - len(testable):,} contain a token with no spelling or LM token).\n')
    # Every lexicon word with a V/O/S label or a sensitive-policy category; categories are named
    # by the observed groupings in lexicon.CATEGORIES (approximate; Apple does not name them).
    flagged = sorted(((labels, '/'.join(name for bit, name in lexicon.CATEGORIES.items() if mask & bit), word)
                      for word, (labels, mask) in lex.flags.items()),
                     key=lambda r: ({'V': 0, 'O': 1, 'S': 2}.get(r[0][:1], 3), r[1], r[2].casefold(), r[2]))
    with open(out / 'word-flags.csv', 'w', newline='', encoding='utf-8') as f:
        csv.writer(f).writerows([('label', 'categories', 'word'), *flagged])
    summary.append(f'{sum(bool(r[0]) for r in flagged):,} V/O/S-labeled and {sum(bool(r[1]) for r in flagged):,} '
                   'categorized lexicon words' + ('.' if flagged else ' (no lexicon file for this language).'))
    (out / 'summary.md').write_text('\n'.join(summary) + '\n')
    print('\n'.join(summary))


if __name__ == '__main__':
    main()
