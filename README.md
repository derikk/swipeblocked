# swipeblocked

Recover the phrase blocklists built into the iPhone keyboard from Apple's own files.

The code behind [swipeblocked.com](https://swipeblocked.com), which publishes the lists and explains
how they were decoded ([how it works](https://swipeblocked.com/how.html)).

This package downloads the newest keyboard language asset from Apple's servers and recovers the
phrases the iOS keyboard will not predict. It needs Python 3.9+, a C compiler (`cc`, `clang` or
`gcc`) and network access, and runs on macOS or Linux without Apple frameworks.

```sh
python3 recover.py              # English: about 10 minutes on 8 CPU cores
python3 recover.py --lang de    # any language in the table below
```

Options: `--out DIR` (default `out/`), `--budget N` (largest exhaustive search in tuples, default
10^12; raise it to search longer keys harder), `--lexicon FILE` (override `data/<lang>-lexicon.tsv.gz`),
and `--bundle DIR --label NAME` (recover a local `<lang>.lm` directory instead, see *Limits*). Downloads
are cached in `cache/` and the scanner is compiled into `build/` on first use.

Outputs go to `out/<lang>-<version>/`, for example `out/en-c17-449/`:

| File | Contents |
|---|---|
| `default-tokens.csv`, `quickpath-tokens.csv` | Blocklist ID and all spellings that share it, e.g. `920,acid/acids` (empty if none known) |
| `default-condensed.md`, `quickpath-condensed.md` | Selected readable keys by length, factored as `{a / b} c` (expands exactly) |
| `default-phrases.csv`, `quickpath-phrases.csv` | Every key found, with its slot, its status and the other tables that accept it |
| `word-flags.csv` | Lexicon words labeled `V` vulgar, `O` offensive or `S` sensitive, with their sensitive-policy categories (below) |
| `summary.md` | Per-length coverage, unused tokens, unmapped IDs, QuickPath-in-default check |

`default` drives typing predictions; `quickpath` drives swipe typing and should be a subset of `default`.

| File | Role |
|---|---|
| `recover.py` | Driver: download, name tokens, search, resolve collisions, write outputs |
| `fetch.py` | Queries Apple's asset catalog; range-reads only the blocklist files from the asset ZIPs |
| `scan.c` | Fast key search and the exact membership test (built automatically into `build/scan`) |
| `lexicon.py` | Reads Apple lexicon files (`Unigrams-*.dat`, `Delta-*.dat`) without Apple frameworks |
| `condense.py` | Factors phrase sets into `{a / b}` lines |
| `extract_lexicon.py`, `data/*-lexicon.tsv.gz` | Word lists extracted from iOS lexicons (step 2); sources in `data/SOURCES.tsv` |

## Languages

From recoveries of the newest served tables (content version c17-449):

| Status | Languages | Notes |
|---|---|---|
| Complete | en | Every slot of both tables at every length |
| Words come with the download | bn, da, de, es, fr, gu, he, hi, it, mr, pa, ta, te | Long tables of de, es, fr, it, hi, pa stay partial. da and he have no shipped lexicon, so no word flags |
| Words from the shipped lexicon | ar, nl, pl, pt, sv, th, vi | The ID map points at the system lexicon's token IDs |
| Partly readable | ru, tr, ko | Their keyboards compute token IDs from stems plus suffixes, which this package does not rebuild; Turkish's 7,440-token vocabulary also limits exhaustive search to three tokens |
| Not supported | zh-Hans, zh-Hant, yue-Hant, ja | Chinese tables are keyed by language-model token IDs in `Chinese.lm`; Japanese uses a plain-text list in another asset |

## Word flags and categories

Each lexicon entry can carry `V`, `O` or `S`, and a category mask that the sensitive (`S`) policy
checks per lookup type (completions and predictions use every category, QuickPath a subset).
Apple does not name the bits. `word-flags.csv` names them by the groupings observed in the iOS 26.3.1
English lexicon: `bodily` 0x100, `anatomy` 0x200, `derogatory` 0x400, `disease` 0x800, `drugs` 0x1000,
`politics` 0x2000, `religion` 0x4000, `sex` 0x8000, `violence` 0x10000, `weapons` 0x20000 and
`mixed` 0x40000. They are approximate, a word can have several, and a category alone does not mean
the word is suppressed. [Word labels](https://swipeblocked.com/labels.html) on the site describes what
each label does. Checked against Apple's Lexicon.framework (macOS 15.7, on its own English lexicon): words,
V/O/S and categories agree on every entry, including all 4,746 categorized ones.


## How it works

1. **Download.** `gdmf.apple.com` lists the LinguisticData assets served to an iPhone on iOS
   27.0. Every served version with a keyboard model for the language is used: the newest is
   the subject, and the older ones are witnesses (step 5). Only
   `AssetData/<lang>.lm/{blocklist,qp_blocklist}.bundle/*.dat` are read, a few KB per table,
   through HTTP range requests. They are cached in `cache/`.

2. **Name tokens.** A key is a tuple of *compact IDs*. English assets map LM token IDs to compact
   IDs in `blocklistidmap.dat`. The spellings of those token IDs live in the lexicon built into
   iOS, not in the downloadable asset. The package therefore ships that word list:
   `data/en-lexicon.tsv.gz`, extracted from the iOS 27.0 `Unigrams-en.dat` and
   `Delta-en_US.dat` with `extract_lexicon.py`. The macOS 15.7 lexicon lacks a few tokens, such
   as `x`. Newer assets for other languages embed their own `Unigrams-<lang>.dat`, keyed directly
   by compact ID, and need no extra file. One compact ID can cover several words (`acid/acids`,
   `left/right`). The condensed lists show the most frequent spelling; `-tokens.csv` shows all.

3. **Search (fast hashing).** Each length has its own table: a CHD minimal perfect hash from
   cmph, plus one row per slot holding the key's 32-bit Jenkins `lookup3` fingerprint. `scan`
   enumerates every tuple whenever the space is at most `--budget` (default 10^12, which covers
   English lengths 2–4). For each prefix it computes the Jenkins state once, then hashes blocks of
   last tokens in a vectorized loop, with the parts of the final mix that don't depend on
   the last token hoisted out of the loop. A cache-sized bit filter and an exact fingerprint set
   discard almost every tuple. Longer keys:
   - QuickPath's list is a subset of the default list, so the default table's keys are translated
     into QuickPath IDs and checked first;
   - every tuple over the tokens of the shorter keys plus the *unused* tokens (in the ID map but in
     no key yet; each must belong to some unrecovered key);
   - one-token insertions into shorter keys and one-token substitutions, until nothing new
     appears;
   - **unused-ID pairs.** Apple numbers compact IDs in order of first appearance in its phrase
     list (`pandemic of such scale destruction` is 1940 1198 1942 1943 1944), so two unused tokens
     whose IDs are at most 4 apart probably entered with the same phrase. Each pair is placed at
     every two positions, in ID order, with the other positions over the mapped vocabulary. This search
     admits many random collisions, so a hit is kept only if another table accepts it (step 5) or
     it belongs to a family of three or more keys one token apart.

   For English, these steps find every six-token key (the `is the number one most …` family) and
   the five-token `{Australia / India / Kenya / Nepal / Pakistan / US} {is / was / …} a very
   {bad / poor}` family. The pair search came out of looking for where the unused token 1645
   `Australia/India/…` occurs. `scan.c` also has a `pattern` mode for per-position ID domains,
   used by that search.

4. **Exact membership.** A fingerprint match alone is not membership. `scan` reimplements
   `cmph_search_packed` and accepts a tuple only if the MPH sends it to the slot whose
   fingerprint matches, which is the keyboard runtime's own test. It agreed with macOS's
   `libcmph` on 5.4 million lookups across five tables. Apple's build hashes key bytes as signed
   `char`, which matters for IDs such as `0x0efd`.

5. **Ruling out false positives.** Each slot holds one real key, but a 32-bit fingerprint lets
   random tuples reach it: about `tuples / 2^32`, roughly 170 for English four-token keys. Every
   candidate in a contested slot, and every key from a non-exhaustive search, is translated into
   each *other* table: the other surface and the older served versions. Translation goes through
   shared spellings and shared LM token IDs, which also carries tokens with no spelling. The
   candidate is then tested there, counting only tables whose MPH for that length differs. Real
   phrases recur across independently built tables; random collisions do not. A slot with
   exactly one supported candidate is `cross-checked` and its rivals are `rejected`. Zero or
   several leaves it `ambiguous` and out of the condensed lists. The same test guards lengths that
   were not searched exhaustively. There, a search over T tuples admits about T / 2^32 random matches,
   and in an empty slot such a match looks like a lone key. So a lone key counts only if another table
   accepts it or it belongs to a family of three or more keys one token apart. Otherwise it is
   `unconfirmed` and left out. (An earlier version skipped this check, which let 137 random Spanish
   six-token tuples through.) No language-model score or human
   choice is involved. For English c17-449 this settles all 158 + 98 contested four-token slots.

## Limits

- Recovery shows table membership, not Apple's source spelling. A compact ID can stand for
  unrelated words (c17-449 groups `conspiracies` with `propaganda`), and the condensed lists
  show only one of them.
- Some keys use IDs that no served version's ID map lists, so no typed word can produce them,
  and some use tokens the lexicon cannot spell. One example is compact 1870, whose four LM tokens
  sit alphabetically between `mulattos'` and `neger`. Both appear as `<ID>` in `-phrases.csv`
  and are left out of the condensed lists. `summary.md` lists them.
- Lengths beyond the exhaustive budget are searched heuristically. For English c17-449 every
  slot now gets a key, but for other languages long tables can stay partial; `summary.md`
  reports the gaps and any still-unused tokens.
- Cross-table support is evidence, not proof. A phrase new in the latest version has no older
  witness unless the other surface carries it.
- The iOS 27.0 *built-in* English tables are newer than any served asset; they add, for example,
  `Zionist propaganda`. They ship only inside iOS images: an AEA-encrypted IPSW or a multi-GB
  Simulator runtime. `--bundle <path to en.lm> --label ios-27.0` recovers such a local copy,
  using the served assets as witnesses.
- The shipped lexicons keep only entries the currently served assets use, plus every flagged or
  categorized word. If Apple serves new tokens, re-extract with `extract_lexicon.py` from a Mac or iOS
  image's `RequiredAssets_<lang>.bundle` (Apple frameworks are not needed, only the files). Most come
  from iOS 17.x built-ins, the newest we had for those languages; token IDs were stable across the
  versions checked.

## License

The code is MIT-licensed; see `LICENSE`. The word lists in `data/` are extracted from Apple's iOS
keyboard lexicons (sources in `data/SOURCES.tsv`) and are included so the recovered lists can be
reproduced and checked. This project is not affiliated with Apple.
