"""Factor a set of equal-length phrases into exactly-expanding lines like `{a / b} c {d / e}`."""
from __future__ import annotations

from collections import defaultdict


def sort_key(text: str) -> tuple[str, str]:
    return text.casefold(), text


def alternatives(words) -> str:
    words = sorted(words, key=sort_key)
    return words[0] if len(words) == 1 else '{' + ' / '.join(words) + '}'


def condense(phrases: set[tuple[str, ...]]) -> list[tuple[str, set[tuple[str, ...]]]]:
    """Return (line, phrases it expands to) pairs whose union is exactly `phrases`.

    Heads that share the same set of continuations are merged, recursively.
    """
    if len(next(iter(phrases))) == 1:
        return [(alternatives(p[0] for p in phrases), phrases)]
    tails = defaultdict(set)
    for phrase in phrases:
        tails[phrase[0]].add(phrase[1:])
    heads = defaultdict(list)
    for head, rest in tails.items():
        heads[frozenset(rest)].append(head)
    lines = []
    for rest, group in heads.items():
        for text, members in condense(set(rest)):
            lines.append((f'{alternatives(group)} {text}', {(h,) + m for h in group for m in members}))
    lines.sort(key=lambda line: sort_key(line[0]))
    assert set().union(*(members for _, members in lines)) == phrases
    return lines


def markdown(title: str, intro: str, phrases: set[tuple[str, ...]]) -> str:
    out = [f'# {title}', '', intro, '']
    for n in sorted({len(p) for p in phrases}):
        lines = condense({p for p in phrases if len(p) == n})
        count = sum(len(p) == n for p in phrases)
        out += [f'## {n} tokens: {count:,} tuples in {len(lines):,} factored lines', '', '```text',
                *(text for text, _ in lines), '```', '']
    return '\n'.join(out)
