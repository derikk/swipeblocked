// scan: find the keys of an Apple keyboard phrase blocklist (blocklist.dat, format 3).
//
//   scan BLOCKLIST.dat N IDS.txt              try every N-tuple of the compact IDs in IDS.txt
//   scan BLOCKLIST.dat pattern DOMAINS.txt    try every tuple whose i-th ID comes from line i of
//                                             DOMAINS.txt (space-separated IDs or lo-hi ranges)
//   scan BLOCKLIST.dat N IDS.txt SEEDS.txt    try every one-ID insertion into the (N-1)-tuples and
//                                             every one-ID substitution into the N-tuples in SEEDS.txt
//   scan BLOCKLIST.dat check < TUPLES.txt     test the given tuples (any length)
//
// Prints "slot<TAB>id id ..." for each tuple the table accepts: the table's minimal perfect hash
// (cmph's packed CHD, reimplemented below) sends the tuple to a slot, and the 32-bit Jenkins
// fingerprint stored there equals the tuple's. That is the keyboard runtime's exact membership test.
//
// The exhaustive search is the fast path: for each (N-1)-token prefix the Jenkins state is computed
// once, then a block of last tokens is hashed in a branch-free loop the compiler vectorizes. Hashes
// go through a cache-resident bit filter and an exact fingerprint set; only the rare survivors pay
// for an MPH lookup.
//
// build: cc -O3 -march=native -pthread scan.c -o scan
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXN 8
#define BLOCK 1024
#define ROT(x, k) (((x) << (k)) | ((x) >> (32 - (k))))
#define MIX(a, b, c) { \
  a -= c; a ^= ROT(c, 4);  c += b; b -= a; b ^= ROT(a, 6);  a += c; \
  c -= b; c ^= ROT(b, 8);  b += a; a -= c; a ^= ROT(c, 16); c += b; \
  b -= a; b ^= ROT(a, 19); a += c; c -= b; c ^= ROT(b, 4);  b += a; }
#define FINAL(a, b, c) { \
  c ^= b; c -= ROT(b, 14); a ^= c; a -= ROT(c, 11); b ^= a; b -= ROT(a, 25); \
  c ^= b; c -= ROT(b, 16); a ^= c; a -= ROT(c, 4);  b ^= a; b -= ROT(a, 14); \
  c ^= b; c -= ROT(b, 24); }

static const uint8_t *mph, *rows;   // the length-N table
static uint32_t row_bytes, slots, n;
static uint32_t *set, set_mask;     // open-addressed set of stored fingerprints
static uint8_t *filter;             // one bit per (fingerprint & filter_mask)
static uint32_t filter_mask;
static uint32_t *ids, nids;         // all-position domain (N-tuple and seeded modes)
static uint32_t *dom[MAXN], dlen[MAXN];  // per-position domains of the exhaustive search
static pthread_mutex_t out_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t u32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

// Bob Jenkins' lookup3 hashword() with initval 0.
static uint32_t hashword(const uint32_t *k, uint32_t len) {
  uint32_t a, b, c;
  a = b = c = 0xdeadbeef + 4 * len;
  for (; len > 3; len -= 3, k += 3) { a += k[0]; b += k[1]; c += k[2]; MIX(a, b, c); }
  switch (len) { case 3: c += k[2]; case 2: b += k[1]; case 1: a += k[0]; FINAL(a, b, c); }
  return c;
}

// ---- cmph's packed CHD minimal perfect hash (cmph_search_packed), reimplemented ----
// All fields are little-endian uint32 words. Bit vectors are read LSB-first.
#define W(p, i) u32((p) + 4 * (i))
static uint32_t bit(const uint8_t *v, uint32_t i) { return v[i >> 3] >> (i & 7) & 1; }

static uint32_t bits(const uint8_t *v, uint32_t pos, uint32_t len) {  // len <= 32 bits at pos
  uint64_t x = W(v, pos >> 5) | (uint64_t)W(v, (pos >> 5) + 1) << 32;
  return len ? (uint32_t)(x >> (pos & 31)) & (uint32_t)(~0ull >> (64 - len)) : 0;
}

// cmph select structure: n, m, a bit vector of n+m bits, then the position of every 128th one.
static uint32_t select_one(const uint8_t *sel, uint32_t i) {  // position of the i-th one bit
  const uint8_t *v = sel + 8;
  uint32_t pos = W(v + 4 * ((W(sel, 0) + W(sel, 1) + 31) >> 5), i >> 7);
  for (uint32_t left = i & 127;; pos++)
    if (bit(v, pos) && !left--) return pos;
}

static uint32_t select_next(const uint8_t *sel, uint32_t pos) {  // next one bit after pos
  while (!bit(sel + 8, ++pos)) {}
  return pos;
}

// cmph's lookup2-style vector hash, as compiled by Apple: key bytes are signed chars, except that
// the tail casts the first byte of each word to uint8. Keys here are always whole uint32 words.
static uint32_t key_word(const uint8_t *k, int tail) {
  return (tail ? k[0] : (uint32_t)(int8_t)k[0]) + ((uint32_t)(int8_t)k[1] << 8) +
         ((uint32_t)(int8_t)k[2] << 16) + ((uint32_t)k[3] << 24);
}

static void jenkins_vector(uint32_t seed, const uint8_t *k, uint32_t len, uint32_t h[3]) {
  uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = seed, rest = len;
#define MIX2(a, b, c) { a -= b; a -= c; a ^= c >> 13; b -= c; b -= a; b ^= a << 8;  c -= a; c -= b; c ^= b >> 13; \
                        a -= b; a -= c; a ^= c >> 12; b -= c; b -= a; b ^= a << 16; c -= a; c -= b; c ^= b >> 5;  \
                        a -= b; a -= c; a ^= c >> 3;  b -= c; b -= a; b ^= a << 10; c -= a; c -= b; c ^= b >> 15; }
  for (; rest >= 12; rest -= 12, k += 12) { a += key_word(k, 0); b += key_word(k + 4, 0); c += key_word(k + 8, 0); MIX2(a, b, c); }
  c += len;
  if (rest >= 4) a += key_word(k, 1);
  if (rest >= 8) b += key_word(k + 4, 1);
  MIX2(a, b, c);
  h[0] = a, h[1] = b, h[2] = c;
}

static uint32_t compressed_seq(const uint8_t *cs, uint32_t i) {
  uint32_t n = W(cs, 0), r = W(cs, 1);
  const uint8_t *sel = cs + 16, *rems = sel + W(cs, 3), *store = rems + 4 * ((n * r + 31) >> 5);
  uint32_t start = 0, s;
  if (i == 0) s = select_one(sel, 0);
  else {
    s = select_one(sel, i - 1);
    start = ((s - (i - 1)) << r) + bits(rems, (i - 1) * r, r);
    s = select_next(sel, s);
  }
  uint32_t len = ((s - i) << r) + bits(rems, i * r, r) - start;
  return len ? bits(store, start, len) + ((1u << len) - 1) : 0;
}

static uint32_t compressed_rank(const uint8_t *cr, uint32_t i) {
  uint32_t max = W(cr, 0), n = W(cr, 1), r = W(cr, 2);
  const uint8_t *sel = cr + 16, *v = sel + 8, *rems = sel + W(cr, 3);
  if (i > max) return n;
  uint32_t q = i >> r, rem = i & ((1u << r) - 1), s = 0, rank = 0;
  if (q) s = select_one(sel, q - 1) + 1, rank = s - q;
  for (; !bit(v, s) && bits(rems, rank * r, r) < rem; s++) rank++;
  return rank;
}

static uint32_t chd_search(const uint8_t *p, const uint32_t *key, uint32_t len) {
  // p: algorithm id (8 = CHD), size and rank structure of the empty bins, size of the CHD-PH
  // function, then that function: algorithm id (7), hash type (0 = Jenkins), seed, bins, buckets.
  const uint8_t *cr = p + 8, *ph = cr + W(p, 1) + 4;
  uint32_t m = W(ph, 3), buckets = W(ph, 4), h[3];
  jenkins_vector(W(ph, 2), (const uint8_t *)key, 4 * len, h);
  uint32_t d = compressed_seq(ph + 20, h[0] % buckets);
  uint32_t bin = (uint32_t)((h[1] % m + (uint64_t)(h[2] % (m - 1) + 1) * (d % m) + d / m) % m);
  return bin - compressed_rank(cr, bin);
}

static int load_table(const uint8_t *file, uint32_t len) {
  if (u32(file) != 0x87c2472f || u32(file + 4) != 3 || len < 1 || len > u32(file + 8)) return 0;
  const uint8_t *d = file + 39 + 20 * (len - 1);  // per-length descriptor; offsets are from byte 32
  uint32_t bits = d[17] + d[18] + d[19];
  if (d[17] != 32 || !bits) return 0;
  mph = file + 32 + u32(d), rows = file + 32 + u32(d + 8);
  row_bytes = bits / 8, slots = u32(d + 12) * 8 / bits, n = len;
  return slots && u32(d + 4);  // an empty length has no MPH
}

static int accept(const uint32_t *t, uint32_t len, uint32_t *slot) {
  *slot = chd_search(mph, t, len);
  return *slot < slots && u32(rows + *slot * row_bytes) == hashword(t, len);
}

static void report(const uint32_t *t, uint32_t len) {
  uint32_t slot;
  if (!accept(t, len, &slot)) return;
  pthread_mutex_lock(&out_lock);
  printf("%u\t", slot);
  for (uint32_t i = 0; i < len; i++) printf(i ? " %u" : "%u", t[i]);
  putchar('\n');
  pthread_mutex_unlock(&out_lock);
}

static uint32_t set_slot(uint32_t h) { return (uint32_t)((h * 0x9e3779b97f4a7c15ull) >> 32) & set_mask; }

static int stored(uint32_t h) {
  if (!(filter[(h & filter_mask) >> 3] >> (h & 7) & 1)) return 0;
  for (uint32_t s = set_slot(h); set[s]; s = (s + 1) & set_mask)
    if (set[s] == h) return 1;
  return h == 0;  // 0 marks empty set cells; let the exact check decide
}

static void build_set(void) {
  uint32_t size = 1, fbits = 1u << 20;
  while (size < slots * 4) size <<= 1;
  while (fbits < slots * 32 && fbits < 1u << 24) fbits <<= 1;
  set = calloc(size, 4), set_mask = size - 1;
  filter = calloc(fbits / 8, 1), filter_mask = fbits - 1;
  for (uint32_t i = 0; i < slots; i++) {
    uint32_t h = u32(rows + i * row_bytes), s = set_slot(h);
    filter[(h & filter_mask) >> 3] |= 1 << (h & 7);
    while (set[s]) s = (s + 1) & set_mask;
    set[s] = h;
  }
}

// Hash a block of last tokens w[0..m) added to Jenkins register r of a prefix state. The parts of
// final() that do not depend on the last token are hoisted out of the loop; each loop is
// branch-free so the compiler vectorizes it.
static void hash_block(uint32_t r, const uint32_t s[3], const uint32_t *w, uint32_t m, uint32_t *out) {
  const uint32_t a = s[0], b = s[1], c = s[2];
  if (r == 0) {
    const uint32_t c1 = (c ^ b) - ROT(b, 14), rc1 = ROT(c1, 11);
    for (uint32_t j = 0; j < m; j++) {
      uint32_t A = ((a + w[j]) ^ c1) - rc1, B = (b ^ A) - ROT(A, 25), C = (c1 ^ B) - ROT(B, 16);
      A = (A ^ C) - ROT(C, 4); B = (B ^ A) - ROT(A, 14); out[j] = (C ^ B) - ROT(B, 24);
    }
  } else if (r == 1) {
    for (uint32_t j = 0; j < m; j++) {
      uint32_t A = a, B = b + w[j], C = c;
      FINAL(A, B, C);
      out[j] = C;
    }
  } else {
    const uint32_t rb14 = ROT(b, 14);
    for (uint32_t j = 0; j < m; j++) {
      uint32_t C = ((c + w[j]) ^ b) - rb14, A = (a ^ C) - ROT(C, 11), B = (b ^ A) - ROT(A, 25);
      C = (C ^ B) - ROT(B, 16); A = (A ^ C) - ROT(C, 4); B = (B ^ A) - ROT(A, 14); out[j] = (C ^ B) - ROT(B, 24);
    }
  }
}

// Exhaustive search over dom[0] x ... x dom[n-1]. Threads take first tokens from a shared counter,
// the other prefix tokens run as an odometer, and the last token is added to whichever Jenkins
// register it lands in.
static uint32_t next_first;

static void *exhaustive_worker(void *unused) {
  (void)unused;
  const uint32_t r = (n - 1) % 3, mixed = (n - 1) / 3;  // last token's register, full blocks before it
  uint32_t idx[MAXN], t[MAXN], hv[BLOCK];
  for (uint32_t first; (first = __atomic_fetch_add(&next_first, 1, __ATOMIC_RELAXED)) < dlen[0];) {
    memset(idx, 0, sizeof idx);
    idx[0] = first;
    for (;;) {
      for (uint32_t i = 0; i + 1 < n; i++) t[i] = dom[i][idx[i]];
      uint32_t a, b, c;
      a = b = c = 0xdeadbeef + 4 * n;
      for (uint32_t k = 0; k < mixed; k++) { a += t[3*k]; b += t[3*k+1]; c += t[3*k+2]; MIX(a, b, c); }
      uint32_t state[3] = {a, b, c};
      for (uint32_t i = 3 * mixed; i + 1 < n; i++) state[i - 3 * mixed] += t[i];
      const uint32_t *last = dom[n - 1], nlast = dlen[n - 1];
      for (uint32_t lo = 0; lo < nlast; lo += BLOCK) {
        uint32_t m = nlast - lo < BLOCK ? nlast - lo : BLOCK;
        hash_block(r, state, last + lo, m, hv);
        for (uint32_t j = 0; j < m; j++)
          if (stored(hv[j])) { t[n - 1] = last[lo + j]; report(t, n); }
      }
      int p = n - 2;  // advance the odometer over prefix positions 1..n-2
      while (p >= 1 && ++idx[p] == dlen[p]) idx[p--] = 0;
      if (p < 1) break;
    }
  }
  return NULL;
}

static void seeded(FILE *seeds) {
  uint32_t s[MAXN + 1], t[MAXN], len;
  char line[512];
  while (fgets(line, sizeof line, seeds)) {
    char *p = line, *end;
    for (len = 0; len <= MAXN; len++, p = end) {
      s[len] = (uint32_t)strtoul(p, &end, 10);
      if (end == p) break;
    }
    if (len == n - 1) {  // insert one ID at every position
      for (uint32_t pos = 0; pos < n; pos++)
        for (uint32_t k = 0; k < nids; k++) {
          for (uint32_t i = 0, j = 0; i < n; i++) t[i] = i == pos ? ids[k] : s[j++];
          if (stored(hashword(t, n))) report(t, n);
        }
    } else if (len == n) {  // substitute one ID at every position
      for (uint32_t pos = 0; pos < n; pos++)
        for (uint32_t k = 0; k < nids; k++) {
          memcpy(t, s, 4 * n);
          t[pos] = ids[k];
          if (stored(hashword(t, n))) report(t, n);
        }
    }
  }
}

static uint8_t *read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) { perror(path); exit(2); }
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  rewind(f);
  uint8_t *data = calloc(size + 8, 1);  // padding: bit-field reads may touch the next word
  if (fread(data, 1, size, f) != (size_t)size) exit(2);
  fclose(f);
  return data;
}

static uint32_t read_ids(char *text, uint32_t **out) {  // "1 2 5-9" -> {1, 2, 5, ..., 9}
  uint32_t count = 0, cap = 1024, *v = malloc(4 * cap);
  for (char *p = strtok(text, " \t\n"); p; p = strtok(NULL, " \t\n")) {
    unsigned lo, hi;
    int k = sscanf(p, "%u-%u", &lo, &hi);
    if (k < 1) continue;
    for (unsigned x = lo; x <= (k == 2 ? hi : lo); x++) {
      if (count == cap) v = realloc(v, 4 * (cap *= 2));
      v[count++] = x;
    }
  }
  *out = v;
  return count;
}

int main(int argc, char **argv) {
  if (argc < 3 || argc > 5) {
    fprintf(stderr, "usage: scan BLOCKLIST.dat (N IDS.txt [SEEDS.txt] | pattern DOMAINS.txt | check)\n");
    return 2;
  }
  const uint8_t *file = read_file(argv[1]);

  if (!strcmp(argv[2], "check")) {
    char line[512];
    while (fgets(line, sizeof line, stdin)) {
      uint32_t t[MAXN], len = 0;
      char *p = line, *end;
      for (; len < MAXN; len++, p = end) {
        t[len] = (uint32_t)strtoul(p, &end, 10);
        if (end == p) break;
      }
      if (load_table(file, len)) report(t, len);
    }
    return 0;
  }

  uint32_t len = 0;
  if (!strcmp(argv[2], "pattern")) {
    FILE *f = fopen(argv[3], "r");
    if (!f) { perror(argv[3]); return 2; }
    static char line[1 << 20];
    for (; len < MAXN && fgets(line, sizeof line, f); len++) dlen[len] = read_ids(line, &dom[len]);
    fclose(f);
  } else {
    char *text = (char *)read_file(argv[3]);
    nids = read_ids(text, &ids);
    len = (uint32_t)atoi(argv[2]);
    for (uint32_t i = 0; i < len && i < MAXN; i++) dom[i] = ids, dlen[i] = nids;
  }
  if (!load_table(file, len) || n > MAXN) { fprintf(stderr, "no table of length %u\n", len); return 2; }
  build_set();

  if (argc == 5) {
    FILE *s = fopen(argv[4], "r");
    if (!s) { perror(argv[4]); return 2; }
    seeded(s);
    return 0;
  }
  if (n == 1) {
    for (uint32_t i = 0; i < dlen[0]; i++) report(&dom[0][i], 1);
    return 0;
  }
  long cpus = sysconf(_SC_NPROCESSORS_ONLN);
  pthread_t threads[64];
  int count = cpus < 1 ? 1 : cpus > 64 ? 64 : (int)cpus;
  for (int i = 0; i < count; i++) pthread_create(&threads[i], NULL, exhaustive_worker, NULL);
  for (int i = 0; i < count; i++) pthread_join(threads[i], NULL);
  return 0;
}
