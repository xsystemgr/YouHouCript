# -*- coding: utf-8 -*-
"""
Cipher Autopilot Lab (RU + coordinates heuristics)
- GUI (Tkinter)
- Parses transmissions, extracts numeric groups
- Runs autopilot pipeline sequentially with STOP
- Heuristics for:
  * Russian (Cyrillic) plausibility
  * Coordinates / military-style patterns
- Adds key-length hints via:
  * Index of Coincidence (IoC)
  * Kasiski-like repeats (on letter stream derived from modN)
- Lightweight hypothesis tests:
  * Grid 00-99 decode
  * Auto Vigenere break on group%26 (EN scoring)
  * Auto Vigenere break on group%33 (RU scoring)
  * Heuristic Vigenere on pairs (mod100) with grid fitness
  * mod10000 constant-shift scan for ASCII-ish effect (sanity)

Note:
This is an analysis & hypothesis tool. If the underlying scheme is OTP/codebook-keyed,
no meaningful decode will be produced (and that itself is a result).
"""

import re
import math
import threading
import queue
from collections import Counter, defaultdict

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# -----------------------------
# Parsing
# -----------------------------
LINE_RE = re.compile(r'^\s*([A-Za-z]+)\s+(\d{5})\s+(.*)$')

def extract_numeric_groups(text):
    return re.findall(r'\b\d{4,5}\b', text)

def extract_tokens_per_line(text):
    records = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = LINE_RE.match(line)
        if not m:
            records.append({"raw": raw, "parsed": False})
            continue
        prefix, msg_id, rest = m.group(1), m.group(2), m.group(3)
        tokens = rest.split()
        nums = [t for t in tokens if re.fullmatch(r"\d{4,5}", t)]
        words = [t for t in tokens if not re.fullmatch(r"\d{4,5}", t)]
        records.append({
            "raw": raw,
            "parsed": True,
            "prefix": prefix,
            "msg_id": msg_id,
            "tokens": tokens,
            "nums": nums,
            "words": words
        })
    return records

# -----------------------------
# Stats
# -----------------------------
def shannon_entropy_digits(numbers):
    digits = "".join(numbers)
    if not digits:
        return 0.0
    c = Counter(digits)
    total = len(digits)
    ent = 0.0
    for v in c.values():
        p = v / total
        ent -= p * math.log2(p)
    return ent

def digit_frequency(numbers):
    digits = "".join(numbers)
    c = Counter(digits)
    return {d: c.get(d, 0) for d in "0123456789"}, len(digits)

def repetitions(numbers):
    c = Counter(numbers)
    return [(k, v) for k, v in c.items() if v > 1]

# -----------------------------
# Grid decoder 00-99
# -----------------------------
DEFAULT_ALPHABET_100 = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " .,;:!?@#$/\\-_=+()[]{}<>"
)
DEFAULT_ALPHABET_100 = (DEFAULT_ALPHABET_100 + ("~" * 100))[:100]

def numbers_to_pairs_00_99(numbers, pad_last_digit=True):
    pairs = []
    for g in numbers:
        s = g.strip()
        i = 0
        while i < len(s):
            chunk = s[i:i+2]
            if len(chunk) == 1:
                if pad_last_digit:
                    chunk = chunk + "0"
                else:
                    break
            if len(chunk) == 2 and chunk.isdigit():
                pairs.append(chunk)
            i += 2
    return pairs

def grid_decode_pairs(pairs, alphabet100):
    alpha = (alphabet100 + ("~" * 100))[:100]
    out = []
    for p in pairs:
        idx = int(p)
        out.append(alpha[idx] if 0 <= idx < 100 else "�")
    return "".join(out)

# -----------------------------
# Scoring / Vigenere
# -----------------------------
EN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ENGLISH_FREQ = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253, "E": 0.12702,
    "F": 0.02228, "G": 0.02015, "H": 0.06094, "I": 0.06966, "J": 0.00153,
    "K": 0.00772, "L": 0.04025, "M": 0.02406, "N": 0.06749, "O": 0.07507,
    "P": 0.01929, "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150, "Y": 0.01974,
    "Z": 0.00074
}

def chi_squared_score_en(text):
    if not text:
        return float("inf")
    counts = {ch: 0 for ch in ENGLISH_FREQ}
    n = 0
    for ch in text:
        if ch in counts:
            counts[ch] += 1
            n += 1
    if n == 0:
        return float("inf")
    score = 0.0
    for ch, exp in ENGLISH_FREQ.items():
        observed = counts[ch]
        expected = n * exp
        if expected > 0:
            score += ((observed - expected) ** 2) / expected
    return score

RU_ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
RU_FREQ = {
    "О": 0.1097, "Е": 0.0845, "А": 0.0801, "И": 0.0735, "Н": 0.0670,
    "Т": 0.0626, "С": 0.0547, "Р": 0.0473, "В": 0.0454, "Л": 0.0440,
    "К": 0.0349, "М": 0.0321, "Д": 0.0298, "П": 0.0281, "У": 0.0262,
    "Я": 0.0201, "Ы": 0.0190, "Ь": 0.0174, "Г": 0.0170, "З": 0.0165,
    "Б": 0.0159, "Ч": 0.0144, "Й": 0.0121, "Х": 0.0097, "Ж": 0.0094,
    "Ш": 0.0073, "Ю": 0.0064, "Ц": 0.0048, "Щ": 0.0036, "Э": 0.0032,
    "Ф": 0.0026, "Ъ": 0.0004, "Ё": 0.0004
}

def chi_squared_score_ru(text):
    if not text:
        return float("inf")
    counts = {ch: 0 for ch in RU_ALPHABET}
    n = 0
    for ch in text:
        if ch in counts:
            counts[ch] += 1
            n += 1
    if n == 0:
        return float("inf")
    score = 0.0
    for ch in RU_ALPHABET:
        exp = RU_FREQ.get(ch, 0.0)
        expected = n * exp
        observed = counts[ch]
        if expected > 0:
            score += ((observed - expected) ** 2) / expected
    return score

def vigenere_decrypt_modN_to_letters(values, key, N, alphabet):
    out = []
    klen = len(key)
    for i, v in enumerate(values):
        p = (v - key[i % klen]) % N
        out.append(alphabet[p])
    return "".join(out)

def find_best_caesar_for_column(values, N, alphabet, score_fn):
    best_shift = 0
    best_score = float("inf")
    for shift in range(N):
        decoded = "".join(alphabet[(v - shift) % N] for v in values)
        s = score_fn(decoded)
        if s < best_score:
            best_score = s
            best_shift = shift
    return best_shift, best_score

def break_vigenere(values, N, alphabet, score_fn, max_keylen=16, top_k=8):
    candidates = []
    for klen in range(1, max_keylen + 1):
        key = []
        for i in range(klen):
            col = [values[j] for j in range(i, len(values), klen)]
            shift, _ = find_best_caesar_for_column(col, N, alphabet, score_fn)
            key.append(shift)
        plaintext = vigenere_decrypt_modN_to_letters(values, key, N, alphabet)
        overall = score_fn(plaintext)
        candidates.append({
            "keylen": klen,
            "key": key,
            "key_text": "".join(alphabet[k] for k in key),
            "score": overall,
            "preview": plaintext[:300]
        })
    candidates.sort(key=lambda x: x["score"])
    return candidates[:top_k]

# -----------------------------
# Numeric Vigenere experiments (mod100/mod10000)
# -----------------------------
def vigenere_decrypt_modN(nums, key_nums, modN):
    out = []
    klen = len(key_nums)
    for i, c in enumerate(nums):
        out.append((c - key_nums[i % klen]) % modN)
    return out

# -----------------------------
# Heuristics: RU + Coordinates
# -----------------------------
RU_COMMON_WORDS = [
    "ПРИКАЗ", "КООРДИНАТ", "СЕВЕР", "ЮГ", "ЗАПАД", "ВОСТОК",
    "ВЫХОД", "ВХОД", "ОТЧЕТ", "ЦЕЛЬ", "ОБЪЕКТ", "ПУНКТ",
    "СЕКТОР", "ГРУППА", "КОД", "СИГНАЛ", "НАЧАТЬ", "ЗАВЕРШИТЬ"
]

RU_BIGRAMS = ["СТ", "НО", "ЕН", "ТО", "НА", "ОВ", "НИ", "РА", "КО", "ПО", "ПР", "ЕР", "ЛИ"]

COORD_PATTERNS = [
    r"\b[NS]\s?\d{1,2}\b",
    r"\b[EWO]\s?\d{1,3}\b",
    r"\b\d{1,2}\.\d{3,6}\b",
    r"\b\d{2,3}\s+\d{2,3}\b",
    r"\b\d{4}\s+\d{4}\b",
    r"\bGRID\b",
    r"\bUTM\b",
]

def printable_ratio(s):
    if not s:
        return 0.0
    ok = sum(1 for ch in s if (ch.isalnum() or ch in " .,;:!?-_()[]{}<>@#/\\\n\r\t"))
    return ok / max(1, len(s))

def cyrillic_ratio(text):
    if not text:
        return 0.0
    total = len(text)
    cyr = sum(1 for ch in text if ch in RU_ALPHABET)
    return cyr / total

def ru_word_hits(text):
    t = text.upper()
    return sum(1 for w in RU_COMMON_WORDS if w in t)

def ru_bigram_score(text):
    t = text.upper()
    return sum(t.count(bg) for bg in RU_BIGRAMS)

def coord_pattern_hits(text):
    hits = 0
    for pat in COORD_PATTERNS:
        if re.search(pat, text):
            hits += 1
    return hits

def numeric_cluster_ratio(text):
    if not text:
        return 0.0
    digits = sum(1 for ch in text if ch.isdigit())
    return digits / len(text)

def ru_plausibility_score(text):
    """
    Combined heuristic score:
    - Cyrillic density
    - common word hits
    - bigram structure
    """
    cr = cyrillic_ratio(text)
    wh = ru_word_hits(text)
    bg = ru_bigram_score(text)
    # weighted
    return (cr * 6.0) + (wh * 4.0) + (min(bg, 30) * 0.25)

def coord_plausibility_score(text):
    """
    Coordinate/military-like score:
    - pattern hits
    - numeric ratio
    - also allows latin N/E/W/S patterns if present
    """
    ph = coord_pattern_hits(text)
    nr = numeric_cluster_ratio(text)
    return (ph * 3.5) + (nr * 2.0)

# -----------------------------
# Key-length hints: IoC + Kasiski-like repeats
# -----------------------------
def index_of_coincidence(text, alphabet):
    """
    IoC = sum f_i(f_i-1) / (N(N-1))
    """
    filtered = [ch for ch in text if ch in alphabet]
    N = len(filtered)
    if N < 2:
        return 0.0
    c = Counter(filtered)
    num = sum(v * (v - 1) for v in c.values())
    den = N * (N - 1)
    return num / den

def average_ioc_for_keylen(values, N, alphabet):
    """
    values are ints 0..N-1
    Treat as letters in alphabet, compute average IoC across columns for a keylen.
    """
    if not values:
        return 0.0
    text = "".join(alphabet[v % N] for v in values)
    cols = []
    for i in range(N):  # not used
        pass
    iocs = []
    for i in range(1, 1):  # placeholder
        pass

def avg_column_ioc_from_values(values, keylen, alphabet):
    if keylen <= 0:
        return 0.0
    cols = [[] for _ in range(keylen)]
    for i, v in enumerate(values):
        cols[i % keylen].append(v)
    iocs = []
    for col in cols:
        txt = "".join(alphabet[x] for x in col)
        iocs.append(index_of_coincidence(txt, alphabet))
    return sum(iocs) / len(iocs) if iocs else 0.0

def kasiski_repeats(text, min_seq=3, max_seq=6, top=10):
    """
    Very lightweight Kasiski-like:
    find repeated sequences of length [min_seq..max_seq] and return distances.
    """
    filtered = re.sub(r"\s+", "", text)
    found = defaultdict(list)
    L = len(filtered)
    for n in range(min_seq, max_seq + 1):
        for i in range(0, L - n + 1):
            seq = filtered[i:i+n]
            found[seq].append(i)

    distances = []
    for seq, idxs in found.items():
        if len(idxs) >= 2:
            idxs.sort()
            for a in range(len(idxs) - 1):
                distances.append(idxs[a+1] - idxs[a])

    if not distances:
        return []

    # factor histogram (common gcd-ish hints)
    factor_counts = Counter()
    for d in distances:
        for f in range(2, 41):
            if d % f == 0:
                factor_counts[f] += 1

    return factor_counts.most_common(top)

# -----------------------------
# Autopilot pipeline
# -----------------------------
def autopilot_run(text, max_keylen, stop_event, log_fn, found_fn):
    nums = extract_numeric_groups(text)
    if not nums:
        log_fn("No numeric groups found.")
        return

    ent = shannon_entropy_digits(nums)
    freq, total_digits = digit_frequency(nums)
    reps = repetitions(nums)

    log_fn(f"Stats: groups={len(nums)}, total_digits={total_digits}, digit_entropy={ent:.4f} (max~3.3219)")
    log_fn(f"Repetitions: {len(reps)} repeated numeric groups")

    # prepare streams
    vals26 = [int(n) % 26 for n in nums]
    vals33 = [int(n) % 33 for n in nums]
    pairs = numbers_to_pairs_00_99(nums, pad_last_digit=True)
    pair_vals = [int(p) for p in pairs if p.isdigit() and len(p) == 2]

    # IoC hints
    if stop_event.is_set(): return
    log_fn("Key-length hints via IoC (values=group%33 as RU letters):")
    for klen in range(1, min(max_keylen, 20) + 1):
        ioc = avg_column_ioc_from_values(vals33, klen, RU_ALPHABET)
        if klen in (1,2,3,4,5,6,7,8,10,12,14,16,18,20):
            log_fn(f"  klen={klen:2d} avgIoC={ioc:.4f}")

    # Kasiski-like on RU letter stream (very rough)
    if stop_event.is_set(): return
    ru_stream = "".join(RU_ALPHABET[v] for v in vals33)
    kas = kasiski_repeats(ru_stream, min_seq=3, max_seq=5, top=10)
    if kas:
        log_fn("Kasiski-like factor hints (RU stream): " + ", ".join(f"{f}({c})" for f, c in kas))
    else:
        log_fn("Kasiski-like: no useful repeats found (could be random/OTP or too short).")

    # 1) Grid decode default alphabet
    if stop_event.is_set(): return
    log_fn("Trying Grid(00-99) decode with default alphabet…")
    grid_txt = grid_decode_pairs(pairs, DEFAULT_ALPHABET_100)
    cr = cyrillic_ratio(grid_txt)
    cs = coord_pattern_hits(grid_txt)
    nr = numeric_cluster_ratio(grid_txt)
    pr = printable_ratio(grid_txt)
    log_fn(f"Grid metrics: printable={pr:.3f}, cyr={cr:.3f}, coord_hits={cs}, num_ratio={nr:.3f}")
    if (cr > 0.55) or (cs >= 1) or (pr > 0.92 and len(grid_txt) > 80):
        found_fn("GRID-DEFAULT", f"printable={pr:.3f} cyr={cr:.2f} coord_hits={cs} num_ratio={nr:.2f}",
                 grid_txt[:800])

    # 2) Auto Vigenere mod26 (EN scoring)
    if stop_event.is_set(): return
    log_fn("Trying Auto Vigenere break on values=(group % 26) with EN scoring…")
    top26 = break_vigenere(vals26, 26, EN_ALPHABET, chi_squared_score_en, max_keylen=max_keylen, top_k=6)
    for c in top26:
        if stop_event.is_set(): return
        prev = c["preview"]
        pr = printable_ratio(prev)
        # Keep only if it's not totally random-looking
        if pr > 0.95 and c["score"] < 250:
            found_fn("VIG26", f"keylen={c['keylen']} key={c['key_text']} score={c['score']:.1f} printable={pr:.2f}",
                     prev)

    # 3) Auto Vigenere mod33 (RU scoring)
    if stop_event.is_set(): return
    log_fn("Trying Auto Vigenere break on values=(group % 33) with RU scoring…")
    top33 = break_vigenere(vals33, 33, RU_ALPHABET, chi_squared_score_ru, max_keylen=max_keylen, top_k=10)
    for c in top33:
        if stop_event.is_set(): return
        prev = c["preview"]
        rscore = ru_plausibility_score(prev)
        cscore = coord_plausibility_score(prev)
        # Thresholds tuned to surface plausible candidates without flooding:
        if (rscore >= 6.0) or (cscore >= 5.0):
            found_fn(
                "VIG33-RU",
                f"keylen={c['keylen']} key={c['key_text']} chi2={c['score']:.1f} ruScore={rscore:.2f} coordScore={cscore:.2f}",
                prev
            )

    # 4) Heuristic Vigenere on PAIRS (mod100) using grid fitness (column-wise best shifts)
    if stop_event.is_set(): return
    if len(pair_vals) > 20:
        log_fn("Trying heuristic Vigenere on PAIRS (mod100) using Grid fitness (klen 1..6)…")
        for klen in range(1, min(6, max_keylen) + 1):
            if stop_event.is_set(): return
            key = []
            for i in range(klen):
                col = [pair_vals[j] for j in range(i, len(pair_vals), klen)]
                best_shift = 0
                best_fit = -1.0
                for shift in range(100):
                    dec_col = [(v - shift) % 100 for v in col]
                    col_pairs = [f"{v:02d}" for v in dec_col]
                    col_txt = grid_decode_pairs(col_pairs, DEFAULT_ALPHABET_100)
                    fit = printable_ratio(col_txt)
                    if fit > best_fit:
                        best_fit = fit
                        best_shift = shift
                key.append(best_shift)

            dec_vals = vigenere_decrypt_modN(pair_vals, key, 100)
            dec_pairs = [f"{v:02d}" for v in dec_vals]
            dec_txt = grid_decode_pairs(dec_pairs, DEFAULT_ALPHABET_100)

            pr = printable_ratio(dec_txt)
            rscore = ru_plausibility_score(dec_txt)
            cscore = coord_plausibility_score(dec_txt)

            log_fn(f"  klen={klen} printable={pr:.3f} ruScore={rscore:.2f} coordScore={cscore:.2f}")

            if (rscore >= 6.0) or (cscore >= 5.0) or (pr > 0.93 and len(dec_txt) > 100):
                found_fn(
                    "VIG100-PAIRS",
                    f"keylen={klen} key={key} printable={pr:.2f} ruScore={rscore:.2f} coordScore={cscore:.2f}",
                    dec_txt[:900]
                )
    else:
        log_fn("Skipping mod100 pairs heuristic (too few pairs).")

    # 5) mod10000 constant-shift scan (sanity)
    if stop_event.is_set(): return
    log_fn("Trying mod10000: constant-shift scan (0..9999 step 37) for ASCII-ish / patterns…")
    g4 = [n for n in nums if len(n) == 4]
    if len(g4) >= 12:
        g4v = [int(x) for x in g4]
        best_shift = 0
        best_pr = -1.0
        best_s = ""
        for shift in range(0, 10000, 37):
            if stop_event.is_set(): return
            dec = [((v - shift) % 10000) % 256 for v in g4v]
            s = "".join(chr(b) if 32 <= b <= 126 else "." for b in dec)
            pr = printable_ratio(s)
            if pr > best_pr:
                best_pr = pr
                best_shift = shift
                best_s = s

        rscore = ru_plausibility_score(best_s)
        cscore = coord_plausibility_score(best_s)

        log_fn(f"  best_shift={best_shift} printable={best_pr:.3f} ruScore={rscore:.2f} coordScore={cscore:.2f}")
        if (rscore >= 5.5) or (cscore >= 4.5) or (best_pr > 0.80):
            found_fn(
                "MOD10000-SHIFT",
                f"best_shift={best_shift} ascii_printable={best_pr:.2f} ruScore={rscore:.2f} coordScore={cscore:.2f}",
                best_s[:600]
            )
    else:
        log_fn("Skipping mod10000 shift scan (too few 4-digit groups).")

    log_fn("Autopilot finished. If nothing meaningful found: πιθανό OTP / codebook+key / ή λίγα δεδομένα.")

# -----------------------------
# GUI
# -----------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cipher Autopilot Lab (RU + Coordinates Heuristics)")
        self.geometry("1250x860")

        self.worker = None
        self.stop_event = threading.Event()
        self.ui_queue = queue.Queue()

        self._build_ui()
        self._pump_ui_queue()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=8)

        ttk.Button(top, text="Load .txt…", command=self.load_file).pack(side="left")
        ttk.Button(top, text="Run Autopilot", command=self.run_autopilot).pack(side="left", padx=6)
        ttk.Button(top, text="STOP", command=self.stop_autopilot).pack(side="left", padx=6)

        ttk.Label(top, text="Max keylen:").pack(side="left", padx=(20, 6))
        self.max_keylen_var = tk.StringVar(value="16")
        ttk.Entry(top, width=6, textvariable=self.max_keylen_var).pack(side="left")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_input = ttk.Frame(nb)
        self.tab_parse = ttk.Frame(nb)
        self.tab_log = ttk.Frame(nb)
        self.tab_found = ttk.Frame(nb)

        nb.add(self.tab_input, text="Input")
        nb.add(self.tab_parse, text="Parse Preview")
        nb.add(self.tab_log, text="Log")
        nb.add(self.tab_found, text="Top Findings")

        # Input tab
        ttk.Label(self.tab_input, text="Paste transmissions here:").pack(anchor="w", padx=6, pady=(6, 2))
        self.input_text = tk.Text(self.tab_input, wrap="none", height=24)
        self.input_text.pack(fill="both", expand=True, padx=6, pady=6)

        # Parse tab
        self.parse_text = tk.Text(self.tab_parse, wrap="none", state="disabled")
        self.parse_text.pack(fill="both", expand=True, padx=6, pady=6)

        # Log tab
        self.log_text = tk.Text(self.tab_log, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)

        # Found tab
        self.found_text = tk.Text(self.tab_found, wrap="word", state="disabled")
        self.found_text.pack(fill="both", expand=True, padx=6, pady=6)

    def get_input(self):
        return self.input_text.get("1.0", "end").strip("\n")

    def load_file(self):
        path = filedialog.askopenfilename(
            title="Load transmissions text",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", data)
            self.refresh_parse_preview()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file:\n{e}")

    def refresh_parse_preview(self):
        text = self.get_input()
        records = extract_tokens_per_line(text)
        lines = []
        for r in records[:30]:
            if not r.get("parsed"):
                lines.append(f"[UNPARSED] {r.get('raw')}")
            else:
                lines.append(f"{r['prefix']} {r['msg_id']} | words={r['words']} | nums={r['nums']}")
        self._set_text(self.parse_text, "\n".join(lines) if lines else "(no lines)")

    def run_autopilot(self):
        text = self.get_input()
        if not text.strip():
            messagebox.showinfo("Empty", "Paste or load some transmissions first.")
            return

        self.refresh_parse_preview()

        try:
            max_keylen = int(self.max_keylen_var.get().strip())
            max_keylen = max(1, min(max_keylen, 40))
        except:
            max_keylen = 16

        # reset
        self.stop_event.clear()
        self._append_log("Starting autopilot…")
        self._set_text(self.found_text, "")

        # start worker
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Running", "Autopilot is already running.")
            return

        self.worker = threading.Thread(
            target=autopilot_run,
            args=(text, max_keylen, self.stop_event, self._log_from_worker, self._found_from_worker),
            daemon=True
        )
        self.worker.start()

    def stop_autopilot(self):
        self.stop_event.set()
        self._append_log("STOP requested. Waiting for worker to exit…")

    # UI queue pump
    def _pump_ui_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "found":
                    tag, meta, preview = payload
                    self._append_found(f"\n=== {tag} | {meta} ===\n{preview}\n")
        except queue.Empty:
            pass
        self.after(120, self._pump_ui_queue)

    # worker -> UI
    def _log_from_worker(self, msg):
        self.ui_queue.put(("log", msg))

    def _found_from_worker(self, tag, meta, preview):
        self.ui_queue.put(("found", (tag, meta, preview)))

    # text helpers
    def _set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.see("end")
        widget.configure(state="disabled")

    def _append_log(self, line):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line.rstrip() + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _append_found(self, block):
        self.found_text.configure(state="normal")
        self.found_text.insert("end", block)
        self.found_text.see("end")
        self.found_text.configure(state="disabled")

if __name__ == "__main__":
    app = App()
    app.mainloop()
