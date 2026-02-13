# -*- coding: utf-8 -*-
import re
import math
import threading
import queue
import time
from collections import Counter

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
                chunk = (chunk + "0") if pad_last_digit else chunk
            if len(chunk) == 2 and chunk.isdigit():
                pairs.append(chunk)
            i += 2
    return pairs

def grid_decode_pairs(pairs, alphabet100):
    out = []
    alpha = (alphabet100 + ("~" * 100))[:100]
    for p in pairs:
        idx = int(p)
        out.append(alpha[idx] if 0 <= idx < 100 else "�")
    return "".join(out)

# -----------------------------
# Vigenere + scoring (EN mod26)
# -----------------------------
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
            "preview": plaintext[:240]
        })
    candidates.sort(key=lambda x: x["score"])
    return candidates[:top_k]

# -----------------------------
# Russian mod33 scoring
# -----------------------------
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

# -----------------------------
# Numeric Vigenere experiments (mod100/mod10000)
# -----------------------------
def vigenere_decrypt_modN(nums, key_nums, modN):
    out = []
    klen = len(key_nums)
    for i, c in enumerate(nums):
        out.append((c - key_nums[i % klen]) % modN)
    return out

def printable_ratio(s):
    if not s:
        return 0.0
    ok = sum(1 for ch in s if (ch.isalnum() or ch in " .,;:!?-_()[]{}<>@#/\\\n\r\t"))
    return ok / max(1, len(s))

def digits_only_ratio(s):
    if not s:
        return 0.0
    ok = sum(1 for ch in s if ch.isdigit())
    return ok / max(1, len(s))

# Very small RU “sanity” word hits (just to detect something plausible)
RU_HINTS = ["КО", "ПО", "НА", "ПРИ", "СЕ", "ОТ", "ДО", "ЭТО", "ЧТО", "КАК", "ГДЕ", "КТО", "ВЫ", "МЫ", "ОН", "ОНА"]

def ru_hint_hits(s):
    ss = s.upper()
    return sum(1 for h in RU_HINTS if h in ss)

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
    log_fn(f"Repetitions: {len(reps)} groups repeated")

    # 1) Grid decode with default alphabet
    if stop_event.is_set(): return
    log_fn("Trying Grid(00-99) decode with default alphabet…")
    pairs = numbers_to_pairs_00_99(nums, pad_last_digit=True)
    grid_txt = grid_decode_pairs(pairs, DEFAULT_ALPHABET_100)
    pr = printable_ratio(grid_txt)
    log_fn(f"Grid decode printable_ratio={pr:.3f}")
    if pr > 0.80 and len(grid_txt) >= 40:
        found_fn("GRID-DEFAULT", f"printable_ratio={pr:.3f}", grid_txt[:600])

    # 2) Auto Vigenere on stream values = group % 26 (EN scoring) — sometimes catches structure even if not EN
    if stop_event.is_set(): return
    log_fn("Trying Auto: Auto Vigenere break on values=(group % 26)…")
    vals26 = [int(n) % 26 for n in nums]
    top26 = break_vigenere(vals26, 26, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", chi_squared_score_en, max_keylen=max_keylen, top_k=6)
    for c in top26:
        if stop_event.is_set(): return
        prev = c["preview"]
        pr = printable_ratio(prev)
        # heuristic: if output not random-looking and has some repeated patterns, keep it
        if pr > 0.90 and c["score"] < 200:
            found_fn("VIG26", f"keylen={c['keylen']} key={c['key_text']} score={c['score']:.1f}", prev)

    # 3) Auto Vigenere on values = group % 33 (RU scoring)
    if stop_event.is_set(): return
    log_fn("Trying RU: Auto Vigenere break on values=(group % 33)…")
    vals33 = [int(n) % 33 for n in nums]
    top33 = break_vigenere(vals33, 33, RU_ALPHABET, chi_squared_score_ru, max_keylen=max_keylen, top_k=8)
    for c in top33:
        if stop_event.is_set(): return
        prev = c["preview"]
        hits = ru_hint_hits(prev)
        # heuristic: keep if has some RU bigram-ish hints
        if hits >= 2 and c["score"] < 300:
            found_fn("VIG33-RU", f"keylen={c['keylen']} key={c['key_text']} score={c['score']:.1f} hits={hits}", prev)

    # 4) Numeric Vigenere brute on pairs (mod100) with short key length 1..6, key values 0..99 (restricted search)
    # Instead of impossible brute (100^k), we do a cheap heuristic:
    # - assume key repeated, find best Caesar-like per column on mod100 using "printable grid text" as fitness.
    if stop_event.is_set(): return
    log_fn("Trying heuristic Vigenere on PAIRS (mod100) using Grid fitness (column-wise best shifts)…")
    pair_vals = [int(p) for p in pairs if p.isdigit() and len(p) == 2]
    if len(pair_vals) > 20:
        for klen in range(1, min(6, max_keylen) + 1):
            if stop_event.is_set(): return
            key = []
            # choose per-column shift that maximizes printable ratio after grid decode
            for i in range(klen):
                col = [pair_vals[j] for j in range(i, len(pair_vals), klen)]
                best_shift = 0
                best_fit = -1.0
                for shift in range(100):
                    dec_col = [(v - shift) % 100 for v in col]
                    # rebuild full stream approx by applying this shift only to column -> too expensive.
                    # So we evaluate on column alone with alphabet: prefer alnum/space punctuation
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
            if pr > 0.85 and len(dec_txt) > 60:
                found_fn("VIG100-PAIRS", f"keylen={klen} key={key} printable_ratio={pr:.3f}", dec_txt[:800])

    # 5) mod10000 groups (4-digit only) with small keys (manual-ish): try keylen 1..4 and shift = 0..9999
    # too big. Instead: test if subtracting a constant makes outputs cluster around ASCII bytes.
    if stop_event.is_set(): return
    log_fn("Trying mod10000: constant-shift scan (0..9999 step 37) to see ASCII-likeness…")
    g4 = [n for n in nums if len(n) == 4]
    if len(g4) >= 12:
        g4v = [int(x) for x in g4]
        best = (0, -1.0, "")
        for shift in range(0, 10000, 37):
            if stop_event.is_set(): return
            dec = [((v - shift) % 10000) % 256 for v in g4v]
            s = "".join(chr(b) if 32 <= b <= 126 else "." for b in dec)
            pr = printable_ratio(s)
            if pr > best[1]:
                best = (shift, pr, s)
        if best[1] > 0.70:
            found_fn("MOD10000-SHIFT", f"best_shift={best[0]} ascii_printable_ratio={best[1]:.3f}", best[2][:400])

    log_fn("Autopilot finished. If nothing meaningful found, πιθανότατα είναι OTP ή χρειάζεται codebook/key.")

# -----------------------------
# GUI
# -----------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cipher Autopilot Lab (RU/EN/Grid/Vigenere)")
        self.geometry("1200x820")

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
        self.tab_log = ttk.Frame(nb)
        self.tab_found = ttk.Frame(nb)
        self.tab_parse = ttk.Frame(nb)

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
        for r in records[:25]:
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
        self._append_found("")

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
