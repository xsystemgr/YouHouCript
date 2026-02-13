# -*- coding: utf-8 -*-
"""
Cipher Lab GUI (Tkinter)
- Paste/Load transmissions
- Parse tokens: prefixes, ids, codewords, numeric groups
- Stats: digit frequency, entropy, repetitions
- Grid decoder: 10x10 (00-99) with configurable alphabet (100 chars)
- Vigenere numeric experiments:
    * mod26 on (group % 26) -> letters
    * mod100 on (pairs 00-99)
    * mod10000 on 4-digit groups
- Auto hypothesis tester:
    * Break classical Vigenere on mod26 stream via chi-squared (English)
    * Suggest key for key lengths 1..N, show best candidates
"""

import re
import math
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# -----------------------------
# Helpers: parsing & stats
# -----------------------------
LINE_RE = re.compile(r'^\s*([A-Za-z]+)\s+(\d{5})\s+(.*)$')

def extract_numeric_groups(text):
    # capture 4 or 5 digit groups (keeps leading zeros)
    return re.findall(r'\b\d{4,5}\b', text)

def extract_tokens_per_line(text):
    """
    Parse each line into:
      prefix, msg_id, remaining_tokens(list)
    remaining tokens may include words and numeric groups.
    """
    records = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = LINE_RE.match(line)
        if not m:
            # store unparsed line
            records.append({"raw": raw, "parsed": False})
            continue
        prefix, msg_id, rest = m.group(1), m.group(2), m.group(3)
        tokens = rest.split()
        records.append({
            "raw": raw,
            "parsed": True,
            "prefix": prefix,
            "msg_id": msg_id,
            "tokens": tokens
        })
    return records

def digit_frequency(numbers):
    digits = "".join(numbers)
    from collections import Counter
    c = Counter(digits)
    return {d: c.get(d, 0) for d in "0123456789"}, len(digits)

def shannon_entropy_digits(numbers):
    digits = "".join(numbers)
    if not digits:
        return 0.0
    from collections import Counter
    c = Counter(digits)
    total = len(digits)
    ent = 0.0
    for k, v in c.items():
        p = v / total
        ent -= p * math.log2(p)
    return ent

def repetitions(numbers):
    from collections import Counter
    c = Counter(numbers)
    return [(k, v) for k, v in c.items() if v > 1]

def safe_int(s):
    try:
        return int(s)
    except:
        return None

# -----------------------------
# Grid decoder (00-99)
# -----------------------------
DEFAULT_ALPHABET_100 = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " .,;:!?@#$/\\-_=+()[]{}<>"
)
# Ensure length 100
DEFAULT_ALPHABET_100 = (DEFAULT_ALPHABET_100 + ("~" * 100))[:100]

def grid_decode_pairs(pairs, alphabet100):
    """
    pairs: list of strings "00".."99"
    map pair -> alphabet100[int(pair)]
    """
    out = []
    for p in pairs:
        if len(p) != 2 or not p.isdigit():
            out.append("�")
            continue
        idx = int(p)
        if 0 <= idx < 100:
            out.append(alphabet100[idx])
        else:
            out.append("�")
    return "".join(out)

def numbers_to_pairs_00_99(numbers):
    """
    Convert list of 4/5-digit groups into 2-digit pairs (00-99) by chunking digits.
    Example: "4413" -> ["44","13"]
             "06476" -> ["06","47","6?"] -> last odd digit becomes "6?" -> mark
    We will pad odd digit with "0" at end: "6" -> "60" (configurable; here fixed)
    """
    pairs = []
    for g in numbers:
        s = g.strip()
        # chunk into pairs
        i = 0
        while i < len(s):
            chunk = s[i:i+2]
            if len(chunk) == 1:
                chunk = chunk + "0"  # pad
            pairs.append(chunk)
            i += 2
    return pairs

# -----------------------------
# Vigenere on mod26 stream
# -----------------------------
ENGLISH_FREQ = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253, "E": 0.12702,
    "F": 0.02228, "G": 0.02015, "H": 0.06094, "I": 0.06966, "J": 0.00153,
    "K": 0.00772, "L": 0.04025, "M": 0.02406, "N": 0.06749, "O": 0.07507,
    "P": 0.01929, "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150, "Y": 0.01974,
    "Z": 0.00074
}

def chi_squared_score(text):
    """
    Lower is better.
    text assumed uppercase A-Z only (we ignore others).
    """
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

def vigenere_decrypt_mod26(values, key):
    """
    values: list ints 0..25
    key: list ints 0..25
    returns letters A-Z
    """
    out = []
    klen = len(key)
    for i, v in enumerate(values):
        p = (v - key[i % klen]) % 26
        out.append(chr(p + 65))
    return "".join(out)

def find_best_caesar_for_column(col_vals):
    """
    For a set of values (0..25) assuming Caesar shift,
    find shift that yields lowest chi-squared when decoded.
    """
    best_shift = 0
    best_score = float("inf")
    for shift in range(26):
        decoded = "".join(chr(((v - shift) % 26) + 65) for v in col_vals)
        s = chi_squared_score(decoded)
        if s < best_score:
            best_score = s
            best_shift = shift
    return best_shift, best_score

def break_vigenere_mod26(values, max_keylen=12, top_k=5):
    """
    Classic Vigenere break:
    - for each keylen, solve each column as Caesar via chi-squared
    - compute overall score, keep best candidates
    """
    candidates = []
    for klen in range(1, max_keylen + 1):
        key = []
        total_score = 0.0
        for i in range(klen):
            col = [values[j] for j in range(i, len(values), klen)]
            shift, score = find_best_caesar_for_column(col)
            key.append(shift)
            total_score += score
        plaintext = vigenere_decrypt_mod26(values, key)
        overall = chi_squared_score(plaintext)
        candidates.append({
            "keylen": klen,
            "key": key,
            "key_text": "".join(chr(k + 65) for k in key),
            "score": overall,
            "preview": plaintext[:200]
        })
    candidates.sort(key=lambda x: x["score"])
    return candidates[:top_k]

# -----------------------------
# Vigenere numeric experiments
# -----------------------------
def vigenere_decrypt_modN(nums, key_nums, modN):
    """
    nums: list ints
    key_nums: list ints
    returns list ints plaintext
    """
    out = []
    klen = len(key_nums)
    for i, c in enumerate(nums):
        p = (c - key_nums[i % klen]) % modN
        out.append(p)
    return out

def ints_to_printable_ascii(vals):
    """
    map ints (0..255 expected) to text, replacing non-printables with '.'
    """
    out = []
    for v in vals:
        if 32 <= v <= 126:
            out.append(chr(v))
        elif v in (10, 13, 9):
            out.append(chr(v))
        else:
            out.append(".")
    return "".join(out)

# -----------------------------
# GUI
# -----------------------------
class CipherLabGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cipher Lab GUI (Hypothesis Tester)")
        self.geometry("1100x750")

        self._build_ui()

    def _build_ui(self):
        # Top controls
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=8)

        ttk.Button(top, text="Load Text File…", command=self.load_file).pack(side="left")
        ttk.Button(top, text="Run All Analyses", command=self.run_all).pack(side="left", padx=6)
        ttk.Button(top, text="Clear", command=self.clear_all).pack(side="left", padx=6)

        ttk.Label(top, text="Max keylen (auto Vigenere mod26):").pack(side="left", padx=(30, 6))
        self.max_keylen_var = tk.StringVar(value="12")
        ttk.Entry(top, width=5, textvariable=self.max_keylen_var).pack(side="left")

        # Notebook tabs
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_input = ttk.Frame(nb)
        self.tab_stats = ttk.Frame(nb)
        self.tab_grid = ttk.Frame(nb)
        self.tab_vig = ttk.Frame(nb)
        self.tab_auto = ttk.Frame(nb)

        nb.add(self.tab_input, text="Input")
        nb.add(self.tab_stats, text="Stats")
        nb.add(self.tab_grid, text="Grid Decoder (00-99)")
        nb.add(self.tab_vig, text="Vigenere Numeric")
        nb.add(self.tab_auto, text="Auto Hypothesis Tester")

        self._build_input_tab()
        self._build_stats_tab()
        self._build_grid_tab()
        self._build_vig_tab()
        self._build_auto_tab()

    def _build_input_tab(self):
        frm = self.tab_input

        ttk.Label(frm, text="Paste your transmissions here:").pack(anchor="w", padx=6, pady=(6, 2))
        self.input_text = tk.Text(frm, wrap="none", height=18)
        self.input_text.pack(fill="both", expand=True, padx=6, pady=6)

        # Output parse preview
        ttk.Label(frm, text="Parse preview (first lines):").pack(anchor="w", padx=6, pady=(10, 2))
        self.parse_preview = tk.Text(frm, wrap="none", height=10, state="disabled")
        self.parse_preview.pack(fill="both", expand=False, padx=6, pady=(0, 6))

    def _build_stats_tab(self):
        frm = self.tab_stats
        self.stats_out = tk.Text(frm, wrap="none", state="disabled")
        self.stats_out.pack(fill="both", expand=True, padx=6, pady=6)

    def _build_grid_tab(self):
        frm = self.tab_grid

        top = ttk.Frame(frm)
        top.pack(fill="x", padx=6, pady=6)

        ttk.Label(top, text="Alphabet (100 chars, index 00..99):").pack(side="left")
        self.alpha_var = tk.StringVar(value=DEFAULT_ALPHABET_100)
        alpha_entry = ttk.Entry(top, textvariable=self.alpha_var)
        alpha_entry.pack(side="left", fill="x", expand=True, padx=6)

        ttk.Button(top, text="Decode Using Grid", command=self.run_grid_decode).pack(side="left", padx=6)

        self.grid_out = tk.Text(frm, wrap="word", state="disabled")
        self.grid_out.pack(fill="both", expand=True, padx=6, pady=6)

    def _build_vig_tab(self):
        frm = self.tab_vig

        cfg = ttk.LabelFrame(frm, text="Vigenere Numeric Decrypt (experiments)")
        cfg.pack(fill="x", padx=6, pady=6)

        row1 = ttk.Frame(cfg); row1.pack(fill="x", padx=6, pady=4)
        ttk.Label(row1, text="Mode:").pack(side="left")
        self.vig_mode = tk.StringVar(value="mod26_letters")
        ttk.Radiobutton(row1, text="mod26 letters (values = group%26)", variable=self.vig_mode, value="mod26_letters").pack(side="left", padx=6)
        ttk.Radiobutton(row1, text="mod100 pairs (00-99)", variable=self.vig_mode, value="mod100_pairs").pack(side="left", padx=6)
        ttk.Radiobutton(row1, text="mod10000 groups (0000-9999)", variable=self.vig_mode, value="mod10000_groups").pack(side="left", padx=6)

        row2 = ttk.Frame(cfg); row2.pack(fill="x", padx=6, pady=4)
        ttk.Label(row2, text="Key (comma-separated ints):").pack(side="left")
        self.vig_key_var = tk.StringVar(value="1,2,3")
        ttk.Entry(row2, textvariable=self.vig_key_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(row2, text="Decrypt", command=self.run_vigenere_numeric).pack(side="left", padx=6)

        self.vig_out = tk.Text(frm, wrap="word", state="disabled")
        self.vig_out.pack(fill="both", expand=True, padx=6, pady=6)

    def _build_auto_tab(self):
        frm = self.tab_auto

        info = ttk.LabelFrame(frm, text="Auto Hypothesis Tester")
        info.pack(fill="x", padx=6, pady=6)

        ttk.Label(info, text=(
            "Tries classical Vigenere break on stream: value = (numeric_group % 26).\n"
            "If your plaintext is not English-like, score may be misleading — but it will still reveal structure if it's not OTP."
        )).pack(anchor="w", padx=6, pady=6)

        ttk.Button(info, text="Run Auto Vigenere(mod26) Break", command=self.run_auto_vigenere).pack(anchor="w", padx=6, pady=(0,6))

        self.auto_out = tk.Text(frm, wrap="word", state="disabled")
        self.auto_out.pack(fill="both", expand=True, padx=6, pady=6)

    # -----------------------------
    # Actions
    # -----------------------------
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
            self.run_all()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file:\n{e}")

    def clear_all(self):
        self.input_text.delete("1.0", "end")
        for box in (self.parse_preview, self.stats_out, self.grid_out, self.vig_out, self.auto_out):
            box.configure(state="normal")
            box.delete("1.0", "end")
            box.configure(state="disabled")

    def run_all(self):
        text = self.get_input()
        if not text.strip():
            return
        self.run_parse_preview()
        self.run_stats()
        # grid/vig/auto are on-demand

    def run_parse_preview(self):
        text = self.get_input()
        records = extract_tokens_per_line(text)

        lines = []
        shown = 0
        for r in records:
            if shown >= 12:
                break
            if not r.get("parsed"):
                lines.append(f"[UNPARSED] {r.get('raw')}")
                shown += 1
                continue
            tokens = r["tokens"]
            nums = [t for t in tokens if re.fullmatch(r"\d{4,5}", t)]
            words = [t for t in tokens if not re.fullmatch(r"\d{4,5}", t)]
            lines.append(
                f"{r['prefix']} {r['msg_id']} | words={words} | nums={nums}"
            )
            shown += 1

        self.parse_preview.configure(state="normal")
        self.parse_preview.delete("1.0", "end")
        self.parse_preview.insert("1.0", "\n".join(lines))
        self.parse_preview.configure(state="disabled")

    def run_stats(self):
        text = self.get_input()
        nums = extract_numeric_groups(text)
        freq, total_digits = digit_frequency(nums)
        ent = shannon_entropy_digits(nums)
        reps = repetitions(nums)

        out = []
        out.append(f"Total numeric groups (4/5 digits): {len(nums)}")
        out.append(f"Total digits across groups: {total_digits}")
        out.append(f"Digit Shannon entropy: {ent:.4f} bits (max for digits ~ 3.3219)")
        out.append("")
        out.append("Digit frequency:")
        for d in "0123456789":
            out.append(f"  {d}: {freq[d]}")
        out.append("")
        out.append("Repetitions (groups appearing more than once):")
        if reps:
            for g, c in sorted(reps, key=lambda x: (-x[1], x[0]))[:50]:
                out.append(f"  {g}  x{c}")
            if len(reps) > 50:
                out.append(f"  ... and {len(reps)-50} more")
        else:
            out.append("  (none)")

        self.stats_out.configure(state="normal")
        self.stats_out.delete("1.0", "end")
        self.stats_out.insert("1.0", "\n".join(out))
        self.stats_out.configure(state="disabled")

    def run_grid_decode(self):
        text = self.get_input()
        nums = extract_numeric_groups(text)
        alpha = self.alpha_var.get()

        if len(alpha) < 100:
            messagebox.showwarning("Alphabet too short", "Alphabet must be at least 100 characters. Padding with '~'.")
            alpha = (alpha + ("~" * 100))[:100]
        else:
            alpha = alpha[:100]

        pairs = numbers_to_pairs_00_99(nums)
        decoded = grid_decode_pairs(pairs, alpha)

        out = []
        out.append("Grid Decode (00-99) over digit-pairs derived from numeric groups.")
        out.append("Note: 5-digit groups are chunked as pairs; last odd digit is padded with 0.")
        out.append("")
        out.append(decoded)

        self.grid_out.configure(state="normal")
        self.grid_out.delete("1.0", "end")
        self.grid_out.insert("1.0", "\n".join(out))
        self.grid_out.configure(state="disabled")

    def run_vigenere_numeric(self):
        text = self.get_input()
        mode = self.vig_mode.get()

        key_str = self.vig_key_var.get().strip()
        if not key_str:
            messagebox.showerror("Key error", "Please provide a key (comma-separated integers).")
            return

        try:
            key_nums = [int(x.strip()) for x in key_str.split(",") if x.strip() != ""]
        except Exception:
            messagebox.showerror("Key error", "Key must be comma-separated integers, e.g. 3,1,4")
            return

        nums_str = extract_numeric_groups(text)
        if not nums_str:
            messagebox.showinfo("No numbers", "No 4/5-digit numeric groups found.")
            return

        out = []
        out.append(f"Mode: {mode}")
        out.append(f"Key: {key_nums}")
        out.append("")

        if mode == "mod26_letters":
            vals = [int(n) % 26 for n in nums_str]
            # key must also be 0..25
            k = [x % 26 for x in key_nums]
            pt = vigenere_decrypt_mod26(vals, k)
            out.append("Decrypted letters (A-Z) from values = group % 26:")
            out.append(pt[:1000])

        elif mode == "mod100_pairs":
            # derive pairs 00-99, then treat each pair as 0..99 and decrypt mod100
            pairs = numbers_to_pairs_00_99(nums_str)
            vals = [int(p) for p in pairs if p.isdigit() and len(p) == 2]
            k = [x % 100 for x in key_nums]
            pt_vals = vigenere_decrypt_modN(vals, k, 100)
            # map back to pairs then to grid text using current alphabet
            alpha = self.alpha_var.get()
            if len(alpha) < 100:
                alpha = (alpha + ("~" * 100))[:100]
            else:
                alpha = alpha[:100]
            pair_strs = [f"{v:02d}" for v in pt_vals]
            decoded = grid_decode_pairs(pair_strs, alpha)
            out.append("Decrypted pairs -> Grid decoded text:")
            out.append(decoded[:2000])

        elif mode == "mod10000_groups":
            # use 4-digit groups only (ignore 5-digit) for cleaner mod10000
            g4 = [n for n in nums_str if len(n) == 4]
            if not g4:
                out.append("No 4-digit groups found to run mod10000.")
            else:
                vals = [int(n) for n in g4]
                k = [x % 10000 for x in key_nums]
                pt_vals = vigenere_decrypt_modN(vals, k, 10000)
                out.append("Decrypted 4-digit values (mod 10000), first 120 values:")
                out.append(" ".join(f"{v:04d}" for v in pt_vals[:120]))
                out.append("")
                # optionally map to bytes by mod256 and show printable preview
                bytes_vals = [v % 256 for v in pt_vals]
                out.append("ASCII-ish preview (value % 256 -> printable):")
                out.append(ints_to_printable_ascii(bytes_vals)[:2000])

        else:
            out.append("Unknown mode.")

        self.vig_out.configure(state="normal")
        self.vig_out.delete("1.0", "end")
        self.vig_out.insert("1.0", "\n".join(out))
        self.vig_out.configure(state="disabled")

    def run_auto_vigenere(self):
        text = self.get_input()
        nums_str = extract_numeric_groups(text)
        if not nums_str:
            messagebox.showinfo("No numbers", "No 4/5-digit numeric groups found.")
            return

        try:
            max_k = int(self.max_keylen_var.get().strip())
            max_k = max(1, min(max_k, 40))
        except:
            max_k = 12

        values = [int(n) % 26 for n in nums_str]
        top = break_vigenere_mod26(values, max_keylen=max_k, top_k=8)

        out = []
        out.append(f"Auto Vigenere(mod26) break on stream values = group % 26")
        out.append(f"Tested key lengths: 1..{max_k}")
        out.append("")
        out.append("Best candidates (lower score ~ more English-like):")
        out.append("")

        for i, c in enumerate(top, 1):
            out.append(f"[{i}] keylen={c['keylen']}  key={c['key_text']}  score={c['score']:.2f}")
            out.append(f"Preview: {c['preview']}")
            out.append("-" * 70)

        self.auto_out.configure(state="normal")
        self.auto_out.delete("1.0", "end")
        self.auto_out.insert("1.0", "\n".join(out))
        self.auto_out.configure(state="disabled")


if __name__ == "__main__":
    app = CipherLabGUI()
    app.mainloop()
