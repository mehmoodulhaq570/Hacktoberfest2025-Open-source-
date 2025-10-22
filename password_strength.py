# password_strength.py
"""
Simple Password Strength Checker

- Estimates entropy based on which character classes are used.
- Checks for length, common-passwords, repeated characters, and sequences.
- Returns a score (0-4) and feedback messages.

No external libraries required.
"""

import math
import re

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "letmein", "baseball",
    "iloveyou", "trustno1", "123123", "sunshine", "master", "welcome",
    "shadow", "ashley", "football", "jesus", "michael", "ninja", "mustang"
}

SPECIAL_CHARS = r"!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"


def estimate_entropy(password: str) -> float:
    """Estimate entropy (bits) using used character classes as a rough pool approach."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(rf"[{re.escape(SPECIAL_CHARS)}]", password):
        pool += len(SPECIAL_CHARS)
    # If no class matched (shouldn't happen for non-empty), fallback:
    pool = max(pool, 1)
    entropy = len(password) * math.log2(pool)
    return entropy


def has_sequence(s: str, length=3) -> bool:
    """Detect simple increasing or decreasing sequences like 'abc' or '321'"""
    s_lower = s.lower()
    for i in range(len(s_lower) - length + 1):
        chunk = s_lower[i:i + length]
        # check alphabetical sequence
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            return True
        if all(ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(len(chunk) - 1)):
            return True
    return False


def repetitive_chars(s: str, threshold=4) -> bool:
    """Return True if the same character repeats >= threshold times consecutively."""
    return re.search(r"(.)\1{" + str(threshold - 1) + r",}", s) is not None


def score_password(password: str) -> dict:
    """
    Analyze password and return:
    {
      'score': int (0-4),
      'entropy': float,
      'strength': one of ['Very weak','Weak','Moderate','Strong','Very strong'],
      'feedback': [list of suggested improvements]
    }
    """
    feedback = []
    if not password:
        return {
            'score': 0,
            'entropy': 0.0,
            'strength': 'Very weak',
            'feedback': ['Password is empty. Use a passphrase or a strong password.']
        }

    pwd = password.strip()
    length = len(pwd)

    # Quick checks
    if pwd.lower() in COMMON_PASSWORDS:
        feedback.append("This password is a commonly used password — avoid it.")
    if length < 8:
        feedback.append("Password is short. Use at least 12 characters for better security.")
    if repetitive_chars(pwd):
        feedback.append("Avoid long runs of the same character (e.g., 'aaaaaa').")
    if has_sequence(pwd):
        feedback.append("Avoid predictable sequences like 'abcd' or '1234'.")

    # Character class checks
    classes_used = []
    if re.search(r"[a-z]", pwd):
        classes_used.append("lowercase")
    if re.search(r"[A-Z]", pwd):
        classes_used.append("uppercase")
    if re.search(r"[0-9]", pwd):
        classes_used.append("digits")
    if re.search(rf"[{re.escape(SPECIAL_CHARS)}]", pwd):
        classes_used.append("special characters")

    if len(classes_used) < 2:
        feedback.append("Use a mix of uppercase, lowercase, digits, and symbols.")

    entropy = estimate_entropy(pwd)

    # Score mapping using entropy and length, but penalize common/simple issues
    # We'll compute base_score from entropy
    if entropy < 28:
        base_score = 0  # very weak
    elif entropy < 36:
        base_score = 1  # weak
    elif entropy < 60:
        base_score = 2  # moderate
    elif entropy < 90:
        base_score = 3  # strong
    else:
        base_score = 4  # very strong

    # Penalize for being in common list or too short or repetitive
    penalty = 0
    if pwd.lower() in COMMON_PASSWORDS:
        penalty += 2
    if length < 8:
        penalty += 1
    if repetitive_chars(pwd):
        penalty += 1
    if has_sequence(pwd):
        penalty += 1

    # Calculate final score, clamp between 0 and 4
    final_score = max(0, min(4, base_score - penalty))

    strength_labels = ['Very weak', 'Weak', 'Moderate', 'Strong', 'Very strong']
    strength = strength_labels[final_score]

    # Helpful, actionable suggestions if not already strong
    if final_score < 4:
        if length < 16:
            feedback.append("Consider a passphrase (3–4 random words) or increase length to 16+ characters.")
        if 'digits' not in classes_used:
            feedback.append("Include digits (0-9).")
        if 'uppercase' not in classes_used:
            feedback.append("Include uppercase letters (A-Z).")
        if 'lowercase' not in classes_used:
            feedback.append("Include lowercase letters (a-z).")
        if 'special characters' not in classes_used:
            feedback.append("Include symbols (e.g., !@#$%).")
        if pwd.lower() in COMMON_PASSWORDS:
            feedback.append("Use a unique password not found in common lists.")
    else:
        feedback.append("Looks good — long, varied, and not common. Consider using a password manager to store it.")

    # Remove duplicate suggestions and tidy feedback
    seen = set()
    feedback_unique = []
    for f in feedback:
        if f not in seen:
            feedback_unique.append(f)
            seen.add(f)

    return {
        'score': final_score,
        'entropy': round(entropy, 2),
        'strength': strength,
        'feedback': feedback_unique
    }


# ---------- Simple CLI for manual testing ----------
if __name__ == "__main__":
    print("Password strength checker — enter a password (or multiple, separated by newline). Ctrl+D / Ctrl+Z to quit.\n")
    try:
        while True:
            pwd = input("Password> ")
            res = score_password(pwd)
            print(f"\n Strength: {res['strength']}  (score {res['score']}/4)  | Entropy ≈ {res['entropy']} bits")
            print(" Suggestions:")
            for s in res['feedback']:
                print("  -", s)
            print("-" * 60)
    except (EOFError, KeyboardInterrupt):
        print("\nBye.")
