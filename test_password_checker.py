import json

from password_checker import (check_length, check_digit, check_username, check_rotation,
                              check_breach, load_credentials, load_breached, write_report,
                              save_summary, load_summary, load_history, add_to_history,
                              save_history, policy, breach_verdicts)

known_breached = load_breached("breached.txt")

length_ok, length_verdict = check_length("test")
assert length_ok == False
print("PASS: check_length correctly identified weak password (length_ok = False)")
#4-character password should return False because it does not meet the 15-character requirement.


length_ok, length_verdict = check_length("abcdefghijklmnop")
assert length_ok == True
print("PASS: check_length correctly identified strong password (length_ok = True)")
#16-character password should return True because it meets the 15-character requirement.


has_digit = check_digit("password")
assert has_digit == False
print("PASS: check_digit correctly returned False for password with no digits")
#Password with no digits should make check_digit return False.


has_digit = check_digit("password1")
assert has_digit == True
print("PASS: check_digit correctly returned True for password containing a digit")
#Password containing a number should make check_digit return True.


not_username = check_username("admin", "admin")
assert not_username == False
print("PASS: check_username correctly returned False when password matches username")
#Matching the password to the username is unsafe, so this test expects False.


not_username = check_username("SecurePassword123", "admin")
assert not_username == True
print("PASS: check_username correctly returned True when password differs from username")
#Password that does not match the username is safe, so this test expects True.


rotation_ok, rotation_verdict = check_rotation(18)
assert rotation_ok == False
print("PASS: check_rotation correctly returned False for 18-month interval")
#Over the policy's maximum rotation limit, so rotation_ok should be False.


rotation_ok, rotation_verdict = check_rotation(6)
assert rotation_ok == True
print("PASS: check_rotation correctly returned True for 6-month interval")
#Within the policy's maximum rotation limit, so rotation_ok should be True.


not_breached = check_breach("password123", known_breached)
assert not_breached == False
print("PASS: check_breach correctly returned False for a breached password")
#A password in the breach list should return False because it is known to be compromised.


not_breached = check_breach("Blue-Harbor-72-Lantern", known_breached)
assert not_breached == True
print("PASS: check_breach correctly returned True for a non-breached password")
#A password not in the breach list should return True because it is not known to be compromised.


length_ok, _ = check_length("abcdefghijklmn")
assert length_ok == False
print("PASS: Minimum strong length is 15")
#Tests that the strong password length is stored correctly in the policy dictionary.


assert check_digit("Password123") == True
print("PASS: Password digit requirement works")

# Week 10: Verify the audit history limit.
assert policy["history_runs"] == 3
print("PASS: History limit is 3")

# Week 09 Test 1: Save and load a JSON summary.
sample = {
    "total": 2,
    "passed": 1,
    "failed": 1,
    "critical": 1,
    "failed_accounts": ["Gmail"],
    "critical_accounts": ["Gmail"]
}

save_summary(sample, "test_summary.json")
assert load_summary("test_summary.json") == sample
print("PASS: JSON summary saves and loads correctly")


# Week 09 Test 2: Account lists remain lists after loading.
loaded = load_summary("test_summary.json")
assert isinstance(loaded["failed_accounts"], list)
print("PASS: failed_accounts remains a list")


with open("credentials.txt", "r") as f:
    credentials_lines = f.readlines()

with open("audit_summary.json", "r") as f:
    summary_text = f.read()

for line in credentials_lines:
    if line.strip():
        password = line.strip().split(",")[2]
        assert password not in summary_text

print("PASS: JSON summary contains no passwords")

# Week 10 Test 1: A missing history file returns an empty list.
assert load_history("missing_test_history.json") == []
print("PASS: Missing history file returns an empty list")


# Week 10 Test 2: The first audit run is numbered 1.
sample = {
    "total": 2,
    "passed": 1,
    "failed": 1,
    "critical": 1,
    "failed_accounts": ["Gmail"],
    "critical_accounts": ["Gmail"]
}

history = add_to_history([], sample, 3)
assert len(history) == 1
assert history[0]["run"] == 1
print("PASS: First audit history run is numbered 1")


# Week 10 Test 3: Keep only the newest 2 runs.
history = []

for i in range(3):
    history = add_to_history(history, sample, 2)

assert [entry["run"] for entry in history] == [2, 3]
print("PASS: add_to_history kept only the newest 2 runs")


# Week 10 Test 4: Save and reload audit history.
save_history(history, "test_history.json")
loaded_history = load_history("test_history.json")

assert loaded_history == history
print("PASS: Audit history saves and loads correctly")

# Test 1: Gmail is on the breach list.
credentials = load_credentials("credentials.txt")
known_breached = load_breached("breached.txt")

result = breach_verdicts("jsmith", credentials, known_breached)

assert result["accounts"][0] == {
    "account": "Gmail",
    "on_breach_list": True
}
print("PASS: breach_verdicts marked Gmail as breached")


# Test 2: Unknown username returns no accounts.
result = breach_verdicts("nobody", credentials, known_breached)

assert result["accounts"] == []
print("PASS: breach_verdicts returns empty accounts for unknown user")


# Test 3: Passwords are not exposed.
result = breach_verdicts("jsmith", credentials, known_breached)
result_json = json.dumps(result)

for credential in credentials:
    if credential["password"] != credential["username"]:
        assert credential["password"] not in result_json

print("PASS: breach_verdicts does not expose passwords")

print("----------------------------------------")
print("All 23 tests passed.")