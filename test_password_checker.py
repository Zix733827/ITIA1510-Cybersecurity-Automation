from password_checker import (check_length, check_digit, check_username, check_rotation,
                              check_breach, load_credentials, load_breached, write_report, save_summary, load_summary)
known_breached = load_breached("breached.txt")
#Imports the functions to be tested from the password_checker.py file.

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
#Over the 12-month limit, so rotation_ok should be False.

rotation_ok, rotation_verdict = check_rotation(6)
assert rotation_ok == True
print("PASS: check_rotation correctly returned True for 6-month interval")
#Within the 12-month limit, so rotation_ok should be True.

not_breached = check_breach("password123", known_breached)
assert not_breached == False
print("PASS: check_breach correctly returned False for a breached password")
#A password in the breach list should return False because it is known to be compromised.

not_breached = check_breach("Blue-Harbor-72-Lantern", known_breached)
assert not_breached == True
print("PASS: check_breach correctly returned True for a non-breached password")
#A password not in the breach list should return True because it is not known to be compromised.

credentials = load_credentials("credentials.txt")
if isinstance(credentials, list):
    print("PASS: load_credentials returned a list")
else:
    print("FAIL: load_credentials did not return a list")
# Test load_credentials() returns a list.

if "account" in credentials[0]:
    print("PASS: first credential contains an account key")
else:
    print("FAIL: first credential does not contain an account key")
# Test the first credential contains the account key.

breached = load_breached("breached.txt")
assert isinstance(breached, list)
print("PASS: load_breached returned a list")
# Test load_breached() returns a list.

assert "password123" in breached
print("PASS: password123 was found in breached list")
# Test that password123 was loaded from breached.txt.

test_lines = ["Test line 1", "Test line 2"]
write_report(test_lines, "test_report.txt")

with open("test_report.txt", "r") as f:
    test_text = f.read()

assert test_text == "Test line 1\nTest line 2\n"
print("PASS: write_report wrote the expected text")
# Test write_report() by writing two lines and reading them back.

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


# Week 09 Test 2: Verify account lists remain lists.
loaded = load_summary("test_summary.json")
assert isinstance(loaded["failed_accounts"], list)
print("PASS: failed_accounts remains a list")


# Week 09 Test 3: Verify the summary contains no passwords.
with open("credentials.txt", "r") as f:
    credentials_lines = f.readlines()

with open("audit_summary.json", "r") as f:
    summary_text = f.read()

for line in credentials_lines:
    if line.strip():
        password = line.strip().split(",")[2]
        assert password not in summary_text

print("PASS: JSON summary contains no passwords")

print("----------------------------------------")
print("All 18 tests passed.")