from password_checker import check_length, check_digit, check_username, check_rotation, check_breach, known_breached
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

print("----------------------------------------")
print("All 10 tests passed.")