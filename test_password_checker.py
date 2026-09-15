from password_checker import check_length, check_digit, check_username, check_rotation

length_ok, length_verdict = check_length("test")
assert length_ok == False
print("PASS: check_length correctly identified weak password (length_ok = False)")

length_ok, length_verdict = check_length("abcdefghijklmnop")
assert length_ok == True
print("PASS: check_length correctly identified strong password (length_ok = True)")

has_digit = check_digit("password")
assert has_digit == False
print("PASS: check_digit correctly returned False for password with no digits")

has_digit = check_digit("password1")
assert has_digit == True
print("PASS: check_digit correctly returned True for password containing a digit")

not_username = check_username("admin", "admin")
assert not_username == False
print("PASS: check_username correctly returned False when password matches username")

not_username = check_username("SecurePassword123", "admin")
assert not_username == True
print("PASS: check_username correctly returned True when password differs from username")

rotation_ok, rotation_verdict = check_rotation(18)
assert rotation_ok == False
print("PASS: check_rotation correctly returned False for 18-month interval")

rotation_ok, rotation_verdict = check_rotation(6)
assert rotation_ok == True
print("PASS: check_rotation correctly returned True for 6-month interval")

print("----------------------------------------")
print("All 8 tests passed.")