known_breached = ["password", "password123", "123456", "qwerty", "letmein", "welcome", "monkey", "dragon", "master", "sunshine"]
#list is outside the main block so functions and the test file can both access it.

policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True
}
#Policy is outside the main block so the functions and test file can access it.

def check_length(password, policy):

    password_length = len(password)

    if password_length < policy["min_length"]:
        length_verdict = "WEAK -- does not meet minimum length requirements"
    elif password_length < 12:
        length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
    elif password_length < policy["strong_length"]:
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

    #Reading the limit from policy is better than hardcoding it because the rule only needs to be changed in one place.
    length_ok = password_length >= policy["strong_length"]

    return length_ok, length_verdict

def check_digit(password):

    has_digit = False

    for char in password:
        if char in "0123456789":
            has_digit = True
    #loop avoids repeating ten separate digit checks.

    return has_digit
    #Checks whether a password contains a digit. Takes a password string. Returns has_digit as a Bool.

def check_username(password, username):

    not_username = password != username

    return not_username
    #Checks whether the password differs from the username. Takes two strings. Returns not_username as a Bool.

def check_rotation(rotation_interval, policy):

    if rotation_interval > policy["max_rotation_months"]:
        rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= policy["good_rotation_months"]:
        rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    rotation_ok = rotation_interval <= policy["max_rotation_months"]

    return rotation_ok, rotation_verdict
    #checks the password rotation interval using limits stored in policy.

def audit_password(account, username, password, rotation_interval, known_breached, policy):

    not_breached = check_breach(password, known_breached)

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval, policy)
    #Each individual security check is handled by its own function.

    overall_pass = length_ok and has_digit and not_username and not_breached
    #All four password conditions must be True for an overall PASS.

    passed = 0
    failed = 0
    critical = 0

    if overall_pass:
        passed = 1
    else:
        failed = 1

    if not_username == False or not_breached == False:
        critical = 1

    print("========================================")
    print("   PASSWORD AUDIT REPORT")
    print("========================================")
    print("Account:           " + account)
    print("Username:          " + username)
    print("Password length:   " + str(password_length) + " characters")
    print("Length score:      " + str(length_score) + " points")
    print("Rotation interval: " + str(rotation_interval) + " months")
    print("Rotations (3 yr):  " + str(rotation_count))
    print("----------------------------------------")
    print("Length verdict:    " + length_verdict)

    if has_digit:
        print("Digit found:       YES")
    else:
        print("Digit found:       NO")

    if not_username:
        print("Username match:    NO")
    else:
        print("Username match:    YES")
        print("CRITICAL -- password must not match username.")

    if not_breached:
        print("Breach check:      PASS -- password not found in known breach list")
    else:
        print("Breach check:      CRITICAL -- password found in known breach list")
    #Show whether the password was found in the known breach list.

    print("Rotation verdict:  " + rotation_verdict)
    print("----------------------------------------")

    if overall_pass:
        print("OVERALL: PASS -- password meets all checked criteria")
    else:
        print("OVERALL: FAIL -- see findings above")

    print("========================================")
    print()

    return passed, failed, critical
    #Audits one password. Takes account data and returns (passed, failed, critical) as a tuple.   

def check_breach(password, known_breached):

    not_breached = password not in known_breached

    return not_breached
#Checks whether a password appears in the known breach list. Takes a password and list. Returns not_breached as a Bool

if __name__ == "__main__":
#Prevents this section from running when password_checker.py is imported by the test file.

    credentials = [
        {"account": "Gmail", "username": "jsmith", "password": "password123", "rotation_interval": 12},
        {"account": "SSH Server", "username": "jsmith", "password": "jsmith", "rotation_interval": 24},
        {"account": "VPN", "username": "jsmith", "password": "Tr0ub4dor&3correct", "rotation_interval": 3},
        {"account": "Company Email", "username": "jsmith", "password": "summer2024!", "rotation_interval": 6},
        {"account": "GitHub", "username": "jsmith", "password": "Blue-Harbor-72-Lantern", "rotation_interval": 6},
    ]
    #Credentials are stored as dictionaries so each value can be accessed by its field name.

    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }
    # One dictionary keeps all batch totals and account lists together.

    for credential in credentials:
        # A for loop walks through each credential dictionary in the credentials list.

        account = credential["account"]
        username = credential["username"]
        password = credential["password"]
        rotation_interval = credential["rotation_interval"]
        # Each value is accessed by its dictionary key instead of its position.

        passed, failed, critical = audit_password(
            account,
            username,
            password,
            rotation_interval,
            known_breached,
            policy
        )
        # audit_password performs all checks and returns the result for this account.

        summary["total"] += 1
        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        if failed == 1:
            summary["failed_accounts"].append(account)
        # Failed account names are stored in the summary dictionary.

        if critical == 1:
            summary["critical_accounts"].append(account)
        # Critical account names are stored in the summary dictionary.

    # This section is outside the for loop but remains inside the main block.
    print("========================================")
    print("   BATCH AUDIT SUMMARY")
    print("========================================")
    print("Credentials audited: " + str(summary["total"]))
    print("Passed:              " + str(summary["passed"]))
    print("Failed:              " + str(summary["failed"]))
    print("----------------------------------------")
    print("Failed accounts:     " + ", ".join(summary["failed_accounts"]))
    print("Critical flags:      " + str(summary.get("critical", 0)))
    print("Critical accounts:   " + ", ".join(summary["critical_accounts"]))
    print("----------------------------------------")
    print("NOTE: Credentials and breach list are hardcoded -- file reading coming in Week 07.")
    print("========================================")
    # The summary runs after the loop so it displays the final totals for all credentials.