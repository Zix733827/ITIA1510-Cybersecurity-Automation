known_breached = ["password", "password123", "123456", "qwerty", "letmein", "welcome", "monkey", "dragon", "master", "sunshine"]
#list is outside the main block so functions and the test file can both access it.

def check_length(password):

    password_length = len(password)

    if password_length < 8:
        length_verdict = "WEAK -- does not meet minimum length requirements"
    elif password_length <= 11:
        length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
    elif password_length <= 14:
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

    #The overall password requirement is at least 15 characters.
    length_ok = password_length >= 15

    return length_ok, length_verdict
    #Checks the password length by taking a password string and returns length_ok bool and length_verdict str.

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

def check_rotation(rotation_interval):

    if rotation_interval > 12:
        rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    rotation_ok = rotation_interval <= 12

    return rotation_ok, rotation_verdict
    #Checks the password rotation interval. Takes the interval in months. Returns rotation_ok as a Bool and rotation_verdict as a str.

def audit_password(account, username, password, rotation_interval, known_breached):

    not_breached = check_breach(password, known_breached)

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)
    #Each individual security check is handled by its own function.

    overall_pass = length_ok and has_digit and not_username and not_breached
    #All three password conditions must be True for an overall PASS.

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
        ["Gmail", "jsmith", "password123", 12],
        ["SSH Server", "jsmith", "jsmith", 24],
        ["VPN", "jsmith", "Tr0ub4dor&3correct", 3],
        ["Company Email", "jsmith", "summer2024!", 6],
        ["GitHub", "jsmith", "Blue-Harbor-72-Lantern", 6],
    ]
    #Stored in a list for Week 05 instead of being entered with input().

    failed_accounts = []
    critical_accounts = []
    #lists keep the account names so they can be displayed in the final summary.

    total_pass = 0

    for credential in credentials:
    #A for loop walks through each credential record in the credentials list.
        
        account = credential[0]
        username = credential[1]
        password = credential[2]
        rotation_interval = credential[3]
        #Each value is accessed by its index and stored in a meaningful variable.
        
        passed, failed, critical = audit_password(
            account,
            username,
            password,
            rotation_interval,
            known_breached
        )
        #audit_password performs all checks and returns the result for this account.

        total_pass = total_pass + passed

        if failed == 1:
            failed_accounts.append(account)
        #Failed accounts are saved so their names can be shown in the summary.

        
        if critical == 1:
            critical_accounts.append(account)
        #Critical accounts are saved so their names can be shown in the summary.

    print("========================================")
    print("   BATCH AUDIT SUMMARY")
    print("========================================")
    print("Credentials audited: " + str(len(credentials)))
    print("Passed:              " + str(total_pass))
    print("Failed:              " + str(len(failed_accounts)))
    print("----------------------------------------")
    print("Failed accounts:     " + ", ".join(failed_accounts))
    print("Critical flags:      " + str(len(critical_accounts)))
    print("Critical accounts:   " + ", ".join(critical_accounts))
    print("----------------------------------------")
    print("NOTE: Breach list and credentials are hardcoded -- file reading coming in Week 08.")
    print("========================================")
    #The summary runs after the loop so all the totals are relected in the batch