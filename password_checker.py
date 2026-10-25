import json
import os

policy = {
    "history_runs": 3
}

def check_length(password):
    """Checks password length and returns length_ok and length_verdict."""

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
    #All four password conditions must be True for an overall PASS.

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

def audit_password(account, username, password, rotation_interval, known_breached, report_lines, current_number, total_credentials):

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

    report_lines.append("========================================")
    report_lines.append("   PASSWORD AUDIT REPORT  (" + str(current_number) + " of " + str(total_credentials) + ")")
    report_lines.append("========================================")
    report_lines.append("Account:           " + account)
    report_lines.append("Username:          " + username)
    report_lines.append("Password length:   " + str(password_length) + " characters")
    report_lines.append("Length score:      " + str(length_score) + " points")
    report_lines.append("Rotation interval: " + str(rotation_interval) + " months")
    report_lines.append("Rotations (3 yr):  " + str(rotation_count))
    report_lines.append("----------------------------------------")
    report_lines.append("Length verdict:    " + length_verdict)

    if has_digit:
        report_lines.append("Digit found:       YES")
    else:
        report_lines.append("Digit found:       NO")

    if not_username:
        report_lines.append("Username match:    NO")
    else:
        report_lines.append("Username match:    YES")
        report_lines.append("CRITICAL -- password must not match username.")

    if not_breached:
        report_lines.append("Breach check:      PASS -- password not found in known breach list")
    else:
        report_lines.append("Breach check:      CRITICAL -- password found in known breach list")
    #Show whether the password was found in the known breach list.

    report_lines.append("Rotation verdict:  " + rotation_verdict)
    report_lines.append("----------------------------------------")

    if overall_pass:
        report_lines.append("OVERALL: PASS -- password meets all checked criteria")
    else:
        report_lines.append("OVERALL: FAIL -- see findings above")

    report_lines.append("========================================")
    report_lines.append("")

    return passed, failed, critical
    #Audits one password. Takes account data and returns (passed, failed, critical) as a tuple.   

def check_breach(password, known_breached):
    """Checks whether a password appears in the known breach list and returns not_breached."""

    not_breached = password not in known_breached
    #"in" checks whether a complete value exists in a list, while a for loop would check each character in the string against each character in the list.

    return not_breached
#Checks whether a password appears in the known breach list. Takes a password and list. Returns not_breached as a Bool

def load_breached(filepath):
    """Read the breached password file. Returns a list of password strings."""
    known_breached = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            if line != "":
                known_breached.append(line)
            #Blank lines are skipped so they do not become passwords in the list.

    return known_breached
    #Using with closes the file automatically, even if an error occurs.

def load_credentials(filepath):
    """Read the credentials file. Returns a list of credential dictionaries."""
    credentials = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            if line == "":
                continue

            fields = line.split(",")

            credentials.append({
                "account": fields[0],
                "username": fields[1],
                "password": fields[2],
                "rotation_interval": int(fields[3]),
            })
            #Skip blank lines so they are not treated as credential records.

    return credentials
    #Using with automatically closes the file when reading is finished.

def write_report(report_lines, filepath):
    """Write each string in report_lines to the file as one line."""
    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")

def save_summary(summary, filepath):
    #Save the summary dictionary as JSON.
    with open(filepath, "w") as f:
        json.dump(summary, f, indent=2)


def load_summary(filepath):
    #Read the saved JSON file back into a dictionary.
    with open(filepath, "r") as f:
        return json.load(f)

def load_history(filepath):
    """Load previous audit runs from a JSON file."""
    #The first run has no history file, so start with an empty list.
    if not os.path.exists(filepath):
        return []

    with open(filepath, "r") as f:
        return json.load(f)

def add_to_history(history, summary, keep):
    """Add one audit run and keep only the newest entries."""

    #Use the newest run number because trimming makes the list length unreliable.
    if history:
        run_number = history[-1]["run"] + 1
    else:
        run_number = 1

    history.append({
        "run": run_number,
        "passed": summary["passed"],
        "failed": summary["failed"],
        "critical_accounts": summary["critical_accounts"]
    })

    #Trim older runs so the history does not grow without limit.
    return history[-keep:]

def save_history(history, filepath):
    """Save the audit history as a JSON file."""
    with open(filepath, "w") as f:
        json.dump(history, f, indent=2)

if __name__ == '__main__':
    credentials = load_credentials("credentials.txt")
    known_breached = load_breached("breached.txt")
    report_lines = []
    #Prevents this section from running when password_checker.py is imported by the test file.

    failed_accounts = []
    critical_accounts = []
    #lists keep the account names so they can be displayed in the final summary.

    total_pass = 0

    for current_number, credential in enumerate(credentials, start=1):
    #A for loop walks through each credential record in the credentials list.
        
        account = credential["account"]
        username = credential["username"]
        password = credential["password"]
        rotation_interval = credential["rotation_interval"]
        #Each value is accessed by its dictionary key and stored in a meaningful variable.
        
        passed, failed, critical = audit_password(
            account,
            username,
            password,
            rotation_interval,
            known_breached,
            report_lines,
            current_number,
            len(credentials)
        )
        #audit_password performs all checks and returns the result for this account.

        total_pass = total_pass + passed

        if failed == 1:
            failed_accounts.append(account)
        #Failed accounts are saved so their names can be shown in the summary.

        
        if critical == 1:
            critical_accounts.append(account)
        #Critical accounts are saved so their names can be shown in the summary.

    report_lines.append("========================================")
    report_lines.append("   BATCH AUDIT SUMMARY")
    report_lines.append("========================================")
    report_lines.append("Credentials audited: " + str(len(credentials)))
    report_lines.append("Passed:              " + str(total_pass))
    report_lines.append("Failed:              " + str(len(failed_accounts)))
    report_lines.append("----------------------------------------")
    report_lines.append("Failed accounts:     " + ", ".join(failed_accounts))
    report_lines.append("Critical flags:      " + str(len(critical_accounts)))
    report_lines.append("Critical accounts:   " + ", ".join(critical_accounts))
    report_lines.append("========================================")
    #The summary runs after the loop so all the totals are relected in the batch

    for line in report_lines:
        print(line)

    write_report(report_lines, "report.txt")
    #Print and save the same report lines so the console and report file match.

        # Build the summary dictionary using the existing audit results.
    summary = {
        "total": len(credentials),
        "passed": total_pass,
        "failed": len(failed_accounts),
        "critical": len(critical_accounts),
        "failed_accounts": failed_accounts,
        "critical_accounts": critical_accounts
    }

    # Save the audit results as JSON without including passwords.
    save_summary(summary, "audit_summary.json")

    # Load previous audits, add the current run, and save the updated history.
    history = load_history("audit_history.json")
    history = add_to_history(history, summary, policy["history_runs"])
    save_history(history, "audit_history.json")