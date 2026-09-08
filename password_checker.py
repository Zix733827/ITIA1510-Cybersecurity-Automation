batch_size = 3
count = 0
#3 passwords processed for the program to batch audit

total_pass = 0
total_fail = 0
critical_count = 0
#Counters outside the loop so the totals are preserved for all checks

while count < batch_size:
#Loop repeats the full audit until all passwrords are processed

    account = input("Enter the account or system name: ")
    username = input("Enter the username: ")
    password = input("Enter the password to analyze: ")
    #Collect account information and the password to analyze

    rotation_interval = input("Enter the password rotation interval in months: ")
    rotation_interval = int(rotation_interval)
    #The rotation interval must be an integer because it will be used in a math calculation

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval
    #Calculate basic password and rotation information

    if password_length < 8:
        length_verdict = "WEAK -- does not meet minimum length requirements"
    elif password_length <= 11:
        length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
    elif password_length <= 14:
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"
    #Rotation frequency is classified so the report can warn about passwords kept for too long

    has_digit = False
    for char in password:
        if char in '0123456789':
            has_digit = True
    #Checks each character for a digit and replaces the long Week 02 OR chain

    not_username = password != username
    #Boolean records whether they are different

    if rotation_interval > 12:
        rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"
    #Rotation frequency is classified so the report can warn about passwords kept for too long

    length_ok = password_length >= 15
    overall_pass = length_ok and has_digit and not_username
    #All three conditions must be True for the password to receive an overall PASS

    if overall_pass:
        total_pass = total_pass + 1
    else:
        total_fail = total_fail + 1

    if not_username == False:
        critical_count = critical_count + 1
    #Tracks the results across the batch for the final summary report

    print("========================================")
    print("   PASSWORD AUDIT REPORT  (" + str(count + 1) + " of " + str(batch_size) + ")")
    print("========================================")
    print("Account:           " + account)
    print("Username:          " + username)
    print("Password length:   " + str(password_length) + " characters")
    print("Length score:      " + str(length_score) + " points")
    print("Rotation interval: " + str(rotation_interval) + " months")
    print("Rotations (3 yr):  " + str(rotation_count))
    print("----------------------------------------")
    print("Length verdict:    " + length_verdict)
    #Display the password audit report

    if has_digit:
        print("Digit found:       YES")
    else:
        print("Digit found:       NO")
    #Converting the Boolean result into YES or NO makes the finding easier for the user to understand

    if not_username:
        print("Username match:    NO")
    else:
        print("Username match:    YES")
        print("CRITICAL -- password must not match username.")

    print("Rotation verdict:  " + rotation_verdict)
    print("----------------------------------------")
    #Matching the username is shown as a critical warning because it creates an easily guessed password

    if overall_pass:
        print("OVERALL: PASS -- password meets all checked criteria")
    else:
        print("OVERALL: FAIL -- see findings above")

    print("========================================")
    #The final decision depends on the combined Boolean result calculated above

    count = count + 1
    #The count must increase so the while loop eventually reaches the batch size and stops

print("========================================")
print("   BATCH AUDIT SUMMARY")
print("========================================")
print("Passwords audited: " + str(count))
print("Passed:            " + str(total_pass))
print("Failed:            " + str(total_fail))
print("Critical flags:    " + str(critical_count))
print("----------------------------------------")
print("NOTE: Input is still hardcoded -- file reading coming in Week 08.")
print("========================================")
#The summary runs after the loop so all the totals are relected in the batch