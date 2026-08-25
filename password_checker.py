account = input("Enter the account or system name: ")
username = input("Enter the username: ")
password = input("Enter the password to analyze: ")
#Collect account information and the password to analyze

rotation_interval = input("Enter the password rotation interval in months: ")
rotation_interval = int(rotation_interval)

password_length = len(password)
length_score = password_length * 10
rotation_count = 36 // rotation_interval
#Calculate basic password and rotation information

print("========================================")
print("   PASSWORD AUDIT REPORT")
print("========================================")
print("Account:           " + account)
print("Username:          " + username)
print("Password length:   " + str(password_length) + " characters")
print("Length score:      " + str(length_score) + " points")
print("Rotation interval: " + str(rotation_interval) + " months")
print("Rotations (3 yr):  " + str(rotation_count))
print("========================================")
#Display the password audit report
