user_list = []
loggedUID = None


# This function receives a phone number from the user | It validates its length, beginning, and character type.
def add_phone_num():
    while True:
        phone = input("Please enter your cellphone number > ")
        if not phone.isdigit():
            print("Input must contain only digits")
        elif len(phone) != 10:
            print("Input must be exactly 10 digits long")
        elif phone[:2] != "05":
            print("Cellphone number must begin with - 05 ")
        else:
            return phone


# This function receives a username from the user.
# It validates it is not "Null", and that it does not exist for previous users.
def add_username():
    while True:
        name = input("Insert the desired username > ")
        if any(user.get("username") == name for user in user_list):
            print("Username already exists")
        elif name == "":
            print("Username can not be Null")
        else:
            return name


# This function receives a password from the user | It validates it is longer than 8 characters.
def add_passwd():
    while True:
        password = input("Insert the desired password > ")
        if len(password) <= 8:
            print("Password is shorter than 8 characters")
        else:
            return password


# This function receives an email address from the user.
# It validates its format by checking for the existence of '@' and the ending '.com'.
def add_email():
    while True:
        email = input("Insert your mail address > ")
        if email.endswith(".com") or email.endswith(".co.il"):
            if "@" in email:
                return email
            else:
                print("Invalid email address format. Must contain '@'")
        else:
            print("Invalid email address format. Must end with '.com' or '.co.il' ")


# This function receives the gender of the user | It validates it is either "male" or "female".
def add_gender():
    while True:
        gender = input("Insert your gender (male/female) > ")
        if gender.lower() not in ["male", "female"]:
            print("Invalid gender. Must be 'male' or 'female'")
        else:
            return gender.lower()


# This function sets the Admin "Status" of the user | It receives boolean values.
def set_admin():
    while True:
        is_admin = input("Are you an admin? (True/False) > ")
        if is_admin == "True" or is_admin == "False":
            return is_admin
        else:
            print("Invalid input, the input must be True/False")


# This function creates a dictionary (using the previous functions).
# It adds the new dictionary to the list of all the users using "append" (user_list).
def registration():
    user_details = {
        "username": add_username(),
        "firstname": input("Insert your firstname > "),
        "lastname": input("Insert your lastname > "),
        "password": add_passwd(),
        "email": add_email(),
        "phone": add_phone_num(),
        "gender": add_gender(),
        "is_admin": set_admin()
    }
    user_list.append(user_details)
    print("Registration successful!")


# This function prints all the users in "user_list" one by one.
def show_all():
    for user in user_list:
        for key, value in user.items():
            print(f"{key} : {value}")
        print()
        print("******************************************************")
        print()


# This function finds the index of a specific user in the list "user_list".
def get_uid(usern):
    for i in range(len(user_list)):
        if user_list[i]["username"] == usern:
            return i
    return None


# This function "logs in" to a specific user by verifying if the username and password match.
# It checks the existence of a user with the inserted username.
# And allows to re-insert a password in case of a wrong attempt.
# After a successful login, it transfers the user to the next menu.
def login():
    if len(user_list) == 0:
        print("Please register before logging in")
        main_menu()

    usern = input("Insert your username > ")
    uid = get_uid(usern)
    if uid is not None:
        pw = input("Insert your password > ")
        while True:
            if user_list[uid]["password"] == pw:
                global loggedUID
                loggedUID = uid
                print("Logged in successfully!")
                sub_menu()
                break
            else:
                print("Login Failed: Incorrect password")
                pw = input("Please re-enter your password > ")
    else:
        print("Login Failed: User not found")
        main_menu()


# This function deletes a user from the list.
# It first checks the existence of the user with the inserted username.
# If the user deletes the "logged on" user, he is redirected to the main menu ("Logged out").
def delete():
    global loggedUID
    usern = input("Write the username of the desired user > ")
    uid = get_uid(usern)
    if uid is None:
        print("User not found")
        sub_menu()
        return
    elif uid == loggedUID:
        user_list.pop(uid)
        print("User deleted successfully!")
        loggedUID = None
        main_menu()
        return
    else:
        user_list.pop(uid)
        print("User deleted successfully!")
        sub_menu()
        return


# This function edits a user in the list by deleting it and running the resignation function.
# It checks for the existence of the username in the list of users.
def edit():
    global loggedUID
    usern = input("Write the username of the desired user > ")
    uid = get_uid(usern)
    if uid is None:
        print("User not found")
    else:
        user_list.pop(uid)
        registration()
    sub_menu()


# This function resets the "loggedUID" variable, which indicates the "Logged" user.
def logout():
    global loggedUID
    loggedUID = None


# This function presents a secondary menu to a user after he has "logged in" to the system.
# It presents the active user, and if he is an "Admin".
# The "match-case" uses the previous functions to perform actions according to user input.
# "Deletion" and "Editing" of users are only allowed for Admins.
# Logging out of the system transfers the user to the main-menu.
def sub_menu():
    global loggedUID
    user = user_list[loggedUID]
    print(f"Logged in as: {user['username']} (Admin: {user['is_admin']})")
    print("1. Delete an existing user (Admin Only)")
    print("2. Edit an existing user (Admin Only)")
    print("3. Show all existing users")
    print("4. Logout")
    choice = int(input("Enter the number of your desired action > "))
    match choice:
        case 1:
            if user["is_admin"]:
                delete()
                sub_menu()
            else:
                print("Permission Denied - the logged user is not an Admin")
                sub_menu()
        case 2:
            if user["is_admin"]:
                edit()
                sub_menu()
            else:
                print("Permission Denied - the logged user is not an Admin")
                sub_menu()
        case 3:
            show_all()
            sub_menu()
        case 4:
            logout()
            main_menu()


# This function presents the main-menu to the user.
def main_menu():
    print("Welcome, please select your action:")
    print("1. Login to an existing user")
    print("2. Create a new user")
    print("3. Exit")
    choice = int(input("Enter the number of your desired action > "))
    match choice:
        case 1:
            login()
            sub_menu()
        case 2:
            registration()
            main_menu()
        case 3:
            exit(0)


main_menu()
