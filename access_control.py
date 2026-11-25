
# ==========================================================
# SECURE FILE SHARING SYSTEM
# MODULE 2: AUTHORIZATION AND ACCESS CONTROL
# ==========================================================

# Registered users and their roles
users = {
    "admin": "Admin",
    "alice": "User",
    "bob": "User",
    "charlie": "User"
}

# Stores file ownership
file_owners = {}

# Stores permissions assigned to users
file_permissions = {}

# Available permissions
VALID_PERMISSIONS = ["Read", "Write", "Delete", "Share"]


# ----------------------------------------------------------
# FUNCTION 1: CHECK USER REGISTRATION
# ----------------------------------------------------------

def user_exists(username):
    return username in users


# ----------------------------------------------------------
# FUNCTION 2: CREATE A FILE
# Files are private by default
# ----------------------------------------------------------

def create_file(username, filename):

    if not user_exists(username):
        print("\nError: User is not registered.")
        return

    if filename in file_owners:
        print("\nError: File already exists.")
        return

    file_owners[filename] = username
    file_permissions[filename] = {}

    print("\nFile created successfully.")
    print("Owner:", username)
    print("Access: Private by default")


# ----------------------------------------------------------
# FUNCTION 3: CHECK PERMISSIONS
# ----------------------------------------------------------

def check_permission(username, filename, action):

    if not user_exists(username):
        return False

    if filename not in file_owners:
        return False

    if action not in VALID_PERMISSIONS:
        return False

    # Admin has administrative access
    if users[username] == "Admin":
        return True

    # Owner has full control over their file
    if file_owners[filename] == username:
        return True

    # Check permissions assigned to other users
    if username in file_permissions[filename]:

        if action in file_permissions[filename][username]:
            return True

    return False


# ----------------------------------------------------------
# FUNCTION 4: SHARE A FILE
# ----------------------------------------------------------

def share_file(owner, filename, receiver, selected_permissions):

    if not user_exists(owner):
        print("\nError: Owner is not registered.")
        return

    if filename not in file_owners:
        print("\nError: File does not exist.")
        return

    if file_owners[filename] != owner:
        print("\nError: Only the file owner can share this file.")
        return

    if not user_exists(receiver):
        print("\nError: Receiver is not registered.")
        return

    if owner == receiver:
        print("\nError: Cannot share a file with yourself.")
        return

    if not selected_permissions:
        print("\nError: Select at least one permission.")
        return

    for permission in selected_permissions:

        if permission not in VALID_PERMISSIONS:
            print("\nError: Invalid permission selected.")
            return

    file_permissions[filename][receiver] = list(set(selected_permissions))

    print("\nFile shared successfully!")
    print("Shared with:", receiver)
    print("Permissions:", file_permissions[filename][receiver])


# ----------------------------------------------------------
# FUNCTION 5: REVOKE ACCESS
# ----------------------------------------------------------

def revoke_access(owner, filename, receiver):

    if filename not in file_owners:
        print("\nError: File does not exist.")
        return

    if file_owners[filename] != owner:
        print("\nError: Only the owner can revoke access.")
        return

    if receiver in file_permissions[filename]:

        del file_permissions[filename][receiver]

        print("\nAccess revoked successfully.")

    else:
        print("\nThis user does not have access to the file.")


# ----------------------------------------------------------
# FUNCTION 6: PERFORM FILE OPERATION
# ----------------------------------------------------------

def perform_operation(username, filename, action):

    if check_permission(username, filename, action):

        print("\nAccess Granted!")
        print(username, "can perform", action, "on", filename)

    else:

        print("\nAccess Denied!")
        print("You do not have permission to perform this operation.")


# ----------------------------------------------------------
# FUNCTION 7: DISPLAY FILE ACCESS DETAILS
# ----------------------------------------------------------

def display_permissions(filename):

    if filename not in file_owners:
        print("\nError: File does not exist.")
        return

    print("\n========== FILE DETAILS ==========")

    print("File Name:", filename)
    print("Owner:", file_owners[filename])

    print("\nAssigned Permissions:")

    if not file_permissions[filename]:

        print("Private - No users have been given access.")

    else:

        for username, permissions in file_permissions[filename].items():

            print(username, ":", ", ".join(permissions))

    print("==================================")


# ----------------------------------------------------------
# FUNCTION 8: DISPLAY REGISTERED USERS
# ----------------------------------------------------------

def display_users():

    print("\n========== REGISTERED USERS ==========")

    for username, role in users.items():

        print("Username:", username, "| Role:", role)

    print("======================================")


# ----------------------------------------------------------
# MAIN MENU
# ----------------------------------------------------------

def main():

    while True:

        print("\n")
        print("========================================")
        print("       SECURE FILE SHARING SYSTEM")
        print("       AUTHORIZATION MODULE")
        print("========================================")

        print("1. Display Registered Users")
        print("2. Create File")
        print("3. Share File")
        print("4. Revoke File Access")
        print("5. Check File Permission")
        print("6. View File Permissions")
        print("7. Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":

            display_users()

        elif choice == "2":

            username = input("Enter username: ")
            filename = input("Enter file name: ")

            create_file(username, filename)

        elif choice == "3":

            owner = input("Enter owner username: ")
            filename = input("Enter file name: ")
            receiver = input("Enter receiver username: ")

            print("\nAvailable Permissions:")
            print("Read, Write, Delete, Share")

            selected = input("Enter permissions separated by commas: ")

            selected_permissions = [
                p.strip().capitalize()
                for p in selected.split(",")
                if p.strip()
            ]

            share_file(owner, filename, receiver, selected_permissions)

        elif choice == "4":

            owner = input("Enter owner username: ")
            filename = input("Enter file name: ")
            receiver = input("Enter username whose access should be revoked: ")

            revoke_access(owner, filename, receiver)

        elif choice == "5":

            username = input("Enter username: ")
            filename = input("Enter file name: ")
            action = input("Enter operation (Read/Write/Delete/Share): ").capitalize()

            perform_operation(username, filename, action)

        elif choice == "6":

            filename = input("Enter file name: ")

            display_permissions(filename)

        elif choice == "7":

            print("\nExiting Authorization Module.")
            break

        else:

            print("\nInvalid choice. Please try again.")


# Run the program
if __name__ == "__main__":
    main()
