
import logging

# Save errors in a separate log file
logging.basicConfig(
    filename="application_errors.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def handle_error(error):
    # Store technical details internally
    logging.exception("Application error: %s", error)

    # Return a safe message to the user
    return {
        "success": False,
        "message": "Something went wrong. Please try again."
    }


def file_not_found():
    return {
        "success": False,
        "message": "File not found."
    }


def access_denied():
    return {
        "success": False,
        "message": "Access denied."
    }


def invalid_input():
    return {
        "success": False,
        "message": "Invalid input provided."
    }
