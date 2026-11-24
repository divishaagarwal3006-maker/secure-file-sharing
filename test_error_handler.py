
from error_handler import (
    handle_error,
    file_not_found,
    access_denied,
    invalid_input
)

print("TESTING ERROR HANDLING")

# Test 1: General application error
try:
    raise ValueError("Database connection failed")
except Exception as e:
    print("Test 1:", handle_error(e))

# Test 2: File not found
print("Test 2:", file_not_found())

# Test 3: Unauthorized access
print("Test 3:", access_denied())

# Test 4: Invalid input
print("Test 4:", invalid_input())

print("\nError handling tests completed!")