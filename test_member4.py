
from validation import validate_filename, validate_file_id

print("Testing Member 4 Validation")

# Test 1: Valid filename
print("Test 1:", validate_filename("document.pdf"))

# Test 2: Empty filename
print("Test 2:", validate_filename(""))

# Test 3: Invalid filename
print("Test 3:", validate_filename("../secret.txt"))

# Test 4: Valid file ID
print("Test 4:", validate_file_id(10))

# Test 5: Invalid file ID
print("Test 5:", validate_file_id("abc"))
