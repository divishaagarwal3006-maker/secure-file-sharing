# Secure File Sharing

A Python web application for secure file sharing with user authentication, database management, and input validation.

## Project Structure
- `app.py` – Main application entry point
- `auth.py` – Authentication module
- `db.py` / `schema.sql` – Database setup and schema
- `validators.py` – Input and file validation
- `logger.py` – Application logging
- `templates/` – HTML templates
- `tests/` – Pytest test suite

## Setup & Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com
   cd secure-file-sharing
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   Create a `.env` file in the root folder with your required secret keys and database settings.

5. **Run the application**
   ```bash
   python app.py
   ```
