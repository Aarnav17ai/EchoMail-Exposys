# Mass-Mail Dispatcher

A simple web application that allows users to upload CSV files containing email addresses, validate them, and send mass emails to valid recipients.

## Features

- Upload CSV files with email addresses
- Validate email addresses automatically
- Display lists of valid and invalid emails
- Send mass emails to valid recipients
- Simple and intuitive user interface

## Setup Instructions

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Installation

1. Clone this repository or download the source code

2. Install the required packages:
   ```
   pip install flask python-dotenv sendgrid pandas
   ```

3. Create a `.env` file in the root directory with the following content:
   ```
   # SendGrid API Key - Get this from your SendGrid account
   SENDGRID_API_KEY=your_sendgrid_api_key_here

   # Email address to send from - Must be verified in SendGrid
   FROM_EMAIL=your_email@example.com
   ```

4. Replace `your_sendgrid_api_key_here` with your actual SendGrid API key and `your_email@example.com` with your verified sender email address.

### Running the Application

1. Start the application:
   ```
   python app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```

## Usage

1. **Upload CSV File**:
   - Click on "Choose CSV File" button
   - Select a CSV file containing email addresses
   - The CSV file should have a column with "email" in its name

2. **Validate Emails**:
   - Click the "Upload & Validate" button
   - The application will process the file and display valid and invalid emails

3. **Send Emails**:
   - Enter a subject and message for your email
   - Click the "Send Emails" button
   - The application will send emails to all valid recipients

## CSV File Format

The application expects a CSV file with at least one column containing email addresses. The column name should include the word "email" (case-insensitive).

Example CSV format:
```
name,email,age
John Doe,john@example.com,30
Jane Smith,jane@example.com,25
Invalid User,notanemail,40
```

## Technologies Used

- Frontend: HTML, CSS, JavaScript
- Backend: Python with Flask
- Email Service: SendGrid
- Data Processing: Pandas

## Project Structure

- `app.py`: Main Flask application
- `templates/index.html`: HTML template for the web interface
- `static/css/style.css`: CSS styles for the application
- `static/js/script.js`: JavaScript for client-side functionality
- `uploads/`: Directory for storing uploaded CSV files

## License

This project is open source and available under the [MIT License](LICENSE). 