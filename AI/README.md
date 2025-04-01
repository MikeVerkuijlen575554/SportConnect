# SportConnect

A Flask web application for managing sport events. This application allows you to add, edit, and delete sport events with details such as title, description, date, location, and maximum participants.

## Features

- View all sport events in a modern card layout
- Add new sport events
- Edit existing events
- Delete events
- Responsive design that works on all devices
- User-friendly interface with Bootstrap styling

## Prerequisites

- Python 3.8 or higher
- MySQL Server
- pip (Python package installer)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd sportconnect
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Unix or MacOS:
source venv/bin/activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Create a MySQL database named `sportconnect`:
```sql
CREATE DATABASE sportconnect;
```

5. Update the database configuration in `app.py`:
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/sportconnect'
```
Replace `username` and `password` with your MySQL credentials.

## Running the Application

1. Make sure your virtual environment is activated
2. Run the Flask application:
```bash
python app.py
```

3. Open your web browser and navigate to:
```
http://localhost:5000
```

## Usage

1. **View Events**: The home page displays all sport events in a card layout
2. **Add Event**: Click the "Add New Event" button to create a new sport event
3. **Edit Event**: Click the "Edit" button on any event card to modify its details
4. **Delete Event**: Click the "Delete" button on any event card to remove it

## Technologies Used

- Flask
- SQLAlchemy
- MySQL
- Bootstrap 5
- Bootstrap Icons

## License

This project is licensed under the MIT License - see the LICENSE file for details. 