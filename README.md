# Smart Complaint Management System

A full-stack web application for managing user complaints with user authentication, complaint submission, tracking, and admin panel for complaint management.

## Features

### 👥 User Features
- **User Registration & Authentication**: Secure registration with password hashing
- **User Dashboard**: View submitted complaints and their status
- **Submit Complaints**: Submit complaints with category, description, and optional image upload
- **Track Status**: Monitor complaint status (Pending, In Progress, Resolved)
- **Complaint History**: View all submitted complaints with filtering

### 🛡️ Admin Features
- **Admin Dashboard**: View all user complaints
- **Filter & Search**: Filter complaints by status and category, search by description
- **Status Management**: Update complaint status
- **Delete Complaints**: Remove complaints from the system
- **Statistics**: View complaint statistics and trends
- **Export Data**: Export complaints to CSV format

### 🔒 Security Features
- Password hashing using Werkzeug security
- SQL injection protection using parameterized queries
- File upload validation and security
- Session-based authentication
- Role-based access control (User/Admin)

## Tech Stack

- **Backend**: Python Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **Database**: SQLite
- **Authentication**: Werkzeug Security

## Project Structure

```
smart-complaint-system/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── database.db                 # SQLite database (auto-created)
├── README.md                   # This file
│
├── templates/                  # HTML templates
│   ├── base.html              # Base template with header/footer
│   ├── login.html             # User login page
│   ├── register.html          # User registration page
│   ├── dashboard.html         # User dashboard
│   ├── complaint_form.html    # Submit complaint form
│   ├── complaint_status.html  # View complaint status
│   ├── admin_login.html       # Admin login page
│   ├── admin_dashboard.html   # Admin dashboard
│   ├── 404.html              # 404 error page
│   └── 500.html              # 500 error page
│
├── static/                     # Static files
│   ├── css/
│   │   └── style.css          # Main stylesheet (minimalist design)
│   ├── js/
│   │   └── script.js          # JavaScript interactions
│   └── images/                # Static images folder
│
└── uploads/                    # Uploaded complaint images
```

## Installation & Setup

### 1. Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### 2. Install Dependencies

```bash
# Navigate to project directory
cd "d:\complaint system"

# Install required packages
pip install -r requirements.txt
```

### 3. Run the Application

```bash
# Start Flask development server
python app.py
```

The application will start at `http://localhost:5000`

## Default Admin Credentials

- **Email**: `admin@example.com`
- **Password**: `admin123`

⚠️ **Important**: Change these credentials in production!

## User Flows

### User Registration & Login
1. Go to `http://localhost:5000`
2. Click "Register" to create a new account
3. Fill in name, email, and password
4. Use the same credentials to login

### Submit a Complaint
1. Login in as a user
2. Click "Submit Complaint" from dashboard
3. Select category and write description
4. (Optional) Upload an image
5. Submit the complaint
6. Track status in your dashboard

### Admin Dashboard
1. Go to `http://localhost:5000/admin/login`
2. Login with admin credentials
3. View all complaints in a table
4. Use filters to search and sort complaints
5. Click "View" to see complaint details
6. Click "Update" to change complaint status
7. Click "Delete" to remove complaints
8. Export data to CSV or print

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Complaints Table
```sql
CREATE TABLE complaints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    image_path TEXT,
    status TEXT DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## API Routes

### User Routes
- `GET /` - Home page (redirects to dashboard or login)
- `GET /login` - User login page
- `POST /login` - User login (form submission)
- `GET /register` - User registration page
- `POST /register` - User registration (form submission)
- `GET /dashboard` - User dashboard (requires login)
- `GET /submit_complaint` - Submit complaint form (requires login)
- `POST /submit_complaint` - Submit complaint (requires login)
- `GET /complaint/<id>` - View complaint status (requires login)
- `GET /logout` - Logout

### Admin Routes
- `GET /admin/login` - Admin login page
- `POST /admin/login` - Admin login (form submission)
- `GET /admin/dashboard` - Admin dashboard (requires admin login)
- `POST /update_status/<id>` - Update complaint status (requires admin)
- `POST /delete_complaint/<id>` - Delete complaint (requires admin)

## UI Design

### Color Scheme
- **Primary**: Black (#000000)
- **Secondary**: White (#FFFFFF)
- **Accent**: Grey (#666666)
- **Success**: Green (#28a745)
- **Warning**: Yellow (#ffc107)
- **Danger**: Red (#dc3545)
- **Info**: Cyan (#17a2b8)

### Design Features
- Minimalist modern interface
- Card-based layout
- Responsive design (mobile, tablet, desktop)
- Hover effects and smooth animations
- Clear typography and spacing
- Status badges with color coding

## Features in Detail

### Complaint Categories
- Product Quality
- Service Issue
- Billing
- Delivery
- Customer Service
- Technical Issue
- Other

### Complaint Status
- **Pending**: Complaint received, awaiting review
- **In Progress**: Complaint is being investigated
- **Resolved**: Complaint has been resolved

### Statistics Dashboard
- Total complaints count
- Pending complaints count
- In-progress complaints count
- Resolved complaints count

### Search & Filter
- Search complaints by description, user name, or email
- Filter by status (Pending, In Progress, Resolved)
- Filter by category
- Combine multiple filters

## File Upload

- **Allowed formats**: PNG, JPG, JPEG, GIF
- **Maximum file size**: 16 MB
- **Storage location**: `/uploads/` folder
- **Files are automatically validated** before upload

## Error Handling

- 404 Page Not Found - Custom error page
- 500 Server Error - Custom error page
- Form validation with user-friendly messages
- Flash messages for all operations

## Security Best Practices

1. **Password Security**: Uses Werkzeug `generate_password_hash()` and `check_password_hash()`
2. **SQL Injection Prevention**: All queries use parameterized queries
3. **File Upload Security**: File extension validation and secure filename handling
4. **Session Management**: Flask session middleware
5. **CSRF Protection**: Form handling with proper POST methods

## Troubleshooting

### Port 5000 Already in Use
```bash
# Change port in app.py
# Modify: app.run(debug=True, host='0.0.0.0', port=8000)
python app.py
```

### Database Errors
```bash
# Delete database and restart (will recreate)
del database.db
python app.py
```

### Import Errors
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

## Future Enhancements

- Email notifications for complaint status updates
- Complaint assignment to support staff
- Comment history on complaints
- User profile management
- Admin user management
- Multiple file uploads per complaint
- Complaint analytics and reporting
- User feedback ratings
- Real-time notifications with WebSocket
- Mobile app (React Native/Flutter)
- Integration with external service APIs

## License

This project is open source and available for educational purposes.

## Support

For issues or questions, please check the code comments or contact the development team.

---

**Created**: March 2024
**Version**: 1.0.0
**Status**: Production Ready ✅
