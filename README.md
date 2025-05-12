# Intern-Connect

**Intern-Connect** is a web-based internship coordination and assessment platform designed to foster seamless communication among students, lecturers, and workplace assessors. It provides structured tools for task assignments, progress evaluations, secure file sharing, and real-time notifications across all roles.

---

## 👨‍💻 Developed By

* **Valeria Jachi** – H230357W
* **Princess Shumba** – H230764F
* **Tirivashe Chitanda** – H230708Z
* **Stanley Kandembirira** – H230755W
* **Faith Runesu** – H230278R

---

## 📁 Folder Structure Overview

```
.
├── controllers/           # Express controller logic
├── db_backups/            # Periodic PostgreSQL backups
├── dist/                  # Compiled frontend assets
│   └── uploads/           # Uploaded files
├── middleware/            # Express middleware functions
├── node_modules/          # Dependencies
├── public/                # Static files & public uploads
│   └── uploads/
├── routes/                # API and authentication routes
├── src/
│   ├── assets/            # Icons, logos, and static assets
│   ├── components/        # All React components
│   │   ├── notifications/     # Notification tab UI
│   │   ├── profileCard/       # Profile card components
│   │   ├── Resources/         # Help & resources tab
│   │   ├── tasks/             # Task modal, feed, comments
│   │   └── users/             # User management components
│   └── utils/             # Shared frontend utilities
├── views/                 # EJS views for server-rendered pages
├── server.js              # Main Express server file
├── dbConfig.js            # PostgreSQL database configuration
├── passportConfig.js      # Passport strategy and serialization
├── main.jsx               # React application entry point
├── App.jsx                # Core React structure with routes
└── .env                   # Environment variables
```

---

## 🔐 Role-Based Capabilities

| Role         | Capabilities                                                                 |
| ------------ | ---------------------------------------------------------------------------- |
| **Intern**   | View assigned tasks, submit updates, comment, upload files, receive feedback |
| **Lecturer** | Monitor student progress, give feedback, manage academic evaluations         |
| **Assessor** | Assign and review tasks, group interns, post comments, view analytics        |
| **Admin**    | Create/manage users, review company submissions, monitor logs and backups    |

---

## 🚀 Key Features

* Real-time task assignment & comments via **WebSockets**
* OTP-secured password resets
* Structured user registration & dynamic forms
* Live intern activity indicators (Active/Offline)
* PDF generation of intern performance reports
* Company submission review workflow
* Admin-level database backup & user logs

---

## 🛠️ Setup Instructions

### Backend Setup

```bash
npm install
npm run dev
```

### Frontend Setup (Vite + React)

```bash
cd src/
npm install
npm run dev
```

Ensure `.env` files exist with:

```env
# Backend .env
DB_USER=...
DB_PASSWORD=...
SESSION_SECRET=...
FRONTEND_URL=http://localhost:5173

# Frontend .env
VITE_BACKEND_URL=http://localhost:4000
```

---

## 🧪 In Development

* PDF download of intern reports
* Admin analytics charts
* Lecturer-level feedback grading system
* Submission deadline reminders

---

> "Empowering internship success through digital clarity."
