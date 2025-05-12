const http = require('http');
const { Server } = require('socket.io');
const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const { pool } = require('./dbConfig');
const initializePassport = require('./passportConfig');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const pgSession = require('connect-pg-simple')(session);



const app = express();
const port = process.env.PORT || 4000;

// CORS Configuration (must be before routes)
app.use(cors({
    origin: process.env.FRONTEND_URL || "http://localhost:5173",
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true
}));
app.options('*', cors());

// Body parser and static files
app.use(express.urlencoded({ extended: false }));
app.use(express.json()); // ✅ This line is required for JSON payloads
app.use(express.static(path.join(__dirname, 'public')));


// Initialize Passport
initializePassport(passport);

// EJS View Engine
app.set("view engine", "ejs");

// Session configuration
// ✅ Define once, reuse for both Express and Socket.IO
const sessionMiddleware = session({
    store: new pgSession({
        pool: pool,
        tableName: 'session'
    }),
    secret: process.env.SESSION_SECRET || 'verysecretvalue',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
});

app.use(sessionMiddleware);




app.use(flash());

// OPTIONAL: make flash messages accessible to templates
app.use((req, res, next) => {
    res.locals.error = req.flash('error');
    res.locals.success = req.flash('success');
    next();
});
// Middleware

app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
    console.log("SESSION USER:", req.session.userId);
    console.log("REQ.USER:", req.user);
    console.log("MANAGEMENT USER:", req.session.managementUser); // ✅ add this
    next();
});

const otpRoutes = require('./routes/otp');
app.use('/api', otpRoutes);
app.use("/api/tasks", require("./routes/tasks"));

const notificationRoutes = require('./routes/notifications');
app.use('/api/notifications', notificationRoutes);


const linkRoutes = require('./routes/linkRequests'); // ✅ make sure this is present
app.use('/api/links', linkRoutes); // ✅ this enables /api/links/lecturer

app.use("/api/links", require("./routes/linkRequests")); // ✅ enables /api/links/accept

app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
    next();
});
app.use((req, res, next) => {
    res.locals.message = req.session.message || null;
    res.locals.messageType = req.session.messageType || null;
    delete req.session.message;
    delete req.session.messageType;
    next();
});

// Multer file upload
const storage = multer.diskStorage({
    destination: './public/uploads/',
    filename: (req, file, cb) => {
        if (!req.session.userId) return cb(new Error("User not authenticated"));
        cb(null, `${req.session.userId}-${Date.now()}${path.extname(file.originalname)}`);
    }
});
const upload = multer({ storage: storage });



// Routes
app.get('/', (req, res) => {
    res.render("index");
});

app.get("/api/interns/unlinked", async (req, res) => {
    if (!req.user || req.user.role !== "Internship Assessor") {
        return res.status(403).json({ message: "Unauthorized" });
    }

    try {
        // 1. Get all interns at same workplace
        const { rows: interns } = await pool.query(`
            SELECT u.id, u.username, u.email, u.avatar_url
            FROM users u
            WHERE u.role = 'Intern'
              AND u.workplace_id = (
                SELECT workplace_id FROM users WHERE id = $1
              )
              AND u.id NOT IN (
                SELECT intern_id FROM assessor_intern_links WHERE assessor_id = $1
              )
        `, [req.user.id]);

        res.json(interns);
    } catch (err) {
        console.error("❌ Failed to fetch unlinked interns:", err);
        res.status(500).json({ error: "Server error" });
    }
});


const commentRoutes = require("./routes/comments");
const taskRoutes = require('./routes/tasks');


// ...other middlewares

// In server.js
const managementRoutes = require('./routes/management');
app.use('/api/management', managementRoutes);
app.use("/contact", require("./routes/contact"));


app.use('/api/tasks', taskRoutes);
app.use('/api/tasks', commentRoutes); // matches /:taskId/comments
const reviewRoutes = require('./routes/review');
app.use("/api", reviewRoutes);  // So /api/review/:internId works


app.get('/api/tasks/:id/comments', async (req, res) => {
    const { id } = req.params;
    try {
        const { rows } = await pool.query(
            'SELECT c.id, c.content, c.created_at, u.username, u.avatar_url FROM task_comments c JOIN users u ON c.user_id = u.id WHERE c.task_id = $1 ORDER BY c.created_at ASC',
            [id]
        );
        res.json(rows);
    } catch (err) {
        console.error("🔥 Failed to fetch comments:", err);
        res.status(500).send("Failed to fetch comments");
    }
});

app.get("/api/interns/sent", async (req, res) => {
    if (!req.user || req.user.role !== "Internship Assessor") {
        return res.status(403).json({ error: "Unauthorized" });
    }

    try {
        const result = await pool.query(`
            SELECT u.id, u.username, u.email, u.avatar_url
            FROM link_requests lr
            JOIN users u ON u.id = lr.intern_id
            WHERE lr.assessor_id = $1 AND lr.status = 'pending'
        `, [req.user.id]);

        res.json(result.rows);
    } catch (err) {
        console.error("❌ Error fetching sent requests:", err);
        res.status(500).json({ error: "Server error" });
    }
});

app.post("/api/link-requests/cancel", async (req, res) => {
    const { internId } = req.body;
    const assessorId = req.user.id;

    try {
        const result = await pool.query(`
            UPDATE link_requests
            SET status = 'cancelled'
            WHERE assessor_id = $1 AND intern_id = $2 AND status = 'pending'
        `, [assessorId, internId]);

        if (result.rowCount > 0) {
            return res.json({ success: true });
        } else {
            return res.status(404).json({ error: "Request not found or already processed" });
        }
    } catch (err) {
        console.error("Cancel request error:", err);
        res.status(500).json({ error: "Internal error" });
    }
});



//Otp
app.post("/api/otp/validate", async (req, res) => {
    const { code } = req.body;
    try {
        const result = await pool.query(
            "SELECT * FROM otp_codes WHERE code = $1 AND is_valid = true ORDER BY created_at DESC LIMIT 1",
            [code]
        );
        if (result.rows.length === 0) {
            return res.json({ valid: false });
        }

        // invalidate the OTP
        await pool.query("UPDATE otp_codes SET is_valid = false WHERE id = $1", [result.rows[0].id]);

        res.json({ valid: true });
    } catch (err) {
        console.error("OTP validation failed:", err);
        res.status(500).json({ error: "Server error" });
    }
});

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

app.post("/api/management/generate-otp", async (req, res) => {
    try {
        const code = generateOtp();
        const result = await pool.query(
            "INSERT INTO otp_codes (code, is_valid) VALUES ($1, true) RETURNING *",
            [code]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error("Error generating OTP:", err);
        res.status(500).json({ error: "Server error" });
    }
});

app.get("/api/management/otp-codes", async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM otp_codes ORDER BY created_at DESC LIMIT 20");
        res.json(result.rows);
    } catch (err) {
        console.error("Error fetching OTPs:", err);
        res.status(500).json({ error: "Server error" });
    }
});

setInterval(async () => {
    try {
        await pool.query(`
      DELETE FROM otp_codes WHERE created_at < NOW() - INTERVAL '10 minutes'
    `);
        console.log("Expired OTP codes cleaned.");
    } catch (err) {
        console.error("Failed to clean expired OTPs:", err);
    }
}, 10 * 60 * 1000); // every 10 minutes

//Unlink

app.post("/api/links/unlink-assessor", async (req, res) => {
    const { internId } = req.body;
    const assessorId = req.user?.id;

    if (!assessorId || !internId) {
        return res.status(400).json({ success: false, error: "Missing assessor or intern ID" });
    }

    try {
        const result = await pool.query(
            `DELETE FROM assessor_intern_links 
             WHERE assessor_id = $1 AND intern_id = $2`,
            [assessorId, internId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, error: "Link not found" });
        }

        return res.json({ success: true, message: "Intern unlinked successfully" });
    } catch (error) {
        console.error("Error unlinking intern:", error);
        return res.status(500).json({ success: false, error: "Server error" });
    }
});


//Change Password
// POST /api/users/update-password
app.post('/api/users/update-password', async (req, res) => {
    const { otp, newPassword } = req.body;
    const userId = req.user?.id;

    if (!userId) return res.status(401).json({ error: "Unauthorized" });

    try {
        const { rows } = await pool.query(
            'SELECT * FROM otp_codes WHERE code = $1 AND is_valid = true AND created_at > NOW() - INTERVAL \'10 minutes\'',
            [otp]
        );

        if (rows.length === 0) {
            return res.status(400).json({ error: "Invalid or expired OTP" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);
        await pool.query('UPDATE otp_codes SET is_valid = false WHERE code = $1', [otp]);

        res.json({ success: true });
    } catch (err) {
        console.error("Password update error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.get("/api/links/intern-linked-lecturers", async (req, res) => {
    const internId = req.user?.id;
    if (!internId) return res.status(401).json({ error: "Not authenticated" });

    try {
        const result = await pool.query(`
            SELECT u.id, u.username, u.email, u.avatar_url, u.job_title
            FROM lecturer_intern_links l
            JOIN users u ON u.id = l.lecturer_id
            WHERE l.intern_id = $1
        `, [internId]);

        res.json(result.rows);
    } catch (error) {
        console.error("Error fetching linked lecturers:", error);
        res.status(500).json({ error: "Server error" });
    }
});



app.post("/api/user/change-password", async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const userId = req.user?.id;

    if (!userId) {
        return res.status(401).json({ error: "Not authenticated." });
    }

    if (!newPassword || newPassword !== confirmPassword) {
        return res.status(400).json({ error: "Passwords do not match." });
    }

    try {
        // Fetch the user's current password hash
        const userRes = await pool.query("SELECT password FROM users WHERE id = $1", [userId]);
        const user = userRes.rows[0];
        if (!user) return res.status(404).json({ error: "User not found." });

        // OPTIONAL: Verify current password if you're using it
        if (currentPassword) {
            const match = await bcrypt.compare(currentPassword, user.password);
            if (!match) return res.status(403).json({ error: "Current password is incorrect." });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashed = await bcrypt.hash(newPassword, salt);

        // Update password
        await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashed, userId]);

        res.json({ message: "Password updated successfully." });
    } catch (err) {
        console.error("Password update failed:", err);
        res.status(500).json({ error: "Server error." });
    }
});

/*
app.get("/api/tasks/intern", async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    if (req.user.role !== "Intern") {
        return res.status(403).json({ error: "Forbidden: Access is restricted to Interns only" });
    }

    const userId = req.user.id;

    try {
        const internWorkplaceRes = await pool.query(`SELECT workplace_id FROM users WHERE id = $1`, [userId]);
        const internWorkplace = internWorkplaceRes.rows[0]?.workplace_id;

        const result = await pool.query(`
            SELECT
                t.id, t.title, t.description, t.due_date, t.status, t.color,
                t.created_at, t.created_by, t.assignee_id, t.assigned_to,
                a.username AS assessor_name,
                i.username AS assignee_name,
                i.avatar_url AS intern_avatar,
                CASE
                    WHEN t.status = 'Completed' THEN 'Completed'
                    WHEN t.due_date < NOW() THEN 'Missing'
                    ELSE 'Pending'
                    END AS computed_status
            FROM tasks t
                     JOIN users a ON t.created_by = a.id
                     JOIN users i ON t.assigned_to = i.id
            WHERE t.assigned_to = $1
              AND a.workplace_id = $2
              AND EXISTS (
                SELECT 1 FROM assessor_intern_links
                WHERE intern_id = $1 AND assessor_id = t.created_by
            )
            ORDER BY t.created_at DESC
        `, [userId, internWorkplace]);


        console.log("👤 Intern ID:", userId);
        console.log("🏢 Workplace ID:", internWorkplace);
        console.log("✅ Tasks found:", result.rows.length);

        res.json(result.rows);
    } catch (err) {
        console.error("🔴 Error fetching intern tasks:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
*/


// GET /api/tasks - Fetch tasks for assessor (based on workplace)
app.get("/api/tasks", async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    if (req.user.role !== "Internship Assessor") {
        return res.status(403).json({ error: "Forbidden: Only assessors can access this route" });
    }

    try {
        const assessorQuery = await pool.query(
            `SELECT workplace_id FROM users WHERE id = $1 AND role = 'Internship Assessor'`,
            [req.user.id]
        );

        const assessor = assessorQuery.rows[0];
        if (!assessor || !assessor.workplace_id) {
            return res.status(403).json({ error: "No workplace assigned to assessor" });
        }

        const taskResult = await pool.query(
            `SELECT t.*, u.username AS assignee_name
             FROM tasks t
                      JOIN users u ON t.assignee_id = u.id
             WHERE t.created_by = $1 AND t.workplace_id = $2
             ORDER BY t.created_at DESC`,
            [req.user.id, assessor.workplace_id]
        );

        res.json(taskResult.rows);
    } catch (err) {
        console.error("❌ Error fetching tasks for assessor:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.get('/users/register', isNotAuthenticated, async (req, res) => {
    try {
        const companies = await pool.query('SELECT id, name FROM companies ORDER BY name ASC');
        const universities = await pool.query('SELECT id, name FROM universities ORDER BY name ASC');
        const departments = await pool.query('SELECT id, name FROM departments ORDER BY name ASC');
        const programs = await pool.query('SELECT id, name FROM programs ORDER BY name ASC');

        res.render("register", {
            errors: [],
            companies: companies.rows,
            universities: universities.rows,
            departments: departments.rows,
            programs: programs.rows
        });
    } catch (err) {
        console.error("Error loading registration page:", err);
        res.status(500).send("Server Error");
    }
});

app.post("/api/management/company-applications", async (req, res) => {
    const internId = req.user?.id;
    const role = req.user?.role;

    // Only allow interns to submit
    if (!internId || role !== "Intern") {
        return res.status(403).json({ success: false, error: "Unauthorized request" });
    }

    const {
        companyName,
        companyAddress,
        industryType,
        supervisorName,
        supervisorEmail,
        companyWebsite
    } = req.body;

    try {
        await pool.query(
            `INSERT INTO company_applications (
                intern_id,
                company_name,
                company_address,
                industry,
                supervisor_name,
                supervisor_email,
                website
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [
                internId,
                companyName,
                companyAddress,
                industryType,
                supervisorName || null,
                supervisorEmail || null,
                companyWebsite || null
            ]
        );

        res.json({ success: true, message: "Company info submitted for review." });
    } catch (err) {
        console.error("❌ Failed to submit company application:", err);
        res.status(500).json({ success: false, error: "Server error. Try again later." });
    }
});


app.get('/users/login', isNotAuthenticated, (req, res) => {
    res.render("login", { errors: [], message: res.locals.message, messageType: res.locals.messageType });
});

app.get('/users/dashboard', isAuthenticated, async (req, res) => {
    try {
        const userQuery = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
        if (!userQuery.rows.length) return res.redirect('/users/login');

        const user = userQuery.rows[0];
        const avatar = user.avatar_url ? `/uploads/${user.avatar_url}` : `/uploads/default-avatar.png`;

        let universities = [], companies = [], departments = [], programs = [];

        try {
            universities = (await pool.query('SELECT * FROM universities')).rows;
            companies = (await pool.query('SELECT * FROM companies')).rows;

            if (user.university_id) {
                departments = (await pool.query('SELECT * FROM departments WHERE university_id = $1', [user.university_id])).rows;
                programs = (await pool.query('SELECT * FROM programs WHERE department_id = $1', [user.department_id])).rows;
            }
        } catch (err) {
            console.error("Error fetching additional data:", err);
        }

        const profileUpdated = user.university_id && user.department_id && user.program_id && user.workplace_id;

        switch (user.role) {
            case "Lecturer":
                return res.render("dashboardL", { user, avatar, universities, companies, departments, programs, profileUpdated });
            case "Internship Assessor":
                return res.render("dashboardA", { user, avatar, universities, companies, departments, programs, profileUpdated });
            default:
                return res.render("dashboard", { user, avatar, universities, companies, departments, programs, profileUpdated });
        }
    } catch (err) {
        console.error("❌ Error processing the dashboard:", err);
        res.status(500).send("Internal Server Error");
    }
});

app.post('/users/upload-avatar', isAuthenticated, upload.single('avatar'), async (req, res) => {
    if (!req.file) {
        req.session.message = "⚠️ Please select an image!";
        req.session.messageType = "error";
        return res.redirect('/users/dashboard');
    }

    try {
        const avatarPath = req.file.filename;
        await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2', [avatarPath, req.user.id]);
        req.session.message = "✅ Avatar updated successfully!";
        req.session.messageType = "success";
        res.redirect('/users/dashboard');
    } catch (error) {
        console.error("❌ Error updating avatar:", error);
        res.status(500).json({ message: "Internal Server Error", error });
    }
});

app.post("/users/connect", isAuthenticated, async (req, res) => {
    try {
        const userId = req.user.id;
        const role = req.user.role;

        // 1. Set user as active
        await pool.query("UPDATE users SET is_active = TRUE WHERE id = $1", [userId]);

        // 2. Emit real-time update to all connected clients
        io.emit("user-status-changed", { userId, is_active: true });

        // 3. Handle JSON (fetch) vs browser requests
        const isFetch = req.headers.accept?.includes("application/json");
        if (isFetch) {
            return res.json({ success: true });
        }

        // ✅ 4. Map role to frontend route
        const redirectUrl = process.env.FRONTEND_URL || "http://localhost:5173";
        const roleRedirectMap = {
            "intern": "intern",
            "lecturer": "lecturer",
            "internship assessor": "assessor"  // 👈 match your frontend route
        };
        const roleKey = role?.toLowerCase();
        const rolePath = roleRedirectMap[roleKey] || "intern";

        return res.redirect(`${redirectUrl}/${rolePath}`);

    } catch (err) {
        console.error("❌ Failed to update is_active:", err);
        return res.status(500).json({ error: "Failed to connect." });
    }
});


app.post('/api/users/activity', async (req, res) => {
    const { userId, isActive } = req.body;

    if (!userId) return res.status(400).json({ error: "Missing user ID" });

    try {
        await pool.query(
            'UPDATE users SET is_active = $1 WHERE id = $2',
            [isActive, userId]
        );

        // ✅ Emit real-time status change
        io.emit("user-status-changed", { userId, is_active: isActive });

        res.json({ success: true });
    } catch (err) {
        console.error("❌ Failed to update activity:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});



app.get('/users/logout', (req, res, next) => {
    const userId = req.user?.id;
    if (userId) {
        pool.query("UPDATE users SET is_active = FALSE WHERE id = $1", [userId])
            .then(() => {
                req.logout(err => {
                    if (err) return next(err);
                    req.session.destroy(err => {
                        if (err) return next(err);
                        res.clearCookie('connect.sid');
                        res.redirect("/users/login");
                    });
                });
            })
            .catch(err => {
                console.error("❌ Error updating is_active on logout:", err);
                res.redirect("/users/login");
            });
    } else {
        req.logout(err => {
            if (err) return next(err);
            req.session.destroy(err => {
                if (err) return next(err);
                res.clearCookie('connect.sid');
                res.redirect("/users/login");
            });
        });
    }
});


app.get('/api/user', isAuthenticated, async (req, res) => {
    try {
        const userQuery = await pool.query(
            'SELECT id, username, avatar_url, workplace_id FROM users WHERE id = $1',
            [req.user.id]
        );

        if (userQuery.rows.length > 0) {
            res.json(userQuery.rows[0]); // includes `id`
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (err) {
        console.error("Error fetching user data:", err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.get('/sec/management', isNotAuthenticated, (req, res) => {
    res.render('management', { title: "Management Login" });
});


app.post('/sec/management/authenticate', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM management WHERE email = $1', [email]);

        if (result.rows.length === 0) {
            req.flash('error', 'Invalid credentials.');
            return res.redirect('/sec/management');
        }

        const admin = result.rows[0];
        console.log("Entered password:", password);
        console.log("Hashed in DB:", admin.password);
        const isMatch = await bcrypt.compare(password, admin.password);
        console.log("✅ Password match:", isMatch);


        if (!isMatch) {
            req.flash('error', 'Invalid credentials.');
            return res.redirect('/sec/management');
        }

        req.session.managementUser = {
            id: admin.id,
            email: admin.email,
            role: admin.role
        };

        await pool.query('UPDATE management SET last_login = NOW() WHERE id = $1', [admin.id]);
        console.log("🧠 Session before saving:", req.session);

        req.session.save(err => {
            if (err) {
                req.flash('error', 'Session error. Try again.');
                return res.redirect('/sec/management');
            }

            return res.redirect('http://192.168.137.1:5173/sec/management/dashboard');
        });



    } catch (err) {
        console.error(err);
        req.flash('error', 'Something went wrong.');
        res.redirect('/sec/management');
    }
});

app.get('/api/management/me', async (req, res) => {
    if (req.session && req.session.managementUser) {
        try {
            // Fetch logged-in admin’s full data if needed
            const adminUser = req.session.managementUser;

            // Fetch all users
            const allUsersQuery = `
                SELECT users.*, universities.name AS university_name
                FROM users
                LEFT JOIN universities ON users.university_id = universities.id
                ORDER BY users.id ASC
            `;
            const allUsersResult = await pool.query(allUsersQuery);

            return res.json({
                ...adminUser,
                allUsers: allUsersResult.rows
            });
        } catch (err) {
            console.error("Failed to fetch all users:", err);
            return res.status(500).json({ error: "Failed to load user data" });
        }
    }

    res.status(401).json({ error: 'Unauthorized' });
});


app.get('/sec/management/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Logout error:", err);
            return res.redirect('/sec/management/dashboard');
        }
        res.clearCookie('connect.sid');
        res.redirect('/sec/management');
    });
});

app.put('/api/management/toggle-active/:id', async (req, res) => {
    try {
        const userId = req.params.id;
        const result = await pool.query("UPDATE users SET is_active = NOT is_active WHERE id = $1 RETURNING *", [userId]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error("Toggle active failed:", err);
        res.status(500).json({ error: "Failed to toggle active status" });
    }
});

app.delete("/api/management/delete-user/:id", async (req, res) => {
    const { password } = req.body;
    const adminId = req.session?.managementUser?.id;
    const adminEmail = req.session?.managementUser?.email;

    if (!adminId || !password) {
        return res.status(400).json({ success: false, error: "Missing credentials." });
    }

    try {
        // Validate admin password from management table
        const result = await pool.query("SELECT password FROM management WHERE id = $1", [adminId]);
        const hashed = result.rows[0]?.password;

        if (!hashed || !bcrypt.compareSync(password, hashed)) {
            return res.status(403).json({ success: false, error: "Incorrect password." });
        }

        // Soft-delete the user (flag instead of delete)
        await pool.query("UPDATE users SET is_deleted = TRUE WHERE id = $1", [req.params.id]);

        // Log the deletion in system_logs using admin_id
        await pool.query(
            `INSERT INTO system_logs (admin_id, action, log_level, details)
             VALUES ($1, $2, $3, $4)`,
            [
                adminId,
                "delete_user",
                "warning",
                `Soft-deleted user ID ${req.params.id} by admin (${adminEmail})`
            ]
        );

        return res.json({ success: true });
    } catch (err) {
        console.error("❌ Delete user error:", err.stack || err.message);
        return res.status(500).json({ success: false, error: "Internal server error." });
    }
});


app.put("/api/management/logs/:id/investigate", async (req, res) => {
    const logId = req.params.id;

    if (!logId) {
        return res.status(400).json({ success: false, error: "Missing log ID." });
    }

    try {
        const result = await pool.query(
            "UPDATE system_logs SET investigated = TRUE WHERE id = $1 RETURNING id",
            [logId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, error: "Log not found." });
        }

        return res.json({ success: true });
    } catch (err) {
        console.error("❌ Failed to mark log as investigated:", err.stack || err.message);
        return res.status(500).json({ success: false, error: "Internal Server Error" });
    }
});

app.get("/api/management/logs", async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM system_logs ORDER BY created_at DESC LIMIT 100");
        res.json(result.rows);
    } catch (err) {
        console.error("❌ Failed to fetch logs:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// POST /api/management/update-workplace
app.post("/api/management/update-workplace", async (req, res) => {
    const {
        internId,
        companyName,
        companyAddress,
        industryType,
        companyWebsite,
        supervisorName,
        supervisorEmail
    } = req.body;

    if (!internId || !companyName || !companyAddress || !industryType) {
        return res.status(400).json({ success: false, error: "Missing required fields." });
    }

    try {
        // 1. Insert company application into 'company_applications' table
        await pool.query(
            `INSERT INTO company_applications (
                intern_id,
                company_name,
                company_address,
                industry,
                website,
                supervisor_name,
                supervisor_email,
                submitted_at,
                reviewed,
                approved
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), FALSE, FALSE)`,
            [
                internId,
                companyName,
                companyAddress,
                industryType,
                companyWebsite,
                supervisorName,
                supervisorEmail
            ]
        );

        // 2. Log system activity
        await pool.query(
            `INSERT INTO system_logs (action, log_level, details, created_at)
             VALUES ($1, $2, $3, NOW())`,
            [
                "submit_company_application",
                "info",
                `Intern ${internId} submitted workplace application for '${companyName}'`
            ]
        );

        res.json({ success: true, message: "✅ Company application submitted." });
    } catch (err) {
        console.error("❌ Error submitting company application:", err);
        res.status(500).json({ success: false, error: "Server error." });
    }
});

// server.js or routes/management.js

// server.js or routes/management.js

app.get("/api/management/company-applications", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                ca.id,
                ca.intern_id,
                u.email AS intern_email,
                ca.company_name,
                ca.company_address,
                ca.industry,
                ca.website,
                ca.supervisor_name,
                ca.supervisor_email,
                ca.reviewed,
                ca.approved,
                ca.reviewed_by,
                ca.submitted_at
            FROM company_applications ca
                     JOIN users u ON ca.intern_id = u.id
            ORDER BY ca.submitted_at DESC
        `);

        res.json(result.rows);
    } catch (err) {
        console.error("❌ Error fetching company applications:", err);
        res.status(500).json({ error: "Failed to fetch company applications." });
    }
});


// POST /api/management/companies/create
// POST /api/management/approve-company/:applicationId
app.post("/api/management/approve-company/:applicationId", upload.single("logo"), async (req, res) => {
    const appId = req.params.applicationId;

    try {
        // 1. Fetch application info
        const { rows } = await pool.query("SELECT * FROM company_applications WHERE id = $1", [appId]);
        if (rows.length === 0) return res.status(404).json({ success: false, error: "Application not found" });

        const app = rows[0];
        const logoUrl = req.file ? `/uploads/company_logos/${req.file.filename}` : null;

        // 2. Insert into companies table
        const insert = await pool.query(
            `INSERT INTO companies (name, industry, location, website, logo_url, verified, added_by_user_id)
       VALUES ($1, $2, $3, $4, $5, true, $6) RETURNING id`,
            [app.company_name, app.industry, app.company_address, app.website, logoUrl, app.reviewed_by || 1]
        );

        const companyId = insert.rows[0].id;

        // 3. Update intern's workplace_id
        await pool.query(`UPDATE users SET workplace_id = $1 WHERE id = $2`, [companyId, app.intern_id]);

        // 4. Update application status
        await pool.query(
            `UPDATE company_applications SET reviewed = true, approved = true, reviewed_by = $1 WHERE id = $2`,
            [app.reviewed_by || 1, appId]
        );

        // 5. Log action
        await pool.query(
            `INSERT INTO system_logs (action, log_level, details, created_at)
             VALUES ('approve_company', 'info', $1, NOW())`,
            [`Approved company '${app.company_name}' from application ID ${appId}`]
        );

        res.json({ success: true, companyId });
    } catch (err) {
        console.error("❌ Company approval failed:", err);
        res.status(500).json({ success: false, error: "Internal server error" });
    }
});


app.post("/api/management/create-user", async (req, res) => {
    const { email, username, role } = req.body;
    try {
        const result = await pool.query(
            "INSERT INTO users (email, username, role, password) VALUES ($1, $2, $3, $4) RETURNING *",
            [email, username, role, "default_password"]
        );
        res.json(result.rows[0]);
    } catch (err) {
        console.error("Create user error:", err);
        res.status(500).json({ error: "Server error" });
    }
});

app.get("/api/management/stats", async (req, res) => {
    try {
        const usersRes = await pool.query("SELECT COUNT(*) FROM users");
        const logsRes = await pool.query("SELECT COUNT(*) FROM system_logs"); // or adjust table name
        const dbConnections = 5; // mock or real value
        const accessRules = 3; // mock or real value

        res.json({
            users: parseInt(usersRes.rows[0].count),
            logs: parseInt(logsRes.rows[0]?.count || 0),
            dbConnections,
            accessRules,
        });
    } catch (err) {
        console.error("Error fetching stats:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.get("/api/management/stats", async (req, res) => {
    try {
        const usersResult = await pool.query("SELECT COUNT(*) FROM users");
        const logsResult = await pool.query("SELECT COUNT(*) FROM system_logs"); // Adjust table name if needed

        const stats = {
            users: parseInt(usersResult.rows[0].count),
            logs: parseInt(logsResult.rows[0]?.count || 0),
            dbConnections: 5, // static or dynamic if tracked
            accessRules: 3     // adjust as needed
        };

        res.json(stats);
    } catch (err) {
        console.error("🔥 Error in /api/management/stats:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});



app.post('/users/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.render('login', { errors: [{ message: info?.message || "Invalid credentials" }] });
        req.logIn(user, err => {
            if (err) return next(err);
            req.session.userId = user.id;
            return res.redirect("/users/dashboard");
        });
    })(req, res, next);
});

app.post('/users/register', async (req, res) => {
    let {
        username,
        email,
        password,
        role,
        workplace,
        other,
        university,
        department,
        program,
        phone,
        emergencyContact
    } = req.body;

    let errors = [];

    if (!username || !email || !password || !role) {
        errors.push({ message: "⚠️ Please fill in all fields!" });
    }

    if (password.length < 6) {
        errors.push({ message: "⚠️ Password must be at least 6 characters!" });
    }

    if (errors.length > 0) {
        return res.render('register', { errors });
    }

    try {
        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length) {
            errors.push({ message: "⚠️ Email already registered!" });
            return res.render('register', { errors });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert into users with full info
        const insertQuery = `
            INSERT INTO users 
            (username, email, password, role, avatar_url, workplace_id, university_id, department_id, program_id, phone, emergency_contact, job_title)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id
        `;

        const result = await pool.query(insertQuery, [
            username,
            email,
            hashedPassword,
            role,
            'default-avatar.png',
            workplace && workplace !== 'other' ? workplace : null,
            university || null,
            department || null,
            program || null,
            phone || null,
            emergencyContact || null,
            role === 'Internship Assessor' ? (req.body.job_title || other || null) : null
        ]);

        const newUserId = result.rows[0].id;

        // Save to other_workplaces if necessary
        if ((role === 'Intern' || role === 'Internship Assessor') && workplace === 'other' && other) {
            await pool.query(
                'INSERT INTO other_workplaces (user_id, name) VALUES ($1, $2)',
                [newUserId, other]
            );
        }

        req.session.message = '🎉 Registration successful! Please log in.';
        req.session.messageType = 'success';
        res.redirect('/users/login');
    } catch (err) {
        console.error("❌ Error during registration:", err);
        res.status(500).send("Server error");
    }
});



app.get('/api/departments', async (req, res) => {
    const universityId = parseInt(req.query.university_id, 10);
    if (isNaN(universityId)) return res.status(400).json({ departments: [] });

    try {
        const result = await pool.query('SELECT * FROM departments WHERE university_id = $1', [universityId]);
        res.json({ departments: result.rows || [] });
    } catch (error) {
        console.error('Error fetching departments:', error);
        res.status(500).json({ departments: [] });
    }
});

app.get('/api/programs', async (req, res) => {
    const universityId = parseInt(req.query.university_id, 10);
    if (isNaN(universityId)) return res.status(400).json({ error: "Invalid university_id" });

    try {
        const result = await pool.query(`
            SELECT p.id, p.name FROM programs p
                                         JOIN departments d ON p.department_id = d.id
            WHERE d.university_id = $1`, [universityId]);

        if (result.rows.length > 0) {
            res.json({ programs: result.rows });
        } else {
            res.status(404).json({ programs: [] });
        }
    } catch (error) {
        console.error('Error fetching programs:', error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.get('/api/companies-all', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name FROM companies ORDER BY name');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching companies:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Fetch interns who share the same workplace_id as the logged-in assessor
app.get('/api/interns-by-workplace', async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
        // Get the workplace_id of the logged-in user (assessor)
        const userResult = await pool.query(
            'SELECT workplace_id FROM users WHERE id = $1',
            [req.user.id]
        );

        const assessorWorkplaceId = userResult.rows[0]?.workplace_id;
        if (!assessorWorkplaceId) {
            return res.status(400).json({ message: 'Assessor has no workplace_id' });
        }

        // Get interns who share this workplace
        const internsResult = await pool.query(
            `SELECT id, username FROM users WHERE role = 'Intern' AND workplace_id = $1`,
            [assessorWorkplaceId]
        );

        res.json(internsResult.rows);
    } catch (err) {
        console.error('❌ Error fetching interns by workplace:', err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

//lecturer
app.get("/api/tasks/lecturer", isAuthenticated, async (req, res) => {
    if (req.user.role.toLowerCase() !== "lecturer") return res.status(403).json({ error: "Not a lecturer" });

    try {
        const internResult = await pool.query(
            "SELECT id FROM users WHERE role = 'Intern' AND lecturer_id = $1",
            [req.user.id]
        );

        const internIds = internResult.rows.map(r => r.id);
        if (internIds.length === 0) return res.json([]);

        const taskResult = await pool.query(
            "SELECT * FROM tasks WHERE assignee_id = ANY($1::int[]) ORDER BY created_at DESC",
            [internIds]
        );

        res.json({ tasks: taskResult.rows }); // ✅ wrap in `{ tasks: ... }` for consistency
    } catch (err) {
        console.error("❌ Lecturer task fetch failed:", err);
        res.status(500).json({ error: "Failed to load tasks" });
    }
});





app.get("/api/assessor/interns", isAuthenticated, async (req, res) => {
    try {
        const userId = req.user.id;

        // Get assessor's workplace_id
        const assessor = await pool.query(
            'SELECT workplace_id FROM users WHERE id = $1 AND role = $2',
            [userId, 'Internship Assessor']
        );

        if (!assessor.rows.length || !assessor.rows[0].workplace_id) {
            return res.status(403).json({ message: "Assessor workplace not found." });
        }

        const workplaceId = assessor.rows[0].workplace_id;

        // ✅ Only interns who are linked + match workplace_id
        const interns = await pool.query(`
            SELECT u.id, u.username, u.email, u.avatar_url, u.is_active,
                   d.name AS department_name, un.name AS university_name
            FROM assessor_intern_links l
            JOIN users u ON u.id = l.intern_id
            LEFT JOIN departments d ON u.department_id = d.id
            LEFT JOIN universities un ON u.university_id = un.id
            WHERE l.assessor_id = $1 AND u.workplace_id = $2
        `, [userId, workplaceId]);

        return res.json({ interns: interns.rows });
    } catch (error) {
        console.error("Error fetching linked interns:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});


app.get("/test-socket", (req, res) => {
    res.send("✅ Socket server is up and reachable");
});


app.get('/users/user-role', isAuthenticated, (req, res) => {
    res.json({ role: req.user.role });
});

const internRoutes = require('./routes/interns');
app.use('/api/interns', internRoutes);


// Auth Middleware

function isManagementAuthenticated(req, res, next) {
    if (req.session && req.session.managementUser) {
        return next();
    }
    req.flash('error', 'Please log in as admin.');
    res.redirect('/sec/management');
}

function isAuthenticated(req, res, next) {
    if (!req.isAuthenticated?.() || !req.user) {
        if (req.headers.accept?.includes('application/json')) {
            return res.status(401).json({ error: 'Unauthorized' }); // ✅ frontend-safe
        } else {
            req.session.message = '🔒 Please log in to access this page!';
            req.session.messageType = 'error';
            return res.redirect('/users/login'); // ✅ still works for EJS
        }
    }
    next();
}


function isNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/users/dashboard');
    }
    next();
}

const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: process.env.FRONTEND_URL || "http://localhost:5173",
        methods: ["GET", "POST"],
        credentials: true
    }
});

// Attach io to the app so routes can access it
app.set("io", io);

// ✅ Use session middleware for Socket.IO
const sharedSession = require("express-socket.io-session");
io.use(sharedSession(sessionMiddleware, {
    autoSave: true
}));

// ✅ WebSocket connection
io.on("connection", (socket) => {
    const user = socket.handshake.session?.passport?.user;

    if (user) {
        const { id, role } = user;

        // 🔗 Join personal room based on role
        if (role === "Lecturer") {
            socket.join(`lecturer_${id}`);
            console.log(`🎓 Lecturer ${id} joined room: lecturer_${id}`);
        } else if (role === "Assessor") {
            socket.join(`assessor_${id}`);
            console.log(`🧑‍💼 Assessor ${id} joined room: assessor_${id}`);
        } else if (role === "Intern") {
            socket.join(`intern_${id}`);
            console.log(`👨‍🎓 Intern ${id} joined room: intern_${id}`);
        }

        console.log("🟢 WebSocket connected:", socket.id);
    } else {
        console.log("⚠️ Socket connected without valid session");
    }

    // Task broadcast
    socket.on("task:created", (taskData) => {
        io.emit("task:new", taskData); // Public for now — customize later
    });

    // Comment broadcast to task-specific room
    socket.on("comment:posted", (comment) => {
        io.to(comment.task_id.toString()).emit("comment:new", comment);
    });

    // Manual room joining (fallback for old logic)
    socket.on("join", (userId) => {
        socket.join(userId);
        console.log(`User joined manual room: ${userId}`);
    });

    socket.on("disconnect", () => {
        console.log("🔴 Client disconnected:", socket.id);
    });
});

server.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Intern-Connect Server is running on port ${port}`);
});
