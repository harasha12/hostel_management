// ================================
// FILE UPLOAD CONFIGURATION
// ================================
const express = require("express");
const mysql = require("mysql2");
const session = require("express-session");
const path = require("path");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const multer = require("multer");
const fs = require("fs");
// ======================
// MULTER CONFIG
// ======================
const receiptsDir = path.join(__dirname, "uploads/receipts");
if (!fs.existsSync(receiptsDir)) {
    fs.mkdirSync(receiptsDir, { recursive: true });
}
const app = express();


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let dir;

    if (file.fieldname === "receipt_pdf") {
      dir = path.join(__dirname, "uploads/receipts");
    } else if (file.fieldname === "outpass_pdf") {
      dir = path.join(__dirname, "uploads/outpasses");
    } else if (file.fieldname === "sbi_pdf") {
      dir = path.join(__dirname, "uploads/sbi");
    } else {
      dir = path.join(__dirname, "uploads");
    }

    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = [".pdf", ".xls", ".xlsx"];
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowed.includes(ext)) {
      return cb(new Error("Only PDF or Excel files allowed"));
    }
    cb(null, true);
  },
});



// ===== Middleware =====
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(
  session({
    secret: "supersecret",
    resave: false,
    saveUninitialized: true,
  })
);

app.use((req, res, next) => {
  res.locals.session = req.session;
  next();
});

// ===== MySQL Connection =====
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'Phani@2005$',
    database: 'hostel_management',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test connection by running a simple query
db.query('SELECT 1', (err) => {
    if (err) console.error("DB Error:", err);
    else console.log("✅ MySQL Pool Connected");
});

module.exports = db;

// Show login choice page
app.get("/choose_login", (req, res) => {
  res.render("choose_login"); // make sure choose_login.ejs exists in views/
});
// Logout
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.send("Error logging out");
    }
    res.redirect("/"); // or redirect to login page
  });
});


// ===== Landing Page =====
app.get("/", (req, res) => {
  if (req.session.role === "student") return res.redirect("/student/dashboard");
  if (req.session.role === "warden") return res.redirect("/warden/dashboard");
  if (req.session.role === "admin") return res.redirect("/admin/dashboard");
  if (req.session.role === "security") return res.redirect("/security/dashboard");

  res.render("choose_login");
});
// ===== FORGOT PASSWORD =====
app.get("/forgot-password", (req, res) => {
  res.render("forgot-password"); // simple email input form
});

app.post("/forgot-password", (req, res) => {
  const { email } = req.body;

  // Check if user exists
  db.query("SELECT * FROM users WHERE email=?", [email], (err, rows) => {
    if (err) return res.send("DB Error");
    if (!rows.length) return res.send("No account found with this email");

    const resetToken = uuidv4(); // unique token
    const resetLink = `http://localhost:3000/reset-password/${resetToken}`;

    // Store token temporarily (you can add a reset_tokens table instead)
    db.query("UPDATE users SET reset_token=? WHERE email=?", [resetToken, email]);

    // Send email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "harshavardhanvangara@gmail.com",
        pass: "bfllbazxsxinlheb", // app password if 2FA enabled
      },
    });

    const mailOptions = {
      from: "harshavardhanvangara@gmail.com",
      to: email,
      subject: "Password Reset - Hostel Management",
      text: `Click the following link to reset your password: ${resetLink}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) return res.send("Error sending email: " + error);
      res.send("Password reset link sent to your email");
    });
  });
});

// ===== RESET PASSWORD =====
app.get("/reset-password/:token", (req, res) => {
  res.render("reset-password", { token: req.params.token });
});

app.post("/reset-password/:token", (req, res) => {
  const { password } = req.body;
  const { token } = req.params;

  bcrypt.hash(password, 10).then((hash) => {
    db.query(
      "UPDATE users SET password=?, reset_token=NULL WHERE reset_token=?",
      [hash, token],
      (err) => {
        if (err) return res.send("Error resetting password");
        res.send("Password reset successful. <a href='/'>Login</a>");
      }
    );
  });
});
// ===== Logout =====
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ===== FORGOT PASSWORD =====
app.get("/forgot-password", (req, res) => {
  res.render("forgot-password"); // email input form
});

app.post("/forgot-password", (req, res) => {
  const { email } = req.body;

  db.query("SELECT * FROM users WHERE email=?", [email], (err, rows) => {
    if (err) return res.send("DB Error");
    if (!rows.length) return res.send("No account found with this email");

    const resetToken = uuidv4(); // unique token
    const resetLink = `http://localhost:3000/reset-password/${resetToken}`;

    db.query("UPDATE users SET reset_token=? WHERE email=?", [resetToken, email]);

    // send email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "harshavardhanvangara@gmail.com",
        pass: "bfllbazxsxinlheb", // app password if 2FA enabled
      },
    });

    const mailOptions = {
      from: "harshavardhanvangara@gmail.com",
      to: email,
      subject: "Password Reset - Hostel Management",
      text: `Click to reset password: ${resetLink}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) return res.send("Error sending email: " + error);
      res.send("Password reset link sent to your email");
    });
  });
});

// ===== RESET PASSWORD =====
app.get("/reset-password/:token", (req, res) => {
  res.render("reset-password", { token: req.params.token });
});

app.post("/reset-password/:token", (req, res) => {
  const { password } = req.body;
  const { token } = req.params;

  bcrypt.hash(password, 10).then((hash) => {
    db.query(
      "UPDATE users SET password=?, reset_token=NULL WHERE reset_token=?",
      [hash, token],
      (err) => {
        if (err) return res.send("Error resetting password");
        res.send("Password reset successful. <a href='/'>Login</a>");
      }
    );
  });
});
app.get('/download/:type/:filename', (req, res) => {
    const { type, filename } = req.params; // type=receipts or outpasses
    const filePath = path.join(__dirname, 'uploads', type, filename);
    res.download(filePath);
});

// =====================================
// STUDENT ROUTES
// =====================================
app.get("/login/student", (req, res) => res.render("login_student"));
app.get("/register/student", (req, res) => res.render("register_student"));

// Register student
// Student registration page
// const bcrypt = require('bcrypt');

// Student Registration Route
app.post("/register/student", (req, res) => {
  const { student_id, name, email, password, room_no, course, year } = req.body;

  if (!student_id || !name || !email || !password) {
    return res.send("Please fill all required fields");
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  // Step 0: Check if student_id already exists
  db.query("SELECT * FROM students WHERE student_id = ?", [student_id], (err, results) => {
    if (err) return res.send("Database error: " + err);
    if (results.length > 0) return res.send("Student ID already exists! Use a different ID.");

    // Step 1: Extract admission year from student_id (R19 → 2019, etc.)
    const prefix = student_id.substring(0, 3);
    let admissionYear = "2000";

    if (prefix === "R19") admissionYear = "2019";
    else if (prefix === "R20") admissionYear = "2020";
    else if (prefix === "R23") admissionYear = "2023";
    else if (prefix === "R27") admissionYear = "2027";

    // Step 2: Get last hostel_id for this year
    const sqlLast = "SELECT hostel_id FROM students WHERE hostel_id LIKE ? ORDER BY hostel_id DESC LIMIT 1";
    db.query(sqlLast, [`${admissionYear}%`], (err2, rows) => {
      if (err2) {
        console.error("Error fetching last hostel_id:", err2);
        return res.send("Error checking hostel ID");
      }

      let newHostelId;
      if (rows.length > 0 && rows[0].hostel_id) {
        // Increment last sequence
        const lastId = rows[0].hostel_id;   // e.g. "2023000005"
        const lastSeq = parseInt(lastId.substring(4)); // get number after year
        newHostelId = admissionYear + String(lastSeq + 1).padStart(6, "0");
      } else {
        // First student of this admission year
        newHostelId = admissionYear + "000001";
      }

      // Step 3: Insert student with generated hostel_id
      const sqlInsert = `
        INSERT INTO students
        (student_id, name, email, password, hostel_id, room_no, course, year, total_fee, total_paid, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, NOW())
      `;

      db.query(
        sqlInsert,
        [student_id, name, email, hashedPassword, newHostelId, room_no, course, year],
        (err3) => {
          if (err3) {
            console.error("Error inserting student:", err3);
            return res.send("Error registering student: " + err3);
          }

          res.send(
            `✅ Student registered successfully!<br>College ID: ${student_id}<br>Hostel ID: ${newHostelId}`
          );
        }
      );
    });
  });
});



// Student login POST
app.post("/login/student", (req, res) => {
  const { student_id, password } = req.body;

  if (!student_id || !password) return res.send("Please provide student ID and password");

  const sql = "SELECT * FROM students WHERE student_id=?";
  db.query(sql, [student_id], (err, results) => {
    if (err) return res.send("DB Error: " + err);
    if (results.length === 0) return res.send("Invalid Credentials");

    const student = results[0];
    const match = bcrypt.compareSync(password, student.password);
    if (!match) return res.send("Invalid Credentials");

    // Save session
    req.session.user = student;
    req.session.role = "student";

    res.redirect("/student/dashboard");
  });
});


app.get("/student/dashboard", (req, res) => {
  if (req.session.role !== "student") return res.redirect("/choose_login");

  // Pass the session user as 'user'
  res.render("student/dashboard", { user: req.session.user });
});



// Show Apply Outpass form
app.get("/student/applyoutpass", (req, res) => {
  if (!req.session.user || req.session.role !== "student") {
    return res.redirect("/login/student");
  }
  res.render("student/applyOutpass");
});

// Handle Apply Outpass form submission
app.post("/student/applyoutpass", (req, res) => {
  if (!req.session.user || req.session.role !== "student") {
    return res.redirect("/login/student");
  }

  const { period, reason, from_date, to_date } = req.body;
  const student_id = req.session.user.student_id;

  db.query(
    "INSERT INTO outpasses (student_id, period, reason, out_date, return_date, status) VALUES (?, ?, ?, ?, ?, ?)",
    [student_id, period, reason, from_date, to_date, "Pending"],
    (err) => {
      if (err) {
        console.error("Error Applying Outpass:", err);
        return res.send("Error Applying Outpass: " + err);
      }
      res.redirect("/student/outpasses");
    }
  );
});

// ==========================
// STUDENT DASHBOARD ROUTES
// ==========================
app.get("/student/dashboard", (req, res) => {
  if (req.session.role !== "student") return res.redirect("/login/student");
  res.render("student/dashboard", { user: req.session.user, session: req.session });
});

// Student Profile
app.get("/student/profile", (req, res) => {
  if (req.session.role !== "student") return res.redirect("/login/student");

  const student_id = req.session.user.student_id;
  db.query("SELECT * FROM students WHERE student_id = ?", [student_id], (err, result) => {
    if (err) return res.send("Error fetching profile: " + err);
    res.render("student/profile", { student: result[0], session: req.session });
  });
});

// Update Profile
app.post("/student/profile", (req, res) => {
  if (req.session.role !== "student") return res.redirect("/login/student");

  const student_id = req.session.user.student_id;
  const { name, email, room_no, course, year } = req.body;

  db.query(
    "UPDATE students SET name=?, email=?, room_no=?, course=?, year=? WHERE student_id=?",
    [name, email, room_no, course, year, student_id],
    (err) => {
      if (err) {
        console.error("Error updating profile:", err);
        return res.send("Error updating profile: " + err);
      }

      // ✅ Fetch updated data again to show in profile page
      db.query(
        "SELECT * FROM students WHERE student_id = ?",
        [student_id],
        (err, results) => {
          if (err) return res.send("Error fetching updated profile: " + err);

          // Update session also so dashboard shows new info
          req.session.user = results[0];

          res.render("profile", { student: results[0] });
        }
      );
    }
  );
});

// Student Attendance
app.get("/student/viewattendance", (req, res) => {
  if (req.session.role !== "student") return res.redirect("/login/student");

  const student_id = req.session.user.student_id;
  db.query("SELECT * FROM attendance WHERE student_id = ?", [student_id], (err, results) => {
    if (err) return res.send("Error fetching attendance: " + err);
    res.render("student/viewattendance", { attendance: results, session: req.session });
  });
});

// Student Fees
app.get('/student/viewfees', async (req, res) => {
    if (req.session.role !== 'student') return res.redirect('/choose_login');

    const student_id = req.session.user.student_id;

    try {
        // Fetch all receipts for this student (including status)
        const [receipts] = await db.promise().query(
            "SELECT ref_id, amount_paid, status, created_at FROM fee_receipts WHERE student_id = ? ORDER BY created_at DESC",
            [student_id]
        );

        // Fetch student's total fee from DB
        const [studentRows] = await db.promise().query(
            "SELECT total_fee FROM students WHERE student_id = ?",
            [student_id]
        );

        const total_fee = studentRows.length ? parseFloat(studentRows[0].total_fee) : 0;

        // Sum only verified receipts
        const total_paid = receipts
            .filter(r => r.status === 'Verified')
            .reduce((sum, r) => sum + (parseFloat(r.amount_paid) || 0), 0);

        const remaining_due = total_fee - total_paid;

        res.render('student/viewfees', {
            receipts,
            total_paid,
            remaining_due,
            total_fee
        });

    } catch (err) {
        console.error("Error loading fee details:", err);
        res.status(500).send("Error loading fee details.");
    }
});



// GET form
app.get('/student/uploadReceipt', (req, res) => {
    if (req.session.role !== 'student') return res.redirect('/choose_login');
    res.render('student/uploadReceipt', { user: req.session.user });
});

// POST upload
app.post('/student/uploadReceipt', upload.single("sbi_pdf"), async (req, res) => {
    let conn;
    try {
        if (req.session.role !== 'student') return res.redirect('/choose_login');

        const student_id = req.session.user.student_id;
        const { ref_id, amount_paid } = req.body;

        if (!req.file) return res.send("❌ No PDF uploaded.");
        const pdf_path = `uploads/receipts/${req.file.filename}`;

        conn = await db.promise().getConnection();
        await conn.beginTransaction();

        // 1️⃣ Verify against SBI transactions
        const [[match]] = await conn.query(
            `SELECT * FROM sbi_transactions WHERE TRIM(ref_id)=? AND CAST(amount AS DECIMAL)=? AND status='Pending'`,
            [ref_id.trim(), parseFloat(amount_paid)]
        );

        if (!match) {
            await conn.rollback();
            return res.send("❌ Cannot verify. REF ID or amount not present in the latest SBI upload.");
        }

        // 2️⃣ Insert fee receipt as Verified
        await conn.query(
            "INSERT INTO fee_receipts (student_id, ref_id, amount_paid, pdf_path, status, created_at) VALUES (?, ?, ?, ?, 'Verified', NOW())",
            [student_id, ref_id.trim(), parseFloat(amount_paid), pdf_path]
        );

        // 3️⃣ Update student's total_paid
        await conn.query(
            "UPDATE students SET total_paid = total_paid + ? WHERE student_id = ?",
            [parseFloat(amount_paid), student_id]
        );

        // 4️⃣ Mark SBI transaction as used
        await conn.query(
            "UPDATE sbi_transactions SET status='Verified' WHERE ref_id=?",
            [ref_id.trim()]
        );

        await conn.commit();
        res.send("✅ Receipt verified successfully using official SBI data.");

    } catch (err) {
        if (conn) await conn.rollback();
        console.error("❌ Error verifying student receipt:", err);
        res.status(500).send("Error uploading or verifying receipt: " + err.message);
    } finally {
        if (conn) conn.release();
    }
});



app.get('/student/viewfees', async (req, res) => {
    if (req.session.role !== 'student') return res.redirect('/choose_login');

    const student_id = req.session.user.student_id;

    const [receipts] = await db.promise().query(
        "SELECT * FROM fee_receipts WHERE student_id=? ORDER BY created_at DESC",
        [student_id]
    );

    const total_paid = receipts
        .filter(r => r.status === 'Verified')
        .reduce((sum, r) => sum + parseFloat(r.amount_paid), 0);

    const total_fee = 50000; // Example, can fetch dynamically
    const remaining_due = total_fee - total_paid;

    res.render('student/viewFees', { receipts, total_paid, remaining_due });
});

// View student outpasses
app.get("/student/outpasses", (req, res) => {
  if (!req.session.user || req.session.role !== "student") {
    return res.redirect("/login/student");
  }

  db.query(
    "SELECT * FROM outpasses WHERE student_id=?",
    [req.session.user.student_id],
    (err, outpasses) => {
      if (err) {
        console.error("Error Loading Outpasses:", err);
        return res.send("Error Loading Outpasses: " + err);
      }
      res.render("student/outpasses", { outpasses });
    }
  );
});


// =====================================
// WARDEN ROUTES
// =====================================
app.get("/login/warden", (req, res) => res.render("login_warden"));
app.get("/register/warden", (req, res) => res.render("register_warden"));

// Warden registration
app.post("/register/warden", (req, res) => {
  const { name, email, password, hostel_id } = req.body;
  if (!hostel_id) return res.send("Hostel ID is required");

  bcrypt.hash(password, 10).then((hash) => {
    db.query(
      "INSERT INTO wardens (name, email, password, hostel_id) VALUES (?, ?, ?, ?)",
      [name, email, hash, hostel_id],
      (err) => {
        if (err) return res.send("Warden Registration Failed: " + err);
        res.redirect("/login/warden");
      }
    );
  });
});


// Warden login
app.post("/login/warden", (req, res) => {
  const { email, password } = req.body;
  db.query("SELECT * FROM wardens WHERE email=?", [email], (err, rows) => {
    if (err) return res.send("DB Error");
    if (!rows.length) return res.send("Invalid Credentials");

    bcrypt.compare(password, rows[0].password).then((match) => {
      if (!match) return res.send("Invalid Credentials");
      req.session.user = rows[0];
      req.session.role = "warden";
      res.redirect("/warden/dashboard");
    });
  });
});

app.get("/warden/dashboard", (req, res) => {
  if (req.session.role !== "warden") return res.redirect("/login/warden");
  res.render("warden/dashboard", { user: req.session.user, session: req.session });
});


// Mark attendance
app.post("/warden/markAttendance", (req, res) => {
  const date = req.body.date || new Date().toISOString().split('T')[0]; // Use today if date not provided
  const period = req.body.period || "1"; // Or get from a hidden input if you have period

  const attendanceData = [];

  // req.body keys will be like 'attendance_123', 'attendance_124', etc.
  for (let key in req.body) {
    if (key.startsWith("attendance_")) {
      const student_id = key.split("_")[1]; // get ID from key
      const status = req.body[key];
      attendanceData.push([student_id, date, period, status]);
    }
  }

  if (attendanceData.length === 0) return res.send("No attendance data submitted");

  // Bulk insert
  db.query(
    "INSERT INTO attendance (student_id, date, period, status) VALUES ?",
    [attendanceData],
    (err) => {
      if (err) return res.send("Error Saving Attendance: " + err);
      res.redirect("/warden/dashboard");
    }
  );
});


// Show Mark Attendance page
app.get("/warden/markAttendance", (req, res) => {
  if (req.session.role !== "warden") return res.redirect("/login/warden");

  db.query("SELECT * FROM students", (err, results) => {
    if (err) return res.send("Error fetching students: " + err);
    res.render("warden/markAttendance", { students: results, session: req.session });
  });
});

// Show all outpasses pending approval
// Show all outpasses pending approval
app.get("/warden/approveOutpass", (req, res) => {
  if (req.session.role !== "warden") return res.redirect("/login/warden");

  db.query("SELECT * FROM outpasses WHERE status='Pending'", (err, results) => {
    if (err) return res.send("Error fetching outpasses: " + err);
    res.render("warden/approveOutpass", { outpasses: results, session: req.session });
  });
});

app.post("/warden/approveOutpass/:id/:action", (req, res) => {
  const { id, action } = req.params;
  const status = action === "approve" ? "Approved" : "Rejected";

  db.query("UPDATE outpasses SET status=? WHERE outpass_id=?", [status, id], (err) => {
    if (err) return res.send("Error Updating Outpass: " + err);
    res.redirect("/warden/approveOutpass");
  });
});




// Show Students list
app.get("/warden/viewStudents", (req, res) => {
  if (req.session.role !== "warden") return res.redirect("/login/warden");

  db.query("SELECT * FROM students", (err, results) => {
    if (err) return res.send("Error fetching students: " + err);
    res.render("warden/viewStudents", { students: results, session: req.session });
  });
});

app.post("/warden/markAttendance", (req, res) => {
  const data = req.body;  // all inputs
  const date = new Date(); // or pick from form
  const period = 1;        // static or from form

  const queries = [];
  Object.keys(data).forEach(key => {
    if (key.startsWith("attendance_")) {
      const student_id = key.replace("attendance_", "");
      const status = data[key];
      queries.push([student_id, date, period, status]);
    }
  });

  if (queries.length === 0) return res.send("No attendance submitted");

  db.query(
    "INSERT INTO attendance (student_id, date, period, status) VALUES ?",
    [queries],
    (err) => {
      if (err) return res.send("Error Saving Attendance: " + err);
      res.redirect("/warden/dashboard");
    }
  );
});
// =======================================
// WARDEN UPLOAD SBI PDF
// =======================================

app.get("/warden/uploadSBI", (req, res) => {
  if (!req.session.user || req.session.role !== "warden") {
    return res.redirect("/choose_login");
  }

  res.render("warden/uploadSBI");
});

app.post("/warden/uploadSBI", upload.single("sbi_pdf"), (req, res) => {
  if (!req.file) {
    return res.send("No file uploaded!");
  }

  // Optional: Save file info to DB if needed
  // db.query("INSERT INTO sbi_uploads (warden_id, file_path) VALUES (?, ?)", [req.session.user.id, req.file.path]);

  res.send("✅ SBI PDF uploaded successfully and stored in /uploads/receipts!");
});


// =====================================
// ADMIN ROUTES
// =====================================
app.get("/login/admin", (req, res) => res.render("login_admin"));
app.get("/register/admin", (req, res) => res.render("register_admin"));

// Admin registration
app.post("/register/admin", (req, res) => {
  const { name, email, password } = req.body;
  bcrypt.hash(password, 10).then((hash) => {
    db.query(
      "INSERT INTO admins (name, email, password) VALUES (?, ?, ?)",
      [name, email, hash],
      (err) => {
        if (err) return res.send("Registration Failed: " + err);
        res.redirect("/login/admin");
      }
    );
  });
});

// Admin login
app.post("/login/admin", (req, res) => {
  const { email, password } = req.body;
  db.query("SELECT * FROM admins WHERE email=?", [email], (err, rows) => {
    if (err) return res.send("DB Error");
    if (!rows.length) return res.send("Invalid Credentials");

    bcrypt.compare(password, rows[0].password).then((match) => {
      if (!match) return res.send("Invalid Credentials");
      req.session.user = rows[0];
      req.session.role = "admin";
      res.redirect("/admin/dashboard");
    });
  });
});






// ======================
// ADMIN DASHBOARD
// ======================
app.get("/admin/dashboard", (req, res) => {
    if (!req.session.user || req.session.role !== "admin") {
        return res.redirect("/choose_login");
    }
    res.render("admin/dashboard", { user: req.session.user, session: req.session });
});

// ======================
// ADMIN UPLOAD SBI PDF
// ======================
app.get("/warden/uploadSBI", (req, res) => {
    if (!req.session.user || req.session.role !== "warden") return res.redirect("/choose_login");
    res.render("warden/uploadSBI");
});

app.post("/warden/uploadSBI", upload.single("sbi_pdf"), async (req, res) => {
    if (!req.session.user || req.session.role !== "warden") return res.redirect("/choose_login");

    try {
        if (!req.file) return res.send("No PDF uploaded!");

        const pdfBuffer = fs.readFileSync(req.file.path);
        const pdfData = await pdfParse(pdfBuffer);

        const lines = pdfData.text.split("\n");
        let updatedCount = 0;

        for (let line of lines) {
            const match = line.match(/REFID[:\s]*(\S+).*AMOUNT[:\s]*(\d+\.?\d*)/i);
            if (match) {
                const ref_id = match[1].trim();
                const amount = parseFloat(match[2]);

                const [studentRows] = await db
                    .promise()
                    .query("SELECT * FROM students WHERE student_id = ?", [ref_id]);

                if (studentRows.length > 0) {
                    await db
                        .promise()
                        .query(
                            "UPDATE students SET total_paid = total_paid + ?, remaining_fee = total_fee - (total_paid + ?) WHERE student_id = ?",
                            [amount, amount, ref_id]
                        );
                    updatedCount++;
                }
            }
        }

        res.send(`✅ SBI PDF processed successfully. ${updatedCount} student(s) updated.`);
    } catch (err) {
        console.error("Error processing SBI PDF:", err);
        res.status(500).send("Error processing SBI PDF: " + err.message);
    }
});


// View pending receipts
app.get('/admin/pendingReceipts', async (req, res) => {
    if (req.session.role !== 'admin') return res.redirect('/choose_login');

    const [pending] = await db.promise().query(
        "SELECT fr.*, s.name FROM fee_receipts fr JOIN students s ON fr.student_id=s.student_id WHERE fr.status='Pending' ORDER BY fr.created_at DESC"
    );

    res.render('admin/pendingReceipts', { pending });
});

// Verify or Reject
app.get('/admin/viewReceipts', async (req, res) => {
    if (req.session.role !== 'admin') return res.redirect('/choose_login');

    const [allReceipts] = await db.promise().query(
        `SELECT fr.*, s.name 
         FROM fee_receipts fr 
         JOIN students s ON fr.student_id = s.student_id
         ORDER BY fr.created_at DESC`
    );

    res.render('admin/viewReceipts', { allReceipts });
});


// GET form
app.get("/admin/setFee", (req, res) => {
    if (req.session.role !== "admin") return res.redirect("/choose_login");
    res.render("admin/setFee"); // form for year + amount
});

// POST form: set fees for all students of a particular year
// POST form: set fees for all students of a particular year
app.post("/admin/setFee", (req, res) => {
    if (req.session.role !== "admin") return res.redirect("/choose_login");

    const { year, amount } = req.body;

    // Only update total_fee and reset total_paid
    // remaining_fee is generated automatically as total_fee - total_paid
    const sql = `
        UPDATE students 
        SET total_fee = ?, 
            total_paid = 0 
        WHERE year = ?
    `;

    db.query(sql, [amount, year], (err) => {
        if (err) return res.send("Error updating fees: " + err);
        res.send(`Fees of ₹${amount} applied to all ${year} year students.`);
    });
});
app.get("/admin/verifyFees", (req, res) => {
  const sql = "SELECT * FROM fees WHERE status = 'Pending'";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching fees:", err);
      return res.status(500).send("Database error");
    }

    // Pass results as receipts to EJS
    res.render("admin/verifyFees", { receipts: results });
  });
});


app.post("/admin/verifyFees/:id", (req, res) => {
  if (!req.session.user || req.session.role !== "admin") {
    return res.redirect("/login/admin");
  }

  const { status } = req.body;
  const feeId = req.params.id;

  db.query(
    "UPDATE fees SET status = ? WHERE id = ?",
    [status, feeId],
    (err) => {
      if (err) {
        console.error(err);
        return res.send("Error verifying fee");
      }
      res.redirect("/admin/verifyFees");
    }
  );
});
// ========================
// MANAGE WARDENS
// ========================

// Show Manage Wardens Page
app.get("/admin/manageWardens", (req, res) => {
    const sql = "SELECT * FROM wardens";
    db.query(sql, (err, results) => {
        if (err) {
            console.error("Error fetching wardens:", err);
            return res.status(500).send("Database error");
        }
        res.render("admin/manageWardens", { wardens: results });
    });
});

// Add Warden
app.post("/admin/addWarden", (req, res) => {
    const { name, email, password } = req.body;

    // Hash password before saving (recommended for security)
    const bcrypt = require("bcrypt");
    const saltRounds = 10;

    bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
        if (err) {
            console.error("Error hashing password:", err);
            return res.status(500).send("Error processing request");
        }

        const sql = "INSERT INTO wardens (name, email, password) VALUES (?, ?, ?)";
        db.query(sql, [name, email, hashedPassword], (err) => {
            if (err) {
                console.error("Error adding warden:", err);
                return res.status(500).send("Database error");
            }
            res.redirect("/admin/manageWardens");
        });
    });
});

// Delete Warden
app.get("/admin/deleteWarden/:id", (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM wardens WHERE id = ?";
    db.query(sql, [id], (err) => {
        if (err) {
            console.error("Error deleting warden:", err);
            return res.status(500).send("Database error");
        }
        res.redirect("/admin/manageWardens");
    });
});
// Render the upload SBI page
app.get("/admin/uploadSBI", (req, res) => {
    if (!req.session.user || req.session.role !== "admin") {
        return res.redirect("/choose_login");
    }

    res.render("admin/uploadSBI"); // make sure this EJS view exists
});
const pdfParse = require("pdf-parse");
const XLSX = require("xlsx");
const Tesseract = require("tesseract.js");
const { fromPath } = require("pdf2pic");

let lastUploadedRefIds = new Set(); // store REF IDs from last upload
let lastUploadedAmounts = {};       // map REF_ID -> amount

// Upload SBI PDF or Excel
app.post("/admin/uploadSBI", upload.single("sbi_pdf"), async (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "admin")
      return res.redirect("/choose_login");

    if (!req.file) return res.send("❌ No file uploaded!");

    const filePath = req.file.path;
    const ext = path.extname(req.file.originalname).toLowerCase();
    let insertedCount = 0;

    if (ext === ".xls" || ext === ".xlsx") {
      const workbook = XLSX.readFile(filePath);
      const sheet = XLSX.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]], { defval: "" });

      if (!sheet.length) {
        console.log("⚠️ Excel file is empty or invalid format");
        return res.send("⚠️ Excel file has no data.");
      }

      console.log("🧾 Columns in Excel:", Object.keys(sheet[0]));
      console.log("📄 Sample first row:", sheet[0]);

      for (const row of sheet) {
        // ✅ Extract REF ID and Amount from correct columns
        const ref_id = (row["Bank Reference No"] || "").toString().trim();
        const amount = parseFloat(row["Amount"] || 0);

        if (ref_id && !isNaN(amount)) {
          await db
            .promise()
            .query(
              `INSERT INTO sbi_transactions (ref_id, amount, uploaded_at)
               VALUES (?, ?, NOW())
               ON DUPLICATE KEY UPDATE amount=?, uploaded_at=NOW()`,
              [ref_id, amount, amount]
            );
          insertedCount++;
        }
      }
    }

    fs.unlinkSync(filePath);
    res.send(`✅ SBI file processed successfully. ${insertedCount} transaction(s) added/updated.`);
  } catch (err) {
    console.error("SBI Upload Error:", err);
    res.status(500).send("Error processing SBI file: " + err.message);
  }
});

// Manual verify button
app.post("/admin/verifyReceipt", async (req, res) => {
  try {
    const { receipt_id } = req.body;

    const [[receipt]] = await db
      .promise()
      .query("SELECT ref_id, amount_paid FROM fee_receipts WHERE receipt_id=?", [
        receipt_id,
      ]);

    if (!receipt) return res.status(404).send("Receipt not found");

    const { ref_id, amount_paid } = receipt;

    // ✅ Verify directly using SBI table (not memory)
    const [[sbiMatch]] = await db
      .promise()
      .query(
        "SELECT * FROM sbi_transactions WHERE ref_id=? AND amount=?",
        [ref_id, amount_paid]
      );

    if (!sbiMatch) {
      return res.send(
        "❌ Cannot verify. REF ID or amount not present in latest SBI upload."
      );
    }

    await db
      .promise()
      .query(
        "UPDATE fee_receipts SET status='Verified', verified_by=?, verified_at=NOW() WHERE receipt_id=?",
        [req.session.user.id, receipt_id]
      );

    res.redirect("/admin/pendingReceipts");
  } catch (err) {
    console.error("Verify error:", err);
    res.status(500).send("Error verifying receipt: " + err.message);
  }
});


// =====================================
// SECURITY ROUTES
// =====================================
app.get("/login/security", (req, res) => res.render("login_security"));
app.get("/register/security", (req, res) => res.render("register_security"));

app.post("/register/security", (req, res) => {
  const { name, email, password, hostel_id } = req.body;
  if (!hostel_id) return res.send("Hostel ID is required");

  bcrypt.hash(password, 10).then((hash) => {
    // Insert into users table (for login/role)
    db.query(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
      [name, email, hash, "security"],
      (err, result) => {
        if (err) return res.send("User Creation Failed: " + err);

        // Insert into security table
        db.query(
          "INSERT INTO security (name, email, password, hostel_id) VALUES (?, ?, ?, ?)",
          [name, email, hash, hostel_id],
          (err) => {
            if (err) return res.send("Security Registration Failed: " + err);
            res.redirect("/login/security");
          }
        );
      }
    );
  });
});


// Security login
app.post("/login/security", (req, res) => {
  const { email, password } = req.body;

  // Always check users table
  db.query("SELECT * FROM users WHERE email=? AND role='security'", [email], (err, rows) => {
    if (err) return res.send("DB Error");
    if (!rows.length) return res.send("Invalid Credentials");

    bcrypt.compare(password, rows[0].password).then((match) => {
      if (!match) return res.send("Invalid Credentials");

      // Save session info
      req.session.user = rows[0];
      req.session.role = "security";

      // Redirect to security dashboard
      res.redirect("/security/dashboard");
    });
  });
});


app.get("/security/dashboard", (req, res) => {
  if (req.session.role !== "security") return res.redirect("/login/security");
  res.render("security/dashboard", { user: req.session.user, session: req.session });
});
/// View outpasses
app.get("/security/viewOutpasses", (req, res) => {
    if (!req.session.user || req.session.role !== "security") {
        return res.redirect("/login/security");
    }

    db.query("SELECT * FROM outpasses ORDER BY out_date DESC", (err, results) => {
        if (err) return res.send("Error fetching outpasses: " + err);
        res.render("security/viewOutpasses", { outpasses: results, session: req.session });
    });
});

// Mark Exit
app.get("/security/markExit/:id", (req, res) => {
    if (!req.session.user || req.session.role !== "security") return res.redirect("/login/security");

    db.query("UPDATE outpasses SET status = 'Exited' WHERE outpass_id = ?", [req.params.id], (err) => {
        if (err) return res.send("Error marking exit: " + err);
        res.redirect("/security/viewOutpasses");
    });
});

// Mark Return
app.get("/security/markReturn/:id", (req, res) => {
    if (!req.session.user || req.session.role !== "security") return res.redirect("/login/security");

    db.query("UPDATE outpasses SET status = 'Returned' WHERE outpass_id = ?", [req.params.id], (err) => {
        if (err) return res.send("Error marking return: " + err);
        res.redirect("/security/viewOutpasses");
    });
});



// =====================================
// START SERVER
// =====================================
app.listen(3000, () => console.log("🚀 Server running on http://localhost:3000"));
