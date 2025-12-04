
// ================================
// FILE UPLOAD CONFIGURATION
// ================================
const express = require("express");
const mysql = require("mysql2");
const session = require("express-session");
const flash = require("connect-flash");
const path = require("path");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const multer = require("multer");
const xlsx = require("xlsx");
const fs = require("fs");
// ======================
// MULTER CONFIG
// ======================
const receiptsDir = path.join(__dirname, "uploads/receipts");
if (!fs.existsSync(receiptsDir)) {
    fs.mkdirSync(receiptsDir, { recursive: true });
}


const app = express();
// ✅ Serve uploads folder publicly
const uploadsPath = path.join(__dirname, "uploads");
console.log("📂 Static serving uploads from:", uploadsPath);

if (!fs.existsSync(uploadsPath)) {
  console.error("❌ uploads folder does not exist at:", uploadsPath);
}



const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "harshavardhanvangara@gmail.com",      // your gmail
    pass: "bfllbazxsxinlheb",      // app password
  },
});


// ✅ serve the entire uploads folder publicly
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
// Serve profile images
app.use('/uploads/profile_images', express.static(path.join(__dirname, 'uploads/profile_images')));

// Serve default images (like default-avatar.png)
app.use('/images', express.static(path.join(__dirname, 'public/images')));

app.use(flash());

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let dir;

    switch (file.fieldname) {

      case "receipt_pdf":
        dir = path.join(__dirname, "uploads/receipts");
        break;

      case "outpass_pdf":
        dir = path.join(__dirname, "uploads/outpasses");
        break;

      case "sbi_pdf":
        dir = path.join(__dirname, "uploads/receipts");
        break;

      case "studentsFile":
        dir = path.join(__dirname, "uploads/students");
        break;

      case "student_aadhaar":
      case "father_aadhaar":
        dir = path.join(__dirname, "uploads/aadhaar"); // ✔ Corrected folder name
        break;

      case "profile_image":
        dir = path.join(__dirname, "uploads/profile_images");
        break;

      case "mess_bill_pdf":
        dir = path.join(__dirname, "uploads/mess_bills");
        break;

      default:
        dir = path.join(__dirname, "uploads");
    }

    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },

filename: (req, file, cb) => {
  const studentId = req.session?.user?.student_id || "unknown";
  const ext = path.extname(file.originalname);

  // ---------- AADHAAR (student & father) ----------
  if (file.fieldname === "student_aadhaar" || file.fieldname === "father_aadhaar") {
    return cb(null, `${studentId}_${file.fieldname}${ext}`);
  }

  // ---------- PROFILE IMAGE ----------
  if (file.fieldname === "profile_image") {
    return cb(null, `${studentId}_profile${ext}`);
  }

  // ---------- ALL OTHER FILES (SBI RECEIPTS, ETC.) ----------
  // Replace spaces + all invalid characters with "_"
  safeName = file.originalname
  .replace(/\s+/g, "_")              // replace SPACES
  .replace(/[<>:"/\\|?*]+/g, "")     // remove invalid characters
  .trim();


  return cb(null, Date.now() + "-" + safeName);
}
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedPdfExcel = [".pdf", ".xls", ".xlsx", ".csv"];
    const allowedImages = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".svg"];
    const ext = path.extname(file.originalname).toLowerCase();

    // For Aadhaar or profile images
    if (file.fieldname === "student_aadhaar" || file.fieldname === "father_aadhaar" || file.fieldname === "profile_image") {
      if (!allowedImages.includes(ext)) return cb(new Error("Only image files are allowed"));
    } else {
      if (!allowedPdfExcel.includes(ext)) return cb(new Error("Only PDF/Excel files are allowed"));
    }
    cb(null, true);
  }
});

module.exports = upload;




function getJoinYearFromRegId(regId) {
  if (!regId || regId.length < 2) return null;
  const prefix = regId.substring(0, 2);
  const joinYear = 2000 + parseInt(prefix);
  const currentYear = new Date().getFullYear();
  if (isNaN(joinYear) || joinYear > currentYear) return null;
  return joinYear;
}

app.get("/uploads/*", (req, res) => {
  const filePath = path.join(__dirname, req.path);
  res.download(filePath, (err) => {
    if (err) {
      console.error("DOWNLOAD ERROR:", err);
      res.status(404).send("File not found");
    }
  });
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
    host: 'tramway.proxy.rlwy.net',   // Railway host
    user: 'root',                     // Railway username
    password: 'PrSpzKuerkeTMsPHGgnrwXFuDwhPDQfC',     // Railway password
    database: 'railway',              // Railway database name
    port: 50208,                      // Railway port
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
// In your server.js or a new route file
app.get("/", (req, res) => {
  res.render("home");
});

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


// ===== Logout =====
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ===== FORGOT PASSWORD =====
app.get("/forgot-password", (req, res) => {
  res.render("forgot-password"); // email input form
});



// ========== FORGOT PASSWORD WITH OTP ==========
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  const tables = ["students", "wardens", "admins", "security"];

  const checkNextTable = (index) => {
    if (index >= tables.length)
      return res.send("No account found with this email");

    const table = tables[index];
    db.query(`SELECT * FROM ${table} WHERE email=?`, [email], (err, rows) => {
      if (err) return res.send("DB Error");
      if (rows.length > 0) {
        // Found the user — store OTP
        db.query(`UPDATE ${table} SET otp=? WHERE email=?`, [otp, email], (err2) => {
          if (err2) return res.send("Error saving OTP");

          // Send OTP via email
          const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
              user: "harshavardhanvangara@gmail.com",
              pass: "bfllbazxsxinlheb", // Use App Password
            },
          });

          const mailOptions = {
            from: "harshavardhanvangara@gmail.com",
            to: email,
            subject: "Password Reset OTP - Hostel Management System",
            text: `Your OTP for password reset is: ${otp}\n\nIt will expire in 10 minutes.`,
          };

          transporter.sendMail(mailOptions, (error) => {
            if (error) return res.send("Error sending email: " + error);
            res.render("reset-password", { table, email }); // show reset form
          });
        });
      } else {
        checkNextTable(index + 1);
      }
    });
  };

  checkNextTable(0);
});


// ===== RESET PASSWORD =====
app.get("/reset-password/:token", (req, res) => {
  res.render("reset-password", { token: req.params.token });
});

app.post("/reset-password", (req, res) => {
  const { email, otp, newPassword } = req.body;
  const tables = ["students", "wardens", "admins", "security"];

  const checkNextTable = (index) => {
    if (index >= tables.length)
      return res.send("Invalid OTP or Email");

    const table = tables[index];
    db.query(
      `SELECT * FROM ${table} WHERE email=? AND otp=?`,
      [email, otp],
      (err, rows) => {
        if (err) return res.send("DB Error");
        if (rows.length > 0) {
          // OTP valid — update password
          bcrypt.hash(newPassword, 10).then((hash) => {
            db.query(
              `UPDATE ${table} SET password=?, otp=NULL WHERE email=?`,
              [hash, email],
              (err2) => {
                if (err2) return res.send("Error updating password");
                res.send(
                  "Password reset successful. <a href='/choose_login.ejs'>Login</a>"
                );
              }
            );
          });
        } else {
          checkNextTable(index + 1);
        }
      }
    );
  };

  checkNextTable(0);
});



app.get('/download/:type/:filename', (req, res) => {
  const { type, filename } = req.params; // type can be receipts, outpasses, sbi, etc.
  const filePath = path.join(__dirname, 'uploads', type, filename);
  res.download(filePath, err => {
    if (err) {
      console.error("Download error:", err);
      res.status(404).send("File not found");
    }
  });
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
app.post("/register/student", async (req, res) => {
  const { student_id, name, email, password, room_no, course, year, student_unique_id } = req.body;

  if (!student_id || !name || !email || !password || !student_unique_id) {
    return res.send("⚠️ Please fill all required fields.");
  }

  try {
    // Check if student_id or student_unique_id already exists
    const [existing] = await db.promise().query(
      "SELECT * FROM students WHERE student_id = ? OR student_unique_id = ?",
      [student_id, student_unique_id]
    );
    if (existing.length > 0) {
      return res.send("❌ Student ID or Unique ID already exists! Please use a different one.");
    }

    // Extract joining year from student_id
    const joinYear = 2000 + parseInt(student_id.substring(0, 2));

    // Generate hostel_id
    const [rows] = await db.promise().query(
      "SELECT hostel_id FROM students WHERE hostel_id LIKE ? ORDER BY hostel_id DESC LIMIT 1",
      [`${joinYear}%`]
    );
    let newHostelId;
    if (rows.length > 0 && rows[0].hostel_id) {
      const lastSeq = parseInt(rows[0].hostel_id.substring(4));
      newHostelId = joinYear + String(lastSeq + 1).padStart(6, "0");
    } else {
      newHostelId = joinYear + "000001";
    }

    // Hash password
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Insert student
    await db.promise().query(`
      INSERT INTO students
      (student_id, student_unique_id, name, email, password, hostel_id, room_no, course, year, total_fee, total_paid, year_of_join, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, NOW())
    `, [
      student_id,
      student_unique_id,
      name,
      email,
      hashedPassword,
      newHostelId,
      room_no,
      course,
      year,
      joinYear
    ]);

    res.send(`
      ✅ Student registered successfully!<br>
      📘 College ID: ${student_id}<br>
      🆔 Unique ID: ${student_unique_id}<br>
      🏠 Hostel ID: ${newHostelId}<br>
      🎓 Year of Join: ${joinYear}
    `);
  } catch (err) {
    console.error("Error in registration:", err);
    res.status(500).send("❌ Error registering student. Please try again later.");
  }
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


app.get("/student/dashboard", async (req, res) => {
  if (!req.session.user || req.session.role !== "student") {
    return res.redirect("/login/student");
  }

  const student_id = req.session.user.student_id;

  try {
    // Get student info
    const [studentRows] = await db.promise().query("SELECT * FROM students WHERE student_id = ?", [student_id]);
    if (studentRows.length === 0) return res.send("Student not found");
    const student = studentRows[0];

    // Get join year from reg ID (e.g., 23B81A46__)
    const joinYear = getJoinYearFromRegId(student.student_id);

    // Get yearly fees and verified payments
    const [yearFees] = await db.promise().query("SELECT * FROM yearly_fee ORDER BY year ASC");
    const [paidFees] = await db.promise().query(
      `SELECT year, SUM(amount_paid) AS total_paid
       FROM fee_receipts
       WHERE student_id = ? AND status = 'Verified'
       GROUP BY year`,
      [student_id]
    );

    const paidMap = {};
    paidFees.forEach((p) => (paidMap[p.year] = parseFloat(p.total_paid || 0)));

    const currentYear = new Date().getFullYear();
    const feeSummary = [];
    let unpaidCount = 0;

    for (const yf of yearFees) {
      if (yf.year >= joinYear && yf.year <= currentYear) {
        const paid = paidMap[yf.year] || 0;
        const due = parseFloat(yf.amount) - paid;
        if (due > 0) unpaidCount++;
        feeSummary.push({
          year: yf.year,
          total_fee: parseFloat(yf.amount),
          paid_amount: paid,
          due_amount: due > 0 ? due : 0,
        });
      }
    }

    res.render("student/dashboard", { student, feeSummary, unpaidCount });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading dashboard");
  }
});



// GET complaint form
app.get('/student/complaint', (req, res) => {
    if (req.session.role !== 'student') return res.redirect('/choose_login');
    res.render('student/complaint', { user: req.session.user });
});

// POST submit complaint
app.post('/student/complaint', (req, res) => {
    if (req.session.role !== 'student') return res.redirect('/choose_login');

    const { subject, description } = req.body;
    const student_id = req.session.user.student_id;

    db.query(
        "INSERT INTO complaints (student_id, subject, description) VALUES (?, ?, ?)",
        [student_id, subject, description],
        (err) => {
            if (err) return res.send("Error submitting complaint: " + err);
            res.send("✅ Complaint submitted successfully!");
        }
    );
});
app.get('/student/complaints', (req, res) => {
    if (req.session.role !== 'student') return res.redirect('/choose_login');

    const student_id = req.session.user.student_id;

    db.query(
        "SELECT * FROM complaints WHERE student_id = ? ORDER BY created_at DESC",
        [student_id],
        (err, results) => {
            if (err) return res.send("Error fetching complaints: " + err);
            res.render('student/viewComplaints', { complaints: results });
        }
    );
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

  const { reason, leave_start, leave_end } = req.body;
  const student_id = req.session.user.student_id;

  const from = new Date(leave_start);
  const to = new Date(leave_end);
  const diffDays = Math.ceil((to - from) / (1000 * 60 * 60 * 24)) + 1;

  db.query(
    `INSERT INTO outpasses (student_id, period, reason, outpass_type, out_date, return_date, status)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [student_id, diffDays, reason, "Normal", leave_start, leave_end, "Pending"],
    (err) => {
      if (err) {
        console.error("Error Applying Outpass:", err);
        return res.send("Error Applying Outpass: " + err);
      }
      res.redirect("/student/outpasses");
    }
  );
});


// 🧩 Apply Emergency Outpass (only one per week)
app.get("/student/applyEmergencyOutpass", async (req, res) => {
  if (!req.session.user || req.session.role !== "student") {
    return res.redirect("/login/student");
  }

  const student_id = req.session.user.student_id;

  // Fetch previous emergency outpasses for display
  const [rows] = await db.promise().query(
    "SELECT * FROM outpasses WHERE student_id = ? AND outpass_type = 'Emergency' ORDER BY created_at DESC",
    [student_id]
  );

  res.render("student/applyEmergencyOutpass", { outpasses: rows });
});

app.post("/student/applyEmergencyOutpass", async (req, res) => {
  if (!req.session.user || req.session.role !== "student") {
    return res.redirect("/login/student");
  }

  const { reason, from_date, to_date } = req.body;
  const student_id = req.session.user.student_id;

  try {
    // Check if already applied this week
    const [existing] = await db.promise().query(
      `SELECT * FROM outpasses 
       WHERE student_id = ? 
         AND outpass_type = 'Emergency'
         AND YEARWEEK(created_at, 1) = YEARWEEK(NOW(), 1)`,
      [student_id]
    );

    if (existing.length > 0) {
      return res.send(`
        <script>
          alert("❌ You can only apply one Emergency Outpass per week!");
          window.location.href = "/student/applyEmergencyOutpass";
        </script>
      `);
    }

    await db
      .promise()
      .query(
        `INSERT INTO outpasses 
         (student_id, period, reason, out_date, return_date, status, outpass_type)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [student_id, "Emergency", reason, from_date, to_date, "Pending", "Emergency"]
      );

    res.redirect("/student/applyEmergencyOutpass");
  } catch (err) {
    console.error("Error applying emergency outpass:", err);
    res.status(500).send("Error applying emergency outpass");
  }
});

// ==========================
// STUDENT DASHBOARD ROUTES
// ==========================
app.get("/student/dashboard", (req, res) => {
  if (req.session.role !== "student") return res.redirect("/login/student");
  res.render("student/dashboard", { user: req.session.user, session: req.session });
});

// ============================================
// ✅ STUDENT PROFILE
// ============================================
app.get("/student/profile", async (req, res) => {
  if (!req.session.user || req.session.role !== "student") 
    return res.redirect("/login/student");

  const student_id = req.session.user.student_id;

  try {
    // 1️⃣ Fetch student
    const [[student]] = await db.promise().query(
      "SELECT * FROM students WHERE student_id = ?",
      [student_id]
    );
    if (!student) return res.send("❌ Student not found");

    const studentYear = parseInt(student.year);

    // 2️⃣ Fetch yearly fees up to student year
    const [yearRows] = await db.promise().query(
      "SELECT * FROM yearly_fee WHERE year <= ? ORDER BY year ASC",
      [studentYear]
    );

    // 3️⃣ Fetch verified receipts for this student
    const [receipts] = await db.promise().query(
      "SELECT year, amount_paid, remarks FROM fee_receipts WHERE student_id=? AND status='Verified'",
      [student_id]
    );

    // 4️⃣ Map receipts by year & component
    const paymentMap = {};
    receipts.forEach(r => {
      const yr = r.year;
      if (!paymentMap[yr]) paymentMap[yr] = { 'Room Rent':0, 'Mess Bill1':0, 'Mess Bill2':0, 'Others':0 };
      
      let key = r.remarks.trim().toLowerCase();
      if(key === 'room rent') key = 'Room Rent';
      else if(key === 'mess bill1') key = 'Mess Bill1';
      else if(key === 'mess bill2') key = 'Mess Bill2';
      else key = 'Others';

      paymentMap[yr][key] += parseFloat(r.amount_paid || 0);
    });

    // 5️⃣ Build fee summary per year
    const feeSummary = yearRows.map(y => {
      const room_rent = Number(y.room_rent || 0);
      const mess_bill1 = Number(y.mess_bill1 || 0);
      const mess_bill2 = Number(y.mess_bill2 || 0);

      const paid = paymentMap[y.year] || {};
      const room_rent_paid = Number(paid['Room Rent'] || 0);
      const mess_bill1_paid = Number(paid['Mess Bill1'] || 0);
      const mess_bill2_paid = Number(paid['Mess Bill2'] || 0);

      const room_rent_due = Math.max(room_rent - room_rent_paid, 0);
      const mess_bill1_due = Math.max(mess_bill1 - mess_bill1_paid, 0);
      const mess_bill2_due = Math.max(mess_bill2 - mess_bill2_paid, 0);

      const total_fee = room_rent + mess_bill1 + mess_bill2;
      const total_paid = room_rent_paid + mess_bill1_paid + mess_bill2_paid;
      const total_due = total_fee - total_paid;

      let status = "Not Paid";
      if (room_rent_paid >= room_rent && 
          mess_bill1_paid >= mess_bill1 && 
          mess_bill2_paid >= mess_bill2) {
        status = "Paid";
      } else if (room_rent_paid > 0 || mess_bill1_paid > 0 || mess_bill2_paid > 0) {
        status = "Partial";
      }

      return {
        year: y.year,
        room_rent_paid: room_rent_paid.toFixed(2),
        room_rent_due: room_rent_due.toFixed(2),
        mess_bill1_paid: mess_bill1_paid.toFixed(2),
        mess_bill1_due: mess_bill1_due.toFixed(2),
        mess_bill2_paid: mess_bill2_paid.toFixed(2),
        mess_bill2_due: mess_bill2_due.toFixed(2),
        total_fee: total_fee.toFixed(2),
        total_paid: total_paid.toFixed(2),
        total_due: total_due.toFixed(2),
        status
      };
    });

    res.render("student/profile", { student, feeSummary });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading student profile");
  }
});



// ============================================
// ✅ STUDENT UPDATE PROFILE
// ============================================
app.post("/student/profile", async (req, res) => {
  if (!req.session.user || req.session.role !== "student") {
    return res.redirect("/login/student");
  }

  const student_id = req.session.user.student_id;
  const { name, email, room_no } = req.body;

  try {
    await db.promise().query(
      "UPDATE students SET name=?, email=?, room_no=? WHERE student_id=?",
      [name, email, room_no, student_id]
    );

    // Refresh session data
    const [studentRows] = await db.promise().query(
      "SELECT * FROM students WHERE student_id=?",
      [student_id]
    );
    req.session.user = studentRows[0];

    res.redirect("/student/profile");
  } catch (err) {
    console.error("❌ Error updating profile:", err);
    res.status(500).send("Error updating profile.");
  }
});

// Student Fees
app.get('/student/viewfees', async (req, res) => {
    if (req.session.role !== 'student') return res.redirect('/choose_login');
    const student_id = req.session.user.student_id;

    try {
        // Fetch student info
        const [[student]] = await db.promise().query(
            "SELECT * FROM students WHERE student_id = ?",
            [student_id]
        );
        if (!student) return res.send("Student not found");

        // Fetch yearly fees
        const [yearlyFees] = await db.promise().query(
            "SELECT * FROM yearly_fee ORDER BY year ASC"
        );

        // Fetch verified receipts
        const [receipts] = await db.promise().query(
    "SELECT ref_id, year, amount_paid, remarks, status, created_at FROM fee_receipts WHERE student_id=? AND status='Verified' ORDER BY created_at DESC",
    [student_id]
);

        

        // Map receipts by year & component
        const paymentMap = {};
        receipts.forEach(r => {
            const yr = r.year;
            if (!paymentMap[yr]) paymentMap[yr] = { 'Room Rent':0, 'Mess Bill1':0, 'Mess Bill2':0, 'Others':0 };
            
            let key = r.remarks.trim().toLowerCase();
            if(key === 'room rent') key = 'Room Rent';
            else if(key === 'mess bill1') key = 'Mess Bill1';
            else if(key === 'mess bill2') key = 'Mess Bill2';
            else key = 'Others';

            paymentMap[yr][key] = (paymentMap[yr][key] || 0) + parseFloat(r.amount_paid || 0);
        });

        // Build fee summary per year
        const feeSummary = yearlyFees
            .filter(f => f.year <= student.year)
            .map(f => {
                const paid = paymentMap[f.year] || {};
                const room_rent_paid = paid['Room Rent'] || 0;
                const mess_bill1_paid = paid['Mess Bill1'] || 0;
                const mess_bill2_paid = paid['Mess Bill2'] || 0;

                // Use Number(...) and default 0 to avoid NaN
                const room_rent = Number(f.room_rent || 0);
                const mess_bill1 = Number(f.mess_bill1 || 0);
                const mess_bill2 = Number(f.mess_bill2 || 0);

                const room_rent_due = Math.max(room_rent - room_rent_paid, 0);
                const mess_bill1_due = Math.max(mess_bill1 - mess_bill1_paid, 0);
                const mess_bill2_due = Math.max(mess_bill2 - mess_bill2_paid, 0);

                const total_fee = room_rent + mess_bill1 + mess_bill2;
                const total_paid = room_rent_paid + mess_bill1_paid + mess_bill2_paid;

                let status = "Not Paid";
                if (room_rent_paid >= room_rent &&
                    mess_bill1_paid >= mess_bill1 &&
                    mess_bill2_paid >= mess_bill2) {
                    status = "Paid";
                } else if (room_rent_paid > 0 || mess_bill1_paid > 0 || mess_bill2_paid > 0) {
                    status = "Partial";
                }

                return {
                    year: f.year,
                    room_rent_paid: room_rent_paid.toFixed(2),
                    room_rent_due: room_rent_due.toFixed(2),
                    mess_bill1_paid: mess_bill1_paid.toFixed(2),
                    mess_bill1_due: mess_bill1_due.toFixed(2),
                    mess_bill2_paid: mess_bill2_paid.toFixed(2),
                    mess_bill2_due: mess_bill2_due.toFixed(2),
                    total_fee: total_fee.toFixed(2),
                    total_paid: total_paid.toFixed(2),
                    total_due: (total_fee - total_paid).toFixed(2),
                    status
                };
            });

        // Calculate totals
        const total_paid = feeSummary.reduce((sum, f) => sum + parseFloat(f.total_paid), 0);
        const total_fee = feeSummary.reduce((sum, f) => sum + parseFloat(f.total_fee), 0);
        const remaining_due = total_fee - total_paid;

        res.render('student/viewfees', { 
            student, 
            feeSummary, 
            total_paid: total_paid.toFixed(2), 
            remaining_due: remaining_due.toFixed(2),
            receipts
        });

    } catch (err) {
        console.error("❌ Error loading fee details:", err);
        res.status(500).send("Error loading fee details.");
    }
});


app.post("/student/upload-aadhaar", upload.fields([
  { name: "student_aadhaar", maxCount: 1 },
  { name: "father_aadhaar", maxCount: 1 }
]), async (req, res) => {
  if (!req.session.user || req.session.role !== "student")
    return res.status(403).send("Unauthorized");

  const studentId = req.session.user.student_id;
  const studentFile = req.files["student_aadhaar"] ? req.files["student_aadhaar"][0].filename : null;
  const fatherFile = req.files["father_aadhaar"] ? req.files["father_aadhaar"][0].filename : null;

  await db.promise().query(
    "UPDATE students SET student_aadhaar=COALESCE(?, student_aadhaar), father_aadhaar=COALESCE(?, father_aadhaar) WHERE student_id=?",
    [studentFile, fatherFile, studentId]
  );

  res.redirect("/student/profile");
});
app.get("/student/aadhaar/:type/:studentId", async (req, res) => {
  const { type, studentId } = req.params;
  const user = req.session.user;

  // Only student self, warden, admin
  if (!user || (user.role === "student" && user.student_id !== studentId) && user.role !== "warden" && user.role !== "admin")
    return res.status(403).send("Unauthorized");

  const [[student]] = await db.promise().query(
    "SELECT student_aadhaar, father_aadhaar FROM students WHERE student_id=?",
    [studentId]
  );

  if (!student) return res.status(404).send("Student not found");

  const fileName = type === "student" ? student.student_aadhaar : student.father_aadhaar;
  if (!fileName) return res.status(404).send("File not uploaded");

  res.sendFile(path.join(__dirname, "uploads/adhaar", fileName));
});

app.post("/student/upload-profile", upload.single("profile_image"), async (req, res) => {
  if (!req.session.user || req.session.role !== "student") return res.redirect("/login/student");

  try {
    const student_id = req.session.user.student_id;
    const filename = req.file.filename;

    // Save filename in DB
    await db.promise().query(
      "UPDATE students SET profile_image=? WHERE student_id=?",
      [filename, student_id]
    );

    // Update session
    const [studentRows] = await db.promise().query(
      "SELECT * FROM students WHERE student_id=?",
      [student_id]
    );
    req.session.user = studentRows[0];

    res.redirect("/student/profile");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error uploading profile image");
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
    let { student_unique_id, ref_id, amount_paid, year, remarks } = req.body;

    if (!student_unique_id || !ref_id || !amount_paid || !year || !remarks)
      return res.send("⚠️ Please fill all required fields.");

    student_unique_id = student_unique_id.trim().toUpperCase().replace(/\s+/g, "_");
    ref_id = ref_id.trim();
    amount_paid = parseFloat(amount_paid);
    year = parseInt(year);

    // Validate student exists
    const [[student]] = await db.promise().query(
      "SELECT * FROM students WHERE student_id = ?",
      [student_id]
    );
    if (!student) return res.send("❌ Student not found.");

    if (!req.file) return res.send("❌ No PDF uploaded.");

    // 🔥🔥 FIX #1: SAVE ALL RECEIPTS INTO uploads/receipts/
    const pdf_path = `uploads/receipts/${req.file.filename}`;

    conn = await db.promise().getConnection();
    await conn.beginTransaction();

    // Check SBI transactions
    const [[txn]] = await conn.query(
      `SELECT * FROM sbi_transactions 
       WHERE TRIM(ref_id)=? 
         AND CAST(amount AS DECIMAL)=? 
         AND status='Pending'`,
      [ref_id, amount_paid]
    );

    // Save receipt as Pending if no matching SBI txn
    let status = txn ? 'Verified' : 'Pending';

    await conn.query(
      `INSERT INTO fee_receipts
       (student_id, student_unique_id, ref_id, amount_paid, pdf_path, year, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
      [student_id, student_unique_id, ref_id, amount_paid, pdf_path, year, status]
    );

    // If verified, update related fee fields
    if (status === 'Verified') {
      let colToUpdate;

      switch (remarks.toLowerCase()) {
        case 'room rent': colToUpdate = 'room_rent_paid'; break;
        case 'mess bill1': colToUpdate = 'mess_bill1_paid'; break;
        case 'mess bill2': colToUpdate = 'mess_bill2_paid'; break;
        default: colToUpdate = null;
      }

      if (colToUpdate) {
        await conn.query(
          `UPDATE students SET 
             ${colToUpdate} = IFNULL(${colToUpdate},0) + ?,
             total_paid = IFNULL(total_paid,0) + ?,
             remaining_fee = total_fee - (IFNULL(total_paid,0) + ?) 
           WHERE student_id = ?`,
          [amount_paid, amount_paid, amount_paid, student_id]
        );
      }

      // Mark SBI txn as verified
      await conn.query("UPDATE sbi_transactions SET status='Verified' WHERE ref_id=?", [ref_id]);
    }

    await conn.commit();

    res.send(`
      ${status === 'Verified' ? '✅ Receipt verified successfully' : '⚠️ Receipt uploaded pending verification'}<br>
      <b>Academic Year:</b> ${year}<br>
      <b>Amount Paid:</b> ₹${amount_paid.toFixed(2)}<br>
      <b>Component Updated:</b> ${remarks}
    `);

  } catch (err) {
    if (conn) await conn.rollback();
    console.error("❌ Error verifying student receipt:", err);
    res.status(500).send("Error verifying receipt: " + err.message);
  } finally {
    if (conn) conn.release();
  }
});
app.get('/warden/acceptedReceipts', async (req, res) => {
  if (req.session.role !== 'admin') return res.redirect('/choose_login');

  try {
    // fetch receipts whose status is 'Verified' or 'Accepted'
    const [accepted] = await db.promise().query(`
      SELECT fr.*, s.name, s.student_unique_id
      FROM fee_receipts fr
      JOIN students s ON fr.student_id = s.student_id
      WHERE fr.status IN ('Verified', 'Accepted')
      ORDER BY fr.verified_at DESC
    `);

    res.render('warden/acceptedReceipts', { accepted });
  } catch (err) {
    console.error("Error fetching accepted receipts:", err);
    res.status(500).send("Database error: " + err.message);
  }
});

app.get("/viewReceipts", async (req, res) => {
  try {
    const [receipts] = await db.promise().query(
      `SELECT fr.*, s.name, s.course, s.year, s.room_no 
       FROM fee_receipts fr
       JOIN students s ON s.student_id = fr.student_id
       ORDER BY fr.created_at DESC`
    );

    res.render("admin/viewReceipts", { receipts });

  } catch (err) {
    console.error("Error loading receipts:", err);
    res.status(500).send("Error loading receipts");
  }
});
app.get("/receipt/download/:receipt_id", async (req, res) => {
  try {
    const receiptId = req.params.receipt_id;

    const [rows] = await db.promise().query(
      "SELECT pdf_path FROM fee_receipts WHERE receipt_id = ?",
      [receiptId]
    );

    if (!rows.length) {
      console.error("❌ Receipt not found");
      return res.status(404).send("Receipt not found");
    }

    const relativePath = rows[0].pdf_path; 
    const fullPath = path.join(__dirname, relativePath);

    console.log("Downloading file:", fullPath);

    res.download(fullPath, (err) => {
      if (err) {
        console.error("Download error:", err);
        res.status(404).send("File not found");
      }
    });

  } catch (err) {
    console.error("Server error:", err);
    res.status(500).send("Server error");
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
// ==============================
// ADMIN — VIEW ALL PAID RECEIPTS
// ==============================
app.get("/admin/viewReceipts", async (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "admin") {
      return res.redirect("/choose_login");
    }

    const [receipts] = await db.promise().query(`
      SELECT fr.*, s.name, s.course, s.year, s.room_no
      FROM fee_receipts fr
      JOIN students s ON fr.student_id = s.student_id
      ORDER BY fr.created_at DESC
    `);

    res.render("admin/viewReceipts", { receipts });
  } catch (err) {
    console.error("ERROR loading paid receipts:", err);
    res.status(500).send("Server Error");
  }
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
// GET - View all complaints submitted by the logged-in student
app.get('/student/viewComplaints', (req, res) => {
    if (!req.session.user || req.session.role !== 'student') {
        return res.redirect('/choose_login');
    }

    const student_id = req.session.user.student_id;

    const sql = `SELECT * FROM complaints 
                 WHERE student_id = ? 
                 ORDER BY created_at DESC`;

    db.query(sql, [student_id], (err, results) => {
        if (err) {
            console.error("Error fetching complaints:", err);
            return res.status(500).send("Database error");
        }

        res.render('student/viewComplaints', { complaints: results });
    });
});
// POST - Submit a complaint
app.post('/student/complaint', (req, res) => {
    if (!req.session.user || req.session.role !== 'student') {
        return res.redirect('/choose_login');
    }

    const student_id = req.session.user.student_id;
    const { subject, description } = req.body;

    const sql = `INSERT INTO complaints (student_id, subject, description, status, created_at)
                 VALUES (?, ?, ?, 'Pending', NOW())`;

    db.query(sql, [student_id, subject, description], (err, result) => {
        if (err) {
            console.error("Error submitting complaint:", err);
            return res.status(500).send("Database error");
        }

        res.redirect('/student/viewComplaints');
    });
});

// ============================================
// ✅ STUDENT - VIEW ATTENDANCE
// ============================================
app.get("/student/viewattendance", async (req, res) => {
  if (!req.session.user || req.session.role !== "student") {
    return res.redirect("/login/student");
  }

  const student_id = req.session.user.student_id;

  try {
    // Fetch attendance data for the logged-in student
    const [attendance] = await db.promise().query(
      `SELECT date, period, status 
       FROM attendance 
       WHERE student_id = ?
       ORDER BY date DESC`,
      [student_id]
    );

    // Render your existing EJS page
    res.render("student/viewattendance", { attendance });
  } catch (err) {
    console.error("❌ Error fetching attendance:", err);
    res.status(500).send("Error loading attendance records.");
  }
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

app.get("/warden/login", (req, res) => {
  res.render("login_warden"); // make sure you have views/login_warden.ejs
});

// Warden login
app.post("/login/warden", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM wardens WHERE email=?", [email], (err, rows) => {
    if (err) return res.send("DB Error");
    if (!rows.length) return res.send("Invalid Credentials");

    const wardenData = rows[0];

    bcrypt.compare(password, wardenData.password).then((match) => {
      if (!match) return res.send("Invalid Credentials");

      // ✅ Save all session info correctly
      req.session.user = wardenData;
      req.session.role = "warden";
      req.session.warden = wardenData; // <---- ADD THIS LINE
      req.session.warden_id = wardenData.warden_id;
      req.session.warden_name = wardenData.name;

      res.redirect("/warden/dashboard");
    });
  });
});


app.get("/warden/dashboard", async (req, res) => {
  if (req.session.role !== "warden") return res.redirect("/login/warden");

  const wardenName = req.session.warden_name;

  try {
    // ✅ Count today's approved outpasses by this warden
    const [approvedToday] = await db.promise().query(
      `SELECT COUNT(*) AS count 
       FROM outpasses 
       WHERE status = 'Approved' 
         AND accepted_by = ? 
         AND DATE(approved_at) = CURDATE()`,
      [wardenName]
    );

    // ✅ Fetch students whose outpasses were approved by this warden
    const [studentsWithOutpass] = await db.promise().query(
      `SELECT s.student_id, s.name, o.status, o.approved_at
       FROM students s
       JOIN outpasses o ON s.student_id = o.student_id
       WHERE o.accepted_by = ?
       ORDER BY o.approved_at DESC`,
      [wardenName]
    );

    // ✅ Render the warden dashboard
    res.render("warden/dashboard", {
      user: req.session.user,
      students: studentsWithOutpass,
      approvedCount: approvedToday[0]?.count || 0,
      session: req.session
    });

  } catch (err) {
    console.error("❌ Error loading warden dashboard:", err);
    res.status(500).send("Error loading dashboard");
  }
});


// Step 1: Select room and year
// Example route
app.get('/warden/markAttendance', async (req, res) => {
  try {
    const blocks = ["Old Block", "New Block", "Main Block", "Aminities", "GYM"];
    const roomsByBlock = {};

    // Fetch available rooms per block
    for (let block of blocks) {
      const [rows] = await db.promise().query(
        "SELECT DISTINCT room_no FROM students WHERE block = ? ORDER BY room_no ASC",
        [block]
      );
      roomsByBlock[block] = rows.map(r => r.room_no);
    }

    // Filters
    const selectedBlock = req.query.block || '';
    const selectedYear = req.query.year || '';
    const selectedRoom = req.query.room_no || '';
    const rooms = selectedBlock ? roomsByBlock[selectedBlock] : [];

    let students = [];

    // Only fetch if all filters are chosen
    if (selectedBlock && selectedYear && selectedRoom) {
      const today = new Date().toISOString().split("T")[0];

      const [rows] = await db.promise().query(`
        SELECT 
          s.student_id,
          s.student_unique_id,
          s.name,
          s.room_no,
          s.block,
          s.year,
          s.course,
          IFNULL(s.total_fee, 0) AS total_fee,
          IFNULL(s.total_paid, 0) AS total_paid,
          IFNULL(SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END), 0) AS present_count,
          COUNT(a.student_id) AS total_classes,
          CASE 
            WHEN EXISTS (
              SELECT 1 FROM outpasses o
              WHERE o.student_id = s.student_id
                AND o.status = 'Approved'
                AND ? BETWEEN o.out_date AND o.return_date
            ) THEN 'On Leave'
            ELSE 'Available'
          END AS leave_status
        FROM students s
        LEFT JOIN attendance a ON s.student_id = a.student_id
        WHERE s.block = ? AND s.year = ? AND s.room_no = ?
        GROUP BY s.student_id
        ORDER BY s.name ASC
      `, [today, selectedBlock, selectedYear, selectedRoom]);

      // ✅ Wrap attendance & fee safely to prevent undefined access in EJS
      students = rows.map(stu => ({
        ...stu,
        attendanceSummary: {
          total_classes: stu.total_classes || 0,
          present_count: stu.present_count || 0
        },
        feeSummary: {
          total_fee: stu.total_fee || 0,
          total_paid: stu.total_paid || 0
        }
      }));
    }

    // Render page
    res.render('warden/markAttendance', {
      blocks,
      block: selectedBlock,
      year: selectedYear,
      room_no: selectedRoom,
      roomsByBlock,
      rooms,
      students
    });

  } catch (err) {
    console.error("Error fetching attendance:", err);
    res.status(500).send("Server Error");
  }
});




app.post("/warden/selectRoom", async (req, res) => {
  try {
    const { year, room_no } = req.body;
    console.log("[selectRoom] received year:", year, "room_no:", room_no);

    // ✅ Get only students from selected year & room
    const [students] = await db.promise().query(
      "SELECT * FROM students WHERE year = ? AND room_no = ?",
      [year, room_no]
    );

    console.log("[selectRoom] SQL returned rows:", students.length);

    // For each student, add current-year fee and attendance summary
    for (const stu of students) {
      // Fee for their current year only
      const [feeRows] = await db.promise().query(`
        SELECT 
          yf.year AS year,
          yf.amount AS total_fee,
          IFNULL(SUM(fr.amount_paid), 0) AS verified_paid
        FROM yearly_fee yf
        LEFT JOIN fee_receipts fr 
          ON yf.year = fr.year
          AND fr.student_id = ?
          AND UPPER(fr.status) = 'VERIFIED'
        WHERE yf.year = ?
        GROUP BY yf.year, yf.amount
      `, [stu.student_id, stu.year]);
      stu.feeSummary = feeRows[0] || { total_fee: 0, verified_paid: 0 };

      // Attendance summary
      const [attRows] = await db.promise().query(`
        SELECT COUNT(*) AS total_classes,
               SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) AS present_count
        FROM attendance
        WHERE student_id = ?
      `, [stu.student_id]);
      stu.attendanceSummary = attRows[0] || { total_classes: 0, present_count: 0 };
    }

    // ✅ Render one page containing both attendance form + student info
    res.render("warden/markAttendance", {
      students,
      room_no,
      year,
    });

  } catch (err) {
    console.error("❌ Error in selectRoom route:", err);
    res.status(500).send("Error loading students: " + err.message);
  }
});


app.post("/mark-attendance", async (req, res) => {
  const { student_id, date, status } = req.body; // no period needed for one-per-day

  try {
    // ✅ Check if already marked for that day
    const [existing] = await db.promise().query(
      "SELECT * FROM attendance WHERE student_id = ? AND date = ?",
      [student_id, date]
    );

    if (existing.length > 0) {
      // Update the existing record instead of inserting again
      await db.promise().query(
        "UPDATE attendance SET status = ? WHERE student_id = ? AND date = ?",
        [status, student_id, date]
      );
      console.log("🟡 Attendance updated for", student_id, date);
    } else {
      // Insert new record
      await db.promise().query(
        "INSERT INTO attendance (student_id, date, status) VALUES (?, ?, ?)",
        [student_id, date, status]
      );
      console.log("✅ Attendance marked for", student_id, date);
    }

    res.redirect("/faculty/attendance"); // or wherever your redirect is
  } catch (err) {
    console.error("❌ Error marking attendance:", err);
    res.status(500).send("Error marking attendance");
  }
});

// Step 2: Submit attendance
app.post("/warden/submitAttendance", async (req, res) => {
  // Check if logged in
  if (!req.session.warden) {
    return res.redirect("/warden/dashboard"); // ✅ fixed path
  }

  const date = new Date().toISOString().split("T")[0];
  const { year, room_no } = req.body;
  const marked_by = req.session.warden.warden_id; // ✅ correct key

  const attendanceData = [];

  for (let key in req.body) {
    if (key.startsWith("attendance_")) {
      const student_id = key.split("_")[1];
      const status = req.body[key];
      attendanceData.push([student_id, date, room_no, status, marked_by]);
    }
  }

  if (!attendanceData.length) return res.send("⚠️ No attendance marked.");

  await db.promise().query(
    "INSERT INTO attendance (student_id, date, period, status, marked_by, created_at) VALUES ?",
    [attendanceData.map(d => [d[0], date, room_no, d[3], marked_by, new Date()])]
  );

  res.redirect("/warden/markAttendance");
});


// View all complaints
app.get('/warden/complaints', (req, res) => {
  const query = `
    SELECT 
      c.complaint_id, 
      c.student_id, 
      s.name AS student_name, 
      s.room_no,
      c.subject, 
      c.description, 
      c.reply, 
      c.status, 
      c.created_at, 
      c.updated_at
    FROM complaints c
    JOIN students s ON c.student_id = s.student_id
    ORDER BY c.created_at DESC;
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching complaints:", err);
      return res.status(500).send("Server error while fetching complaints.");
    }

    // Pass messages as empty object if none
    res.render('warden/complaints', { complaints: results, messages: {} });
  });
});


// Reply to complaint
app.post('/warden/complaints/:id/reply', (req, res) => {
    if (!req.session.user || req.session.role !== 'warden') return res.redirect('/login/warden');

    const complaint_id = req.params.id;
    const { reply, status } = req.body; // status can be 'Replied' or 'Resolved'

    db.query(
        "UPDATE complaints SET reply = ?, status = ? WHERE complaint_id = ?",
        [reply, status, complaint_id],
        (err) => {
            if (err) return res.send("Error replying to complaint: " + err);
            res.redirect('/warden/complaints');
        }
    );
});


// Show all outpasses pending approval
// Show all outpasses pending approval
app.get("/warden/approveOutpass", (req, res) => {
  if (req.session.role !== "warden") return res.redirect("/login/warden");

  const query = `
    SELECT o.*, s.name AS student_name, s.room_no 
    FROM outpasses o
    JOIN students s ON o.student_id = s.student_id
    WHERE o.status='Pending'
    ORDER BY o.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) return res.send("Error fetching outpasses: " + err);
    res.render("warden/approveOutpass", { outpasses: results, session: req.session });
  });
});


app.post("/warden/approveOutpass/:id/:action", (req, res) => {
  const { id, action } = req.params;

  const status = action === "approve" ? "Approved" : "Rejected";

  // Warden info
  const acceptedBy = req.session.warden_name || "Unknown Warden";
  const approvedAt = new Date();

  // 1️⃣ Update outpass status
 // 1️⃣ Update outpass status
const updateQuery = `
  UPDATE outpasses
  SET status = ?, accepted_by = ?, approved_at = ?
  WHERE outpass_id = ?
`;

db.query(updateQuery, [status, acceptedBy, approvedAt, id], (err) => {
  if (err) {
    console.error("Outpass Update Error:", err);
    return res.send("Error updating outpass: " + err);
  }

  // 2️⃣ Fetch student email + details
  const fetchQuery = `
    SELECT s.email, s.name, o.out_date, o.return_date, o.reason
    FROM outpasses o
    JOIN students s ON o.student_id = s.student_id
    WHERE o.outpass_id = ?
  `;

  db.query(fetchQuery, [id], (err2, results) => {
    if (err2 || results.length === 0) {
      console.log("Email fetch error:", err2);
      return res.redirect("/warden/approveOutpass");
    }

    const student = results[0];

    // 3️⃣ Prepare Email
    const subject =
      status === "Approved"
        ? "Outpass Approved - Hostel Management"
        : "Outpass Rejected - Hostel Management";

    const message =
      status === "Approved"
        ? `Hello ${student.name},

Your outpass request has been *approved*.

📅 Out Date: ${student.out_date}
📅 Return Date: ${student.return_date}
📝 Reason: ${student.reason}

Please follow hostel rules during your outing.

Regards,
Hostel Warden`
        : `Hello ${student.name},

Your outpass request has been *rejected*.

📝 Reason Provided: ${student.reason}

If you need clarification, kindly meet the warden.

Regards,
Hostel Warden`;

    // 4️⃣ Send Email
    transporter.sendMail(
      {
        from: "harshavardhanvangara@gmail.com",
        to: student.email,
        subject: subject,
        text: message
      },
      (mailErr, info) => {
        if (mailErr) {
          console.log("Email Send Error:", mailErr);
        } else {
          console.log("Email sent:", info.response);
        }

        return res.redirect("/warden/approveOutpass");
      }
    );
  });
});
});



app.get("/warden/emergencyOutpasses", (req, res) => {
  if (req.session.role !== "warden") return res.redirect("/login/warden");

  const query = `
    SELECT o.*, s.name AS student_name, s.room_no 
    FROM outpasses o
    JOIN students s ON o.student_id = s.student_id
    WHERE o.status='Pending' AND o.outpass_type='Emergency'
    ORDER BY o.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) return res.send("Error fetching emergency outpasses: " + err);
    res.render("warden/approveOutpass", { outpasses: results, session: req.session });
  });
});


// ==================== WARDEN UPLOAD STUDENTS ====================

// ============================================
// ✅ WARDEN: UPLOAD STUDENTS PAGE
// ============================================
app.get("/warden/upload-students", (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "warden") {
      return res.redirect("/choose_login");
    }

    res.render("warden/upload-students");
  } catch (err) {
    console.error("❌ Error loading upload_students page:", err);
    res.status(500).send("Error loading upload_students page");
  }
});

app.post("/warden/upload-students", upload.single("studentsFile"), async (req, res) => {
  try {
    if (!req.file) {
      return res.render("warden/upload-students", {
        success: null,
        error: "⚠️ Please select a file."
      });
    }

    const workbook = xlsx.readFile(req.file.path);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];

    // Read sheet with empty cells
    let data = xlsx.utils.sheet_to_json(sheet, { defval: "" });

    // Skip heading rows
    data = data.slice(4);

    // ---------- CLEANING FUNCTIONS ----------
    function clean(val) {
      if (!val) return "";
      return val.toString().trim();
    }

    function cleanRoom(val) {
      if (!val) return "";
      return val.toString().trim().replace(/\s+/g, "");
    }

    function cleanStudentId(val) {
      if (!val) return "";
      return val
        .toString()
        .trim()
        .split(/[\s\n]+/)[0]   // Only first reg
        .trim();
    }

    // 🚀 FIXED: PERFECT COURSE HANDLING
    function normalizeCourse(c) {
      if (!c) return "";

      let text = c.toString().toUpperCase().trim();

      // Remove BTECH / B.TECH / B-TECH / B TECH / BTECH(CSE)
      text = text.replace(/B[\.\-\s]*TECH[\s\-\.\(\)]*/g, "");
      text = text.replace(/B[\.\-\s]*T[\.\-\s]*/g, "");

      // Remove extra symbols
      text = text.replace(/[\.\-\(\)]/g, "");
      text = text.replace(/\s+/g, "");

      const map = {
        "CSE": "CSE",
        "CS": "CSE",
        "CSC": "CSC",
        "CSD": "CSD",
        "CYS": "CYS",
        "AI&DS": "AIDS",
        "AIDS": "AIDS",

        "ECE": "ECE",
        "EEE": "EEE",

        "ME": "MECH",
        "MECH": "MECH",

        "CIVIL": "CIVIL"
      };

      // exact match
      if (map[text]) return map[text];

      // contains match
      for (let key in map) {
        if (text.includes(key)) return map[key];
      }

      return text;
    }

    function normalizeBlock(b) {
      if (!b) return "";
      const block = b.toString().replace(/\s+/g, "").toUpperCase();

      if (block.includes("OLD")) return "Old Block";
      if (block.includes("NEW")) return "New Block";
      if (block.includes("MAIN")) return "Main Block";
      if (block.includes("AMEN")) return "Amenities";
      if (block.includes("GYM")) return "GYM Block";

      return "";
    }

    function romanToNumber(roman) {
      if (!roman) return null;
      const map = { I: 1, II: 2, III: 3, IV: 4 };
      return map[roman.trim().toUpperCase()] || null;
    }

    // -------- ROOM/BLOCK INHERIT FIX ----------
    let lastRoom = "";
    let lastBlock = "";

    let insertedCount = 0;

    for (const row of data) {
      let room_no = cleanRoom(row["__EMPTY_1"]);
      const name  = clean(row["__EMPTY_2"]);
      const student_id = cleanStudentId(row["__EMPTY_3"]);
      const course = normalizeCourse(row["__EMPTY_4"] || "");
      const year = romanToNumber(clean(row["__EMPTY_5"]));
      let block = normalizeBlock(row["__EMPTY_6"]);
      const student_mobile = clean(row["__EMPTY_7"]);
      const father_mobile  = clean(row["__EMPTY_8"]);

      // inherit room, block
      if (!room_no && lastRoom) room_no = lastRoom;
      if (!block && lastBlock) block = lastBlock;

      if (room_no) lastRoom = room_no;
      if (block)   lastBlock = block;

      if (!student_id || !name) continue;

      const email = `${student_id}@gmail.com`;
      const uniqueId = student_id;

      const joinYear = 2000 + parseInt(student_id.substring(0, 2));

      // Generate hostel_id
      const [rows] = await db.promise().query(
        "SELECT hostel_id FROM students WHERE hostel_id LIKE ? ORDER BY hostel_id DESC LIMIT 1",
        [`${joinYear}%`]
      );

      let newHostelId;
      if (rows.length > 0 && rows[0].hostel_id) {
        const lastSeq = parseInt(rows[0].hostel_id.substring(4));
        newHostelId = joinYear + String(lastSeq + 1).padStart(6, "0");
      } else {
        newHostelId = joinYear + "000001";
      }

      const hashedPassword = bcrypt.hashSync(student_id.toString(), 10);

      // INSERT
      await db.promise().query(
        `INSERT INTO students 
          (student_id, student_unique_id, name, email, password, hostel_id, 
           room_no, course, year, block, student_mobile, father_mobile, year_of_join)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE 
           name = VALUES(name), 
           course = VALUES(course), 
           year = VALUES(year), 
           room_no = VALUES(room_no),
           block = VALUES(block), 
           student_mobile = VALUES(student_mobile),
           father_mobile = VALUES(father_mobile)`,
        [
          student_id, uniqueId, name, email, hashedPassword,
          newHostelId, room_no, course, year, block,
          student_mobile, father_mobile, joinYear
        ]
      );

      insertedCount++;
    }

    res.render("warden/upload-students", {
      success: `✅ ${insertedCount} students uploaded successfully!`,
      error: null
    });

  } catch (err) {
    console.error("UPLOAD ERROR:", err);
    res.render("warden/upload-students", {
      success: null,
      error: "❌ Error while uploading file."
    });
  }
});

app.get("/warden/upload_results", (req, res) => {
  const messages = {};

  if (req.query.success) {
    messages.success = "✅ Results uploaded and processed successfully!";
  }
  if (req.query.error) {
    messages.error = "❌ Something went wrong while uploading results.";
  }

  res.render("warden/upload_results", { messages });
});


app.post("/warden/upload_results", async (req, res) => {
  try {
    if (!req.files || !req.files.result_pdf) {
      return res.send("❌ No PDF uploaded");
    }

    const { year, semester } = req.body;
    const file = req.files.result_pdf;
    const folderPath = path.join(__dirname, "uploads", "results");

    if (!fs.existsSync(folderPath)) fs.mkdirSync(folderPath, { recursive: true });

    const filePath = path.join(folderPath, Date.now() + "-" + file.name.replace(/\s+/g, "_"));
    await file.mv(filePath);

    // Save PDF info in DB
    await db.promise().query(
      "INSERT INTO results_pdf (file_path, year, semester, uploaded_by) VALUES (?, ?, ?, ?)",
      [filePath.replace(__dirname + "/", ""), year, semester, "warden"]
    );

    // Parse PDF content
    const pdfBuffer = fs.readFileSync(filePath);
    const data = await pdfParse(pdfBuffer);
    const text = data.text;

    const regex = /Reg\.No:\s*(\S+).*?Subjects\s*Failed:\s*(\d+)/gs;
    let match;

    while ((match = regex.exec(text)) !== null) {
      const regNo = match[1].trim();
      const backlogs = parseInt(match[2]);
      const status = backlogs > 0 ? "Failed" : "Passed";

      const [studentRows] = await db.promise().query(
        "SELECT student_id FROM students WHERE student_unique_id = ?",
        [regNo]
      );

      if (studentRows.length > 0) {
        const student_id = studentRows[0].student_id;

        const [exists] = await db.promise().query(
          "SELECT id FROM student_results WHERE student_id = ? AND year = ? AND semester = ?",
          [student_id, year, semester]
        );

        if (exists.length > 0) {
          await db.promise().query(
            "UPDATE student_results SET total_backlogs=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE student_id=? AND year=? AND semester=?",
            [backlogs, status, student_id, year, semester]
          );
        } else {
          await db.promise().query(
            "INSERT INTO student_results (student_id, reg_no, year, semester, total_backlogs, status) VALUES (?, ?, ?, ?, ?, ?)",
            [student_id, regNo, year, semester, backlogs, status]
          );
        }

        await db.promise().query(
          `UPDATE students 
           SET remaining_backlogs = (
             SELECT IFNULL(SUM(total_backlogs), 0)
             FROM student_results
             WHERE student_id = ? AND status='Failed'
           )
           WHERE student_id = ?`,
          [student_id, student_id]
        );
      }
    }

    res.redirect("/warden/upload_results?success=1");
  } catch (err) {
    console.error("❌ Error uploading results:", err);
    res.status(500).send("Error processing results PDF");
  }
});


app.get("/warden/uploadMessBill", (req, res) => {
  res.render("warden/uploadMessBill");
});

app.post("/warden/uploadMessBill", upload.single("mess_bill_pdf"), async (req, res) => {
  try {
    const pdfBuffer = fs.readFileSync(req.file.path);
    const data = await pdfParse(pdfBuffer);
    const text = data.text.trim();

    const lines = text.split("\n").map(l => l.trim()).filter(l => l);
    const month = new Date().toLocaleString("default", { month: "long", year: "numeric" });
    const uploadedBy = req.session?.warden?.name || "Admin";

    for (const line of lines) {
      // Expected line: "205 Harsha STU123 3200"
      const parts = line.split(/\s+/);
      if (parts.length < 3) continue;

      let room_no, name, student_id, amount;

      if (!isNaN(parts[0])) room_no = parts[0];
      name = parts[1];
      amount = parseFloat(parts[parts.length - 1]);
      student_id = parts.find(p => p.startsWith("STU")) || null;

      // Find matching student
      const [rows] = await db.promise().query(
        "SELECT * FROM students WHERE student_id = ? OR (room_no = ? AND name = ?)",
        [student_id, room_no, name]
      );

      if (rows.length > 0) {
        const s = rows[0];

        // Insert or update in mess_bills
        await db.promise().query(
          "INSERT INTO mess_bills (student_id, month, amount, uploaded_by) VALUES (?, ?, ?, ?)",
          [s.student_id, month, amount, uploadedBy]
        );

        // Update student's current mess bill
        await db.promise().query(
          "UPDATE students SET current_mess_bill = ? WHERE student_id = ?",
          [amount, s.student_id]
        );
      }
    }

    res.send("✅ Mess Bill uploaded and updated successfully!");
  } catch (err) {
    console.error(err);
    res.status(500).send("❌ Error reading PDF: " + err.message);
  }
});

app.get("/warden/eligibility", async (req, res) => {
  try {
    const [students] = await db.promise().query(`
      SELECT student_id, student_unique_id, name, year, remaining_backlogs,
        CASE
          WHEN remaining_backlogs <= 3 THEN 'Eligible'
          ELSE 'Not Eligible'
        END AS room_status
      FROM students
    `);

    res.render("warden/eligibility", { students });
  } catch (err) {
    console.error("❌ Eligibility Error:", err);
    res.status(500).send("Database error loading eligibility");
  }
});


// Show Students list
// 🔹 View all students (with optional search)
app.get("/warden/viewStudents", async (req, res) => {
  if (!req.session.user || req.session.role !== "warden") {
    return res.redirect("/choose_login");
  }

  try {
    const search = req.query.search ? `%${req.query.search}%` : "%%";
   const [students] = await db.promise().query(
  `SELECT student_id, name, email, room_no, course, year, total_fee, total_paid, remaining_fee, profile_image
   FROM students
   WHERE name LIKE ? OR student_id LIKE ? OR room_no LIKE ?`,
  [search, search, search]
);


    res.render("warden/viewStudents", {
      students,
      search: req.query.search || "",
      session: req.session
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error fetching students: " + err.message);
  }
});


app.post("/warden/markAttendance", (req, res) => {
  const data = req.body;  // all inputs
  const date = new Date();
   // or pick from form
   const formattedDate = date.toISOString().slice(0, 19).replace('T', ' '); 
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
app.get('/admin/complaints', (req, res) => {
  if (!req.session.user || req.session.role !== 'admin') {
    return res.redirect('/login/admin');
  }

  const query = "SELECT * FROM complaints ORDER BY complaint_id DESC";
  db.query(query, (err, results) => {
    if (err) return res.send("Error fetching complaints: " + err);
    res.render('admin/admin_complaints', { complaints: results });
  });
});

app.post('/admin/complaints/:id/reply', (req, res) => {
  if (!req.session.user || req.session.role !== 'admin')
    return res.redirect('/login/admin');

  const complaint_id = req.params.id;
  const { reply, status } = req.body;

  db.query(
    "UPDATE complaints SET reply = ?, status = ? WHERE complaint_id = ?",
    [reply, status, complaint_id],
    (err) => {
      if (err) return res.send("Error replying to complaint: " + err);
      // ✅ Use absolute path here
      res.redirect('/admin/admin_complaints');
    }
  );
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
app.get("/warden/student/:student_id", async (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "warden") {
      return res.redirect("/choose_login");
    }

    const student_id = req.params.student_id;

    // 1️⃣ Fetch student info
    const [studentRows] = await db.promise().query(
  `SELECT student_id, student_unique_id, name, email, room_no, course, year, 
          total_paid, total_fee, remaining_fee, year_of_join,
          student_aadhaar, father_aadhaar
   FROM students WHERE student_id = ?`,
  [student_id]
);

    if (!studentRows.length) return res.send("❌ Student not found.");
    const student = studentRows[0];
    const studentYear = parseInt(student.year);

    // 2️⃣ Fetch yearly fee components & payments
    const [rows] = await db.promise().query(
      `
      SELECT 
          CAST(yf.year AS UNSIGNED) AS academic_year,
          yf.room_rent, yf.mess_bill1, yf.mess_bill2,
          (yf.room_rent + yf.mess_bill1 + yf.mess_bill2) AS total_fee,
          IFNULL(SUM(fr.amount_paid), 0) AS paid_amount
      FROM yearly_fee yf
      LEFT JOIN fee_receipts fr 
          ON CAST(yf.year AS UNSIGNED) = CAST(fr.year AS UNSIGNED)
          AND fr.student_id = ?
      WHERE CAST(yf.year AS UNSIGNED) <= ?
      GROUP BY yf.year, yf.room_rent, yf.mess_bill1, yf.mess_bill2
      ORDER BY yf.year ASC
      `,
      [student_id, studentYear]
    );

    // 3️⃣ Build fee summary
    const feeSummary = rows.map(row => {
      const roomRent = parseFloat(row.room_rent || 0);
      const mess1 = parseFloat(row.mess_bill1 || 0);
      const mess2 = parseFloat(row.mess_bill2 || 0);
      const totalFee = parseFloat(row.total_fee || 0);
      const paid = parseFloat(row.paid_amount || 0);
      const due = Math.max(totalFee - paid, 0);

      return {
        academic_year: row.academic_year,
        room_rent: roomRent.toFixed(2),
        mess_bill1: mess1.toFixed(2),
        mess_bill2: mess2.toFixed(2),
        total_fee: totalFee.toFixed(2),
        paid_amount: paid.toFixed(2),
        due_amount: due.toFixed(2),
      };
    });

    // 4️⃣ Recalculate totals for student
    const totalPaid = feeSummary.reduce((s, f) => s + parseFloat(f.paid_amount), 0);
    const totalFee = feeSummary.reduce((s, f) => s + parseFloat(f.total_fee), 0);
    const remainingFee = Math.max(totalFee - totalPaid, 0);

    // 5️⃣ Attendance summary
    const [attendanceRows] = await db.promise().query(
      `SELECT COUNT(*) AS total_classes,
              SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) AS present_count
       FROM attendance WHERE student_id = ?`,
      [student_id]
    );
    const attendanceSummary = attendanceRows[0] || { total_classes: 0, present_count: 0 };

    // 6️⃣ Render profile page
    res.render("warden/student_profile", {
      student,
      feeSummary,
      totalPaid,
      remainingFee,
      attendanceSummary
    });

  } catch (err) {
    console.error("❌ Error fetching student profile:", err);
    res.status(500).send("Error fetching student profile: " + err.message);
  }
});


// ✅ WARDEN VIEW STUDENT PROFILE (FINAL FIX)
app.get("/warden/room/:room_no", async (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "warden") {
      return res.redirect("/choose_login");
    }

    const { room_no } = req.params;

    // 1️⃣ Get all students in that room
    const [students] = await db.promise().query(
      `SELECT student_id, student_unique_id, name, email, course, year, 
              total_paid, total_fee, remaining_fee, year_of_join
       FROM students 
       WHERE room_no = ? 
       ORDER BY name ASC`,
      [room_no]
    );

    if (!students.length) {
      return res.send("❌ No students found in this room.");
    }

    // 2️⃣ Build fee + attendance summaries for each student
    for (let student of students) {
      // Fee Summary per student (same as your current logic)
     const [feeRows] = await db.promise().query(`
  SELECT 
      yf.year AS academic_year,
      yf.amount AS total_fee,
      IFNULL(SUM(CASE WHEN fr.status = 'Verified' THEN fr.amount_paid END), 0) AS verified_amount
  FROM yearly_fee yf
  LEFT JOIN fee_receipts fr 
      ON TRIM(CAST(yf.year AS CHAR)) = TRIM(CAST(fr.year AS CHAR))
      AND fr.student_id = ?
  WHERE CAST(yf.year AS UNSIGNED) <= CAST(? AS UNSIGNED)
  GROUP BY yf.year, yf.amount
`, [stu.student_id, stu.year]);


      // Calculate due + status
      const feeSummary = feeRows.map(row => {
        const totalFee = parseFloat(row.total_fee || 0);
        const verified = parseFloat(row.verified_amount || 0);
        const uploaded = parseFloat(row.uploaded_amount || 0);
        const due = totalFee - verified;
        const status = verified >= totalFee ? "✅ Fully Paid" :
                       uploaded > 0 ? "⏳ Pending Verification" :
                       "❌ Not Paid";

        return {
          academic_year: row.academic_year,
          total_fee: totalFee.toFixed(2),
          uploaded_amount: uploaded.toFixed(2),
          verified_amount: verified.toFixed(2),
          due_amount: due.toFixed(2),
          status
        };
      });

      student.feeSummary = feeSummary;

      // Attendance summary per student
      const [attendanceRows] = await db.promise().query(
        `SELECT COUNT(*) AS total_classes,
                SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) AS present_count
         FROM attendance WHERE student_id = ?`,
        [student.student_id]
      );

      const attendanceSummary = attendanceRows[0] || {
        total_classes: 0,
        present_count: 0
      };

      student.attendanceSummary = attendanceSummary;
    }

    // 3️⃣ Render all students of that room in one page
    res.render("warden/room_students", { room_no, students });

  } catch (err) {
    console.error("❌ Error fetching room students:", err);
    res.status(500).send("Error fetching room students: " + err.message);
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
// ⭐ View ALL Receipts for Warden
app.get("/warden/viewReceipts", async (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "warden") {
      return res.redirect("/choose_login");
    }

    const [receipts] = await db.promise().query(`
      SELECT fr.receipt_id, fr.student_id, s.name, s.course, s.year, s.room_no,
             fr.ref_id, fr.amount_paid, fr.status, fr.pdf_path, fr.created_at
      FROM fee_receipts fr
      JOIN students s ON fr.student_id = s.student_id
      ORDER BY fr.created_at DESC
    `);

    res.render("warden/viewReceipts", { receipts });

  } catch (err) {
    console.error("Error loading receipts:", err);
    res.status(500).send("Server Error");
  }
});


app.get('/warden/pendingReceipts', async (req, res) => {
    if (req.session.role !== 'admin') return res.redirect('/choose_login');

    const [pending] = await db.promise().query(
        "SELECT fr.*, s.name FROM fee_receipts fr JOIN students s ON fr.student_id=s.student_id WHERE fr.status='Pending' ORDER BY fr.created_at DESC"
    );

    res.render('warden/pendingReceipts', { pending });
});
// ---------------- ADMIN VIEW ALL OUTPASSES ----------------
app.get("/admin/viewOutpasses", (req, res) => {
  if (!req.session.user || req.session.role !== "admin") {
    return res.redirect("/login/admin");
  }

  const query = `
    SELECT o.*, s.name AS student_name, s.room_no, s.course, s.year
    FROM outpasses o
    JOIN students s ON o.student_id = s.student_id
    ORDER BY o.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching all outpasses:", err);
      return res.send("Error fetching all outpasses: " + err);
    }
    res.render("admin/viewOutpasses", { outpasses: results, session: req.session });
  });
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
// GET pending fee receipts
// GET pending fee receipts
app.get("/admin/verifyFees", (req, res) => {
  if (!req.session.user || req.session.role !== "admin") 
    return res.redirect("/login/admin");

  const sql = `
    SELECT f.receipt_id, f.student_id, s.name, f.ref_id, f.amount_paid, f.year, f.pdf_path, f.status, f.created_at
    FROM fee_receipts f
    JOIN students s ON f.student_id = s.student_id
    WHERE f.status = 'Pending'
    ORDER BY f.created_at DESC
  `;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).send("Database error: " + err.message);
    res.render("admin/verifyFees", { receipts: results });
  });
});

// POST verify or reject a fee receipt
app.post("/admin/verifyFees/:receipt_id", async (req, res) => {
  if (!req.session.user || req.session.role !== "admin") 
    return res.redirect("/login/admin");

  const receipt_id = req.params.receipt_id;
  const { status } = req.body;

  let conn;
  try {
    conn = await db.promise().getConnection();
    await conn.beginTransaction();

    // 1️⃣ Fetch receipt
    const [rows] = await conn.query("SELECT * FROM fee_receipts WHERE receipt_id=?", [receipt_id]);
    if (rows.length === 0) {
      await conn.rollback();
      return res.send("Fee receipt not found.");
    }
    const receipt = rows[0];

    // 2️⃣ If Verified, update student's total_paid and remaining_fee
    if (status === "Verified") {
      // Fetch current totals
      const [[student]] = await conn.query("SELECT total_paid, total_fee FROM students WHERE student_id=?", [receipt.student_id]);
      if (!student) {
        await conn.rollback();
        return res.send("Student not found.");
      }

      const new_total_paid = parseFloat(student.total_paid) + parseFloat(receipt.amount_paid);
      const remaining_fee = parseFloat(student.total_fee) - new_total_paid;

      await conn.query(`
        UPDATE students
        SET total_paid = ?, remaining_fee = ?
        WHERE student_id = ?
      `, [new_total_paid, remaining_fee, receipt.student_id]);
    }

    // 3️⃣ Update receipt status and verified_at
    await conn.query("UPDATE fee_receipts SET status=?, verified_at=NOW() WHERE receipt_id=?", [status, receipt_id]);

    await conn.commit();
    res.redirect("/admin/verifyFees");
  } catch (err) {
    if (conn) await conn.rollback();
    console.error("Error verifying fee:", err);
    res.status(500).send("Error verifying fee: " + err.message);
  } finally {
    if (conn) conn.release();
  }
});

app.get("/admin/student/:student_id", async (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "admin") {
      return res.redirect("/choose_login");
    }

    const student_id = req.params.student_id;

    // Fetch student details
    const [studentRows] = await db.promise().query(
      `SELECT student_id, student_unique_id, name, email, room_no, course, year, 
              total_paid, total_fee, remaining_fee, year_of_join,
              student_aadhaar, father_aadhaar
       FROM students WHERE student_id = ?`,
      [student_id]
    );

    if (!studentRows.length) return res.send("❌ Student not found.");
    const student = studentRows[0];
    const studentYear = parseInt(student.year);

    // Fetch yearly fee + payments
    const [rows] = await db.promise().query(
      `
      SELECT 
          CAST(yf.year AS UNSIGNED) AS academic_year,
          yf.room_rent, yf.mess_bill1, yf.mess_bill2,
          (yf.room_rent + yf.mess_bill1 + yf.mess_bill2) AS total_fee,
          IFNULL(SUM(fr.amount_paid), 0) AS paid_amount
      FROM yearly_fee yf
      LEFT JOIN fee_receipts fr 
          ON CAST(yf.year AS UNSIGNED) = CAST(fr.year AS UNSIGNED)
          AND fr.student_id = ?
      WHERE CAST(yf.year AS UNSIGNED) <= ?
      GROUP BY yf.year, yf.room_rent, yf.mess_bill1, yf.mess_bill2
      ORDER BY yf.year ASC
      `,
      [student_id, studentYear]
    );

    const feeSummary = rows.map(row => {
      const totalFee = parseFloat(row.total_fee || 0);
      const paid = parseFloat(row.paid_amount || 0);
      const due = Math.max(totalFee - paid, 0);
      return {
        academic_year: row.academic_year,
        room_rent: parseFloat(row.room_rent || 0).toFixed(2),
mess_bill1: parseFloat(row.mess_bill1 || 0).toFixed(2),
mess_bill2: parseFloat(row.mess_bill2 || 0).toFixed(2),

        total_fee: totalFee.toFixed(2),
        paid_amount: paid.toFixed(2),
        due_amount: due.toFixed(2),
      };
    });

    // Totals
    const totalPaid = feeSummary.reduce((a, b) => a + parseFloat(b.paid_amount), 0);
    const totalFee = feeSummary.reduce((a, b) => a + parseFloat(b.total_fee), 0);
    const remainingFee = Math.max(totalFee - totalPaid, 0);

    // Attendance summary
    const [attendanceRows] = await db.promise().query(
      `SELECT COUNT(*) AS total_classes,
              SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) AS present_count
       FROM attendance WHERE student_id = ?`,
      [student_id]
    );
    const attendanceSummary = attendanceRows[0] || { total_classes: 0, present_count: 0 };

    res.render("admin/student_profile", {
      student,
      feeSummary,
      totalPaid,
      remainingFee,
      attendanceSummary
    });

  } catch (err) {
    console.error("❌ Error fetching student profile (admin):", err);
    res.status(500).send("Error fetching student profile: " + err.message);
  }
});

app.get("/admin/viewStudents", async (req, res) => {
  if (!req.session.user || req.session.role !== "admin") {
    return res.redirect("/choose_login");
  }

  try {
    const search = req.query.search ? `%${req.query.search}%` : "%%";

    const [students] = await db.promise().query(
      `SELECT student_id, name, email, room_no, course, year, total_fee, total_paid, remaining_fee, profile_image
       FROM students
       WHERE name LIKE ? OR student_id LIKE ? OR room_no LIKE ?`,
      [search, search, search]
    );

    res.render("admin/viewStudents", {
      students,
      search: req.query.search || "",
      session: req.session
    });

  } catch (err) {
    console.error("❌ Error fetching admin student list:", err);
    res.status(500).send("Error fetching students: " + err.message);
  }
});


// ========================
// MANAGE WARDENS
// ========================

// ===============================
// ✅ MANAGE WARDENS PAGE
// ===============================
app.get("/admin/manageWardens", async (req, res) => {
  try {
    // Fetch all wardens only (no hostels table)
    const [wardens] = await db.promise().query("SELECT * FROM wardens");

    // Render page with wardens and flash messages
    res.render("admin/manageWardens", {
      wardens,
      messages: {
        success: req.flash("success"),
        error: req.flash("error")
      }
    });
  } catch (err) {
    console.error("Error fetching wardens:", err);
    res.status(500).send("Database error");
  }
});


// ===============================
// ✅ ADD NEW WARDEN (no hostels lookup)
// ===============================
app.post("/admin/addWarden", async (req, res) => {
  try {
    const { name, email, password, hostel_id } = req.body;

    if (!name || !email || !password || !hostel_id) {
      req.flash("error", "All fields are required.");
      return res.redirect("/admin/manageWardens");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.promise().query(
      "INSERT INTO wardens (name, email, password, hostel_id, created_at) VALUES (?, ?, ?, ?, NOW())",
      [name, email, hashedPassword, hostel_id]
    );

    req.flash("success", "✅ Warden added successfully!");
    res.redirect("/admin/manageWardens");
  } catch (err) {
    console.error("Error adding warden:", err);

    if (err.code === "ER_DUP_ENTRY") {
      req.flash("error", "⚠️ Email already exists!");
      return res.redirect("/admin/manageWardens");
    }

    req.flash("error", "❌ Database error. Please try again.");
    res.redirect("/admin/manageWardens");
  }
});


// ===============================
// ✅ DELETE WARDEN
// ===============================
app.post("/admin/deleteWarden/:id", async (req, res) => {
  const { id } = req.params;

  try {
    await db.promise().query("DELETE FROM wardens WHERE warden_id = ?", [id]);
    req.flash("success", "🗑️ Warden deleted successfully!");
    res.redirect("/admin/manageWardens");
  } catch (err) {
    console.error("Error deleting warden:", err);
    req.flash("error", "❌ Failed to delete warden. Please try again.");
    res.redirect("/admin/manageWardens");
  }
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
    if (!req.session.user || req.session.role !== "admin") return res.redirect("/choose_login");
    if (!req.file) return res.send("❌ No file uploaded!");

    const filePath = req.file.path;
    const ext = path.extname(req.file.originalname).toLowerCase();
    let sbiTransactions = [];

    if (ext === ".xls" || ext === ".xlsx") {
      const workbook = XLSX.readFile(filePath);
      const sheet = XLSX.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]], { defval: "" });

      sheet.forEach(row => {
        const ref_id = (row["Bank Reference No"] || "").toString().trim();
        const amount = parseFloat(row["Amount"] || 0);
        if (ref_id && !isNaN(amount)) sbiTransactions.push({ ref_id, amount });
      });
    }

    fs.unlinkSync(filePath); // delete uploaded file after reading

    // ====== HERE: Automatic block-wise verification ======
    for (const txn of sbiTransactions) {
      const { ref_id, amount } = txn;

      const [[student]] = await db.promise().query(
        "SELECT * FROM students WHERE student_unique_id = ?",
        [ref_id]
      );
      if (!student) continue;

      const year = parseInt(student.year); // optional: can use txn.year if present
      const [[fee]] = await db.promise().query(
        "SELECT * FROM yearly_fee WHERE year = ?",
        [year]
      );
      if (!fee) continue;

      const room_due = fee.room_rent - (student.room_rent_paid || 0);
      const mess1_due = fee.mess_bill1 - (student.mess_bill1_paid || 0);
      const mess2_due = fee.mess_bill2 - (student.mess_bill2_paid || 0);

      if (Math.abs(amount - room_due) < 0.01) {
        await db.promise().query(
          "UPDATE students SET room_rent_paid = IFNULL(room_rent_paid,0) + ?, total_paid=IFNULL(total_paid,0)+?, remaining_fee=total_fee-IFNULL(total_paid,0) WHERE student_id=?",
          [amount, amount, student.student_id]
        );
      } else if (Math.abs(amount - mess1_due) < 0.01) {
        await db.promise().query(
          "UPDATE students SET mess_bill1_paid = IFNULL(mess_bill1_paid,0) + ?, total_paid=IFNULL(total_paid,0)+?, remaining_fee=total_fee-IFNULL(total_paid,0) WHERE student_id=?",
          [amount, amount, student.student_id]
        );
      } else if (Math.abs(amount - mess2_due) < 0.01) {
        await db.promise().query(
          "UPDATE students SET mess_bill2_paid = IFNULL(mess_bill2_paid,0) + ?, total_paid=IFNULL(total_paid,0)+?, remaining_fee=total_fee-IFNULL(total_paid,0) WHERE student_id=?",
          [amount, amount, student.student_id]
        );
      } else {
        await db.promise().query(
          `INSERT INTO fee_receipts (student_id, ref_id, amount_paid, status, created_at)
           VALUES (?, ?, ?, 'Pending', NOW())`,
          [student.student_id, ref_id, amount]
        );
      }

      // Mark SBI transaction as verified
      await db.promise().query("UPDATE sbi_transactions SET status='Verified' WHERE ref_id=?", [ref_id]);
    }

    res.send(`✅ SBI transactions processed successfully.`);

  } catch (err) {
    console.error("SBI Upload Error:", err);
    res.status(500).send("Error processing SBI file: " + err.message);
  }
});


// Manual verify button
app.get('/admin/acceptedReceipts', async (req, res) => {
  if (req.session.role !== 'admin') return res.redirect('/choose_login');

  try {
    // fetch receipts whose status is 'Verified' or 'Accepted'
    const [accepted] = await db.promise().query(`
      SELECT fr.*, s.name, s.student_unique_id
      FROM fee_receipts fr
      JOIN students s ON fr.student_id = s.student_id
      WHERE fr.status IN ('Verified', 'Accepted')
      ORDER BY fr.verified_at DESC
    `);

    res.render('admin/acceptedReceipts', { accepted });
  } catch (err) {
    console.error("Error fetching accepted receipts:", err);
    res.status(500).send("Database error: " + err.message);
  }
});

app.get("/admin/yearlyFees", async (req, res) => {
  if (!req.session.user || req.session.role !== "admin") {
    return res.redirect("/login/admin");
  }

  try {
    const [rows] = await db.promise().query("SELECT * FROM yearly_fee ORDER BY year ASC");
    res.render("admin/yearlyFees", { fees: rows });
  } catch (err) {
    console.error("Error fetching yearly fees:", err);
    res.status(500).send("Database error");
  }
});
app.post("/admin/yearlyFees", async (req, res) => {
  if (!req.session.user || req.session.role !== "admin") return res.redirect("/login/admin");

  const { year, room_rent, mess_bill1, mess_bill2 } = req.body;

  try {
    await db.promise().query(
      `INSERT INTO yearly_fee (year, room_rent, mess_bill1, mess_bill2, amount)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
       room_rent=VALUES(room_rent),
       mess_bill1=VALUES(mess_bill1),
       mess_bill2=VALUES(mess_bill2),
       amount=VALUES(amount)`,
      [parseInt(year),
       parseFloat(room_rent),
       parseFloat(mess_bill1),
       parseFloat(mess_bill2),
       parseFloat(room_rent) + parseFloat(mess_bill1) + parseFloat(mess_bill2)]
    );

    res.redirect("/admin/yearlyFees");
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error");
  }
});

// ====================== ADMIN COMPLAINTS PAGE ======================
app.get('/admin/admin_complaints', (req, res) => {
  const query = `
    SELECT 
      c.complaint_id, 
      c.student_id, 
      s.name AS student_name, 
      s.room_no,
      c.subject, 
      c.description, 
      c.reply, 
      c.status, 
      c.created_at, 
      c.updated_at
    FROM complaints c
    JOIN students s ON c.student_id = s.student_id
    ORDER BY c.created_at DESC;
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching complaints:", err);
      return res.status(500).send("Server error while fetching complaints.");
    }

    // Render EJS from views/admin/admin_complaints.ejs
    res.render('admin/admin_complaints', { complaints: results, user: req.session.user });
  });
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


app.get("/security/dashboard", async (req, res) => {
  try {
    if (req.session.role !== "security") return res.redirect("/login/security");

    const roomQuery = req.query.room_no || "";
    const today = new Date().toISOString().split("T")[0];

    let sql = `
      SELECT 
        o.outpass_id, 
        o.student_id, 
        s.name, 
        s.room_no,
        o.status, 
        o.accepted_by, 
        o.approved_at
      FROM outpasses o
      JOIN students s ON o.student_id = s.student_id
      WHERE DATE(o.approved_at) = ?
    `;

    const params = [today];

    if (roomQuery.trim() !== "") {
      sql += " AND s.room_no = ?";
      params.push(roomQuery.trim());
    }

    sql += " ORDER BY o.approved_at DESC";

    const [outpasses] = await db.promise().query(sql, params);

    // ✅ Add countToday so EJS doesn't throw undefined error
    const countToday = outpasses.length;

    res.render("security/dashboard", {
      user: req.session.user,
      session: req.session,
      outpasses,
      roomQuery,
      countToday   // 🔥 FIXED
    });
  } catch (err) {
    console.error("❌ Error loading security dashboard:", err);
    res.status(500).send("Error loading security dashboard: " + err.message);
  }
});


/// View outpasses
app.get("/security/viewOutpasses", (req, res) => {
    if (!req.session.user || req.session.role !== "security") {
        return res.redirect("/login/security");
    }

    db.query(
        "SELECT * FROM outpasses WHERE status IN ('Approved', 'Exited') ORDER BY out_date DESC",
        (err, results) => {
            if (err) return res.send("Error fetching outpasses: " + err);
            res.render("security/viewOutpasses", { outpasses: results, session: req.session });
        }
    );
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
app.get("/security/todayOutpasses", async (req, res) => {
  if (!req.session.user || req.session.role !== "security") {
    return res.redirect("/login/security");
  }

  try {
    const [rows] = await db.promise().query(
      `SELECT o.*, s.name AS student_name, s.room_no
       FROM outpasses o
       JOIN students s ON o.student_id = s.student_id
       WHERE DATE(o.updated_at) = CURDATE()
       ORDER BY o.updated_at DESC`
    );

    res.render("security/todayOutpasses", { outpasses: rows });
  } catch (err) {
    console.error("Error fetching today's outpasses:", err);
    res.status(500).send("Error loading today's outpasses");
  }
});

app.get("/security/searchByRoom", async (req, res) => {
  if (!req.session.user || req.session.role !== "security") {
    return res.redirect("/login/security");
  }

  const { room_no } = req.query;

  try {
    const [rows] = await db.promise().query(
      `SELECT o.*, s.name AS student_name, s.room_no
       FROM outpasses o
       JOIN students s ON o.student_id = s.student_id
       WHERE DATE(o.updated_at) = CURDATE()
         AND s.room_no = ?
       ORDER BY o.updated_at DESC`,
      [room_no]
    );

    res.render("security/todayOutpasses", { outpasses: rows });
  } catch (err) {
    console.error("Error searching outpasses:", err);
    res.status(500).send("Error searching outpasses");
  }
});

app.get("/security/emergencyOutpasses", async (req, res) => {
  const [rows] = await db.promise().query(
    "SELECT * FROM outpasses WHERE outpass_type='Emergency' AND status='Approved' ORDER BY created_at DESC"
  );
  res.render("security/emergencyOutpasses", { outpasses: rows });
});

// =====================================
// START SERVER
// =====================================
app.listen(3000, () => console.log("🚀 Server running on http://localhost:3000"));

