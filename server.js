const express = require("express");
const app = express();

const mysql = require("mysql2");
const session = require("express-session");
const flash = require("connect-flash");
const cookieParser = require("cookie-parser");
const path = require("path");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const multer = require("multer");
const xlsx = require("xlsx");
const fs = require("fs");
const { execFile } = require("child_process");
const pdfParse = require("pdf-parse");

// ================================
// STATIC UPLOADS (FIXES YOUR ERROR)
// ================================
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Ensure uploads/receipts exists (Render safe)
const receiptsDir = path.join(__dirname, "uploads", "receipts");
if (!fs.existsSync(receiptsDir)) {
  fs.mkdirSync(receiptsDir, { recursive: true });
}

console.log("pdfParse type:", typeof pdfParse);

// ================================
// BODY PARSERS
// ================================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ================================
// COOKIES
// ================================
app.use(cookieParser());

// ================================
// SESSION (FIXED ❗)
// ================================
app.use(
  session({
    secret: "hostel_management_secret_123",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 }, // 1 hour
  })
);

// ================================
// FLASH
// ================================
app.use(flash());

// ================================
// FLASH → VIEWS
// ================================
app.use((req, res, next) => {
  res.locals.flashSuccess = req.flash("success");
  res.locals.flashError = req.flash("error");
  res.locals.flashInfo = req.flash("info");
  res.locals.flashWarn = req.flash("warning");
  res.locals.cookieLogoutMsg = req.cookies?.flash_logout || null;
  next();
});


// ================================
// NO-CACHE HEADERS (BACK BUTTON FIX)
// ================================
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  next();
});
app.use((req, res, next) => {
  res.locals.isSpa =
    req.xhr || req.headers["x-requested-with"] === "XMLHttpRequest";
  next();
});

app.use((req, res, next) => {
    let sql;

    if (req.session?.user?.role === "Warden") {
        // Warden sees only his hostel’s notices
        sql = `SELECT * FROM notices WHERE hostel_id = ? OR posted_by = 'Admin' ORDER BY notice_id DESC LIMIT 5`;
        db.query(sql, [req.session.user.hostel_id], (err, result) => {
            res.locals.globalNotices = result || [];
            next();
        });
    } else if (req.session?.user?.role === "Student") {
        // Student sees all admin + their hostel notices
        sql = `SELECT * FROM notices WHERE hostel_id = ? OR posted_by = 'Admin' ORDER BY notice_id DESC LIMIT 5`;
        db.query(sql, [req.session.user.hostel_id], (err, result) => {
            res.locals.globalNotices = result || [];
            next();
        });
    } else {
        // Admin sees all notices
        sql = `SELECT * FROM notices ORDER BY notice_id DESC LIMIT 5`;
        db.query(sql, (err, result) => {
            res.locals.globalNotices = result || [];
            next();
        });
    }
});



// ================================
// MUST RUN BEFORE USING req.flash()
// ================================
// Body parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


// Cookies
app.use(cookieParser());

// ⭐ SESSION MUST COME BEFORE FLASH ⭐
app.use(
  session({
    secret: "hostel_management_secret_123",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 }, // 1 hour
  })
);
app.use(flash());
// ================================
// FLASH → EXPOSE TO VIEWS
// ================================
// MUST BE BEFORE ANY ROUTES!
app.use((req, res, next) => {
  res.locals.flashSuccess = req.flash("success") || [];
  res.locals.flashError = req.flash("error") || [];
  res.locals.flashInfo = req.flash("info") || [];
  res.locals.flashWarn = req.flash("warning") || [];
  res.locals.cookieLogoutMsg = req.cookies?.flash_logout || null;
  next();
});

// ================================
// NO-CACHE HEADERS (BACK BUTTON FIX)
// ================================
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  next();
});
app.use((req, res, next) => {
    let sql;

    if (req.session?.user?.role === "Warden") {
        // Warden sees only his hostel’s notices
        sql = `SELECT * FROM notices WHERE hostel_id = ? OR posted_by = 'Admin' ORDER BY notice_id DESC LIMIT 5`;
        db.query(sql, [req.session.user.hostel_id], (err, result) => {
            res.locals.globalNotices = result || [];
            next();
        });
    } else if (req.session?.user?.role === "Student") {
        // Student sees all admin + their hostel notices
        sql = `SELECT * FROM notices WHERE hostel_id = ? OR posted_by = 'Admin' ORDER BY notice_id DESC LIMIT 5`;
        db.query(sql, [req.session.user.hostel_id], (err, result) => {
            res.locals.globalNotices = result || [];
            next();
        });
    } else {
        // Admin sees all notices
        sql = `SELECT * FROM notices ORDER BY notice_id DESC LIMIT 5`;
        db.query(sql, (err, result) => {
            res.locals.globalNotices = result || [];
            next();
        });
    }
});

// ================================
// STATIC UPLOADS
// ================================

// ✅ Serve uploads folder publicly

const uploadsPath = path.join(__dirname, "uploads");
app.use("/uploads", express.static(uploadsPath));




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

const storage = multer.diskStorage({
  destination: (req, file, cb) => {

  let dir;

  switch (file.fieldname) {
    case "receipt_pdf":
    case "sbi_pdf":
    case "statement_file":  
      
      dir = path.join(__dirname, "uploads", "receipts");
      break;
    case "sbi_excel":   // ✅ ADD THIS
    dir = path.join(__dirname, "uploads", "sbi_excel");
    break;
    case "outpass_pdf":
      dir = path.join(__dirname, "uploads", "outpasses");
      break;

    case "studentsFile":
    case "result_pdf": // 🔥 FIX
      dir = path.join(__dirname, "uploads", "students");
      break;
    


    case "student_aadhaar":
    case "father_aadhaar":
      dir = path.join(__dirname, "uploads", "aadhaar");
      break;

    case "profile_image":
      dir = path.join(__dirname, "uploads", "profile_images");
      break;

    case "mess_bill_pdf":
      dir = path.join(__dirname, "uploads", "mess_bills");
      break;

    default:
      dir = path.join(__dirname, "uploads");
  }

  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  cb(null, dir);
},

filename: (req, file, cb) => {
    let dir;

    switch (file.fieldname) {
      case "receipt_pdf":
      case "sbi_pdf":
        dir = path.join(__dirname, "uploads", "receipts");
        break;

      case "outpass_pdf":
        dir = path.join(__dirname, "uploads", "outpasses");
        break;

      case "studentsFile":
        dir = path.join(__dirname, "uploads", "students");
        break;

      case "student_aadhaar":
      case "father_aadhaar":
        dir = path.join(__dirname, "uploads", "aadhaar");
        break;

      case "profile_image":
        dir = path.join(__dirname, "uploads", "profile_images");
        break;

      case "mess_bill_pdf":
        dir = path.join(__dirname, "uploads", "mess_bills");
        break;

      default:
        dir = path.join(__dirname, "uploads");
    }

    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },


  filename: (req, file, cb) => {
    const studentId =
      req.session && req.session.user && req.session.user.student_id
        ? req.session.user.student_id
        : "unknown";

    const ext = path.extname(file.originalname);

    // Aadhaar
    if (file.fieldname === "student_aadhaar" || file.fieldname === "father_aadhaar") {
      return cb(null, `${studentId}_${file.fieldname}${ext}`);
    }

    // Profile image
    if (file.fieldname === "profile_image") {
      return cb(null, `${studentId}_profile${ext}`);
    }

    // All other files
    const safeName = file.originalname
      .replace(/\s+/g, "_")
      .replace(/[<>:"/\\|?*]+/g, "")
      .trim();

    cb(null, Date.now() + "-" + safeName);
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

function parseSbiPdf(pdfPath) {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(__dirname, "python", "parse_sbi_pdf.py");

    execFile(
      "python",
      [scriptPath, pdfPath],
      { maxBuffer: 1024 * 1024 * 20 },
      (error, stdout, stderr) => {
        if (error) {
          console.error(stderr);
          return reject(error);
        }

        try {
          const data = JSON.parse(stdout);
          resolve(data);
        } catch (e) {
          reject("Invalid JSON from python");
        }
      }
    );
  });
}



// Serve downloads from the uploads directory (secure)
const uploadsDir = path.join(__dirname, "uploads");

// Regex route — compatible with all Express/path-to-regexp versions
app.get(/^\/uploads\/(.*)$/, (req, res) => {
  try {
    const requested = req.params[0] || ""; // captured group from (.*)

    // Normalize and remove any leading ../ attempts
    const safeRel = path.normalize(requested).replace(/^(\.\.(\/|\\|$))+/, "");

    // Resolve absolute paths
    const absolute = path.join(uploadsDir, safeRel);
    const normalizedUploadsDir = path.resolve(uploadsDir) + path.sep;
    const normalizedAbsolute = path.resolve(absolute);

    // Ensure the file is within uploadsDir (prevent path traversal)
    if (!normalizedAbsolute.startsWith(normalizedUploadsDir) && normalizedAbsolute !== path.resolve(uploadsDir)) {
      console.warn("Blocked suspicious download attempt:", requested);
      return res.status(400).send("Invalid file path");
    }

    // Check file exists & readable, then send as download
    fs.access(absolute, fs.constants.R_OK, (err) => {
      if (err) {
        console.error("DOWNLOAD ERROR: file not found/unreadable:", absolute, err);
        return res.status(404).send("File not found");
      }

      res.download(absolute, (err) => {
        if (err) {
          console.error("DOWNLOAD ERROR:", err);
          if (!res.headersSent) res.status(500).send("Download failed");
        }
      });
    });
  } catch (e) {
    console.error("Unexpected error serving upload:", e);
    res.status(500).send("Server error");
  }
});


// ===== Middleware =====
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));





// ===== MySQL Connection =====

const db = mysql.createPool({
    host: 'metro.proxy.rlwy.net',   // Railway host
    user: 'root',                     // Railway username
    password: 'JkJhecPuMJlJAlewWSknGUdQcthevayy',     // Railway password
    database: 'railway',              // Railway database name
    port: 23019,                      // Railway port
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
async function updateYearlyFee(student_id, academic_year) {
  const [[sum]] = await db.promise().query(`
    SELECT 
      IFNULL(SUM(total_amount),0) AS total_fee,
      IFNULL(SUM(paid_amount),0) AS paid
    FROM yearly_fee_components
    WHERE student_id=? AND academic_year=?
  `, [student_id, academic_year]);

  await db.promise().query(`
    UPDATE yearly_fee_status
    SET total_fee=?, total_paid=?, remaining_fee=?, updated_at=NOW()
    WHERE student_id=? AND academic_year=?
  `, [
    sum.total_fee,
    sum.paid,
    sum.total_fee - sum.paid,
    student_id,
    academic_year
  ]);
}
async function findStudentForTransaction({ amount, reference_no, txn_date }) {
  // 1️⃣ Try reference number match
  const [[byRef]] = await db.promise().query(`
    SELECT student_id
    FROM payment_claims
    WHERE ref_no = ?
      AND status = 'SUBMITTED'
    LIMIT 1
  `, [reference_no]);

  if (byRef) return byRef.student_id;

  // 2️⃣ Try amount + date (±2 days)
  const [[byAmount]] = await db.promise().query(`
    SELECT student_id
    FROM payment_claims
    WHERE amount = ?
      AND payment_date BETWEEN DATE_SUB(?, INTERVAL 2 DAY)
                          AND DATE_ADD(?, INTERVAL 2 DAY)
      AND status = 'SUBMITTED'
    LIMIT 1
  `, [amount, txn_date, txn_date]);

  if (byAmount) return byAmount.student_id;

  // ❌ Not confident
  return null;
}
//
// Logout
// POST or GET depending on your current route



app.get("/logout", (req, res) => {
  // Set logout message (readable by frontend script)
  res.cookie("flash_logout", "Logged out successfully", {
    maxAge: 3000,   // 3 seconds
    httpOnly: false // must be false so JS can read it
  });

  // Destroy session
  req.session.destroy(err => {
    res.clearCookie("connect.sid");
    return res.redirect("/choose_login");

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
app.get("/login/student", (req, res) => {
    const errorMsg = req.flash("error");
    const successMsg = req.flash("success");

    res.render("login_student", {
        message: errorMsg[0] || successMsg[0] || null,
        messageType: errorMsg[0] ? "error" : "success"
    });
});

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

    // after successful registration in DB
req.flash('success', 'Registration successful — please login.');
req.session.save(() => res.redirect('/choose_login'));

  } catch (err) {
    console.error("Error in registration:", err);
    res.status(500).send("❌ Error registering student. Please try again later.");
  }
});



// Student login POST
app.post("/login/student", (req, res) => {
  const { student_id, password } = req.body;

  // ---- Inline validation error ----
  if (!student_id || !password) {
    return res.render("login_student", {
      message: "Please provide Student ID and Password",
      messageType: "error"
    });
  }

  const sql = "SELECT * FROM students WHERE student_id=?";
  db.query(sql, [student_id], (err, results) => {
    if (err) {
      return res.render("login_student", {
        message: "Database Error",
        messageType: "error"
      });
    }

    if (results.length === 0) {
      return res.render("login_student", {

        message: "Invalid Credentials|Try Again",

        message: "Invalid Credentials",

        messageType: "error"
      });
    }

    const student = results[0];
    const match = bcrypt.compareSync(password, student.password);

    if (!match) {
      return res.render("login_student", {
        message: "Invalid Credentials",
        messageType: "error"
      });
    }

    // -------- SUCCESS LOGIN --------
    req.session.user = student;
    req.session.role = "student";

    // 🔥 Flash toast for success
    req.flash("success", "Login successful — welcome back!");

    return req.session.save(() => {
      res.redirect("/student/dashboard");
    });
  });
});

app.get("/testflash", (req, res) => {
  req.flash("success", "Flash is working!");
  res.redirect("/testshow");
});

app.get("/testshow", (req, res) => {
  res.send(res.locals.flashSuccess);
});



app.get("/student/dashboard", async (req, res) => {
  if (!req.session.user || req.session.role !== "student") {
    return res.redirect("/login/student");
  }

  const student_id = req.session.user.student_id;

  try {
 
    // Fetch student details

    const [studentRows] = await db.promise().query(
      "SELECT * FROM students WHERE student_id = ?", 
      [student_id]
    );

    if (studentRows.length === 0) return res.send("Student not found");
    const student = studentRows[0];

    const joinYear = getJoinYearFromRegId(student.student_id);


    const [yearFees] = await db.promise().query(
      "SELECT * FROM yearly_fee ORDER BY year ASC"
    );


    const [paidFees] = await db.promise().query(
      `
      SELECT year, SUM(amount_paid) AS total_paid
      FROM fee_receipts
      WHERE student_id = ? AND status = 'Verified'
      GROUP BY year
      `,
      [student_id]
    );

    const paidMap = {};
    paidFees.forEach(p => paidMap[p.year] = parseFloat(p.total_paid || 0));

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
          due_amount: Math.max(0, due)
        });
      }
    }


    // ⭐⭐ FETCH ONLY LATEST NOTICE ⭐⭐
    const [latestNoticeRows] = await db.promise().query(
      "SELECT * FROM notices ORDER BY created_at DESC LIMIT 1"
    );

    const latestNotice = latestNoticeRows.length ? latestNoticeRows[0] : null;

    // ⭐ RENDER PAGE ⭐
      // <= ADD THIS

    // ⭐⭐⭐ THIS WAS MISSING ⭐⭐⭐
    res.render("student/dashboard", { 
      student, 
      feeSummary, 
      unpaidCount,
      latestNotice, 

      flashSuccess: res.locals.flashSuccess,
      flashError: res.locals.flashError
    });

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
    /* ---------------- STUDENT ---------------- */
    const [[student]] = await db.promise().query(
      "SELECT * FROM students WHERE student_id = ?",
      [student_id]
    );
    if (!student) return res.send("Student not found");

    const studentYear = Number(student.year || 0); // ✅ SAFE FIX

    /* ---------------- YEARLY FEES ---------------- */
    const [yearlyFees] = await db.promise().query(
      "SELECT * FROM yearly_fee ORDER BY year ASC"
    );

    /* ---------------- ALL RECEIPTS (SHOW TO STUDENT) ---------------- */
    const [receipts] = await db.promise().query(
      `SELECT ref_id, year, amount_paid, remarks, status, created_at
       FROM fee_receipts
       WHERE student_id = ?
       ORDER BY created_at DESC`,
      [student_id]
    );

    /* ---------------- ONLY VERIFIED FOR CALCULATION ---------------- */
    const verifiedReceipts = receipts.filter(r => r.status === 'Verified');

    /* ---------------- MAP PAYMENTS ---------------- */
    const paymentMap = {};

    verifiedReceipts.forEach(r => {
      const yr = Number(r.year);
      if (!yr) return;

      if (!paymentMap[yr]) {
        paymentMap[yr] = {
          'Room Rent': 0,
          'Mess Bill1': 0,
          'Mess Bill2': 0,
          'Others': 0
        };
      }

      let raw = (r.remarks || "").replace(/[_\s]/g, "").toLowerCase();
      let key = "Others";

      if (raw.includes("room")) key = "Room Rent";
      else if (raw.includes("messbill1")) key = "Mess Bill1";
      else if (raw.includes("messbill2")) key = "Mess Bill2";

      paymentMap[yr][key] += Number(r.amount_paid || 0);
    });

    /* ---------------- BUILD SUMMARY ---------------- */
    const feeSummary = yearlyFees
      .filter(f => Number(f.year) <= studentYear)
      .map(f => {
        const paid = paymentMap[f.year] || {};

        const room_rent = Number(f.room_rent || 0);
        const mess_bill1 = Number(f.mess_bill1 || 0);
        const mess_bill2 = Number(f.mess_bill2 || 0);

        const room_rent_paid = paid['Room Rent'] || 0;
        const mess_bill1_paid = paid['Mess Bill1'] || 0;
        const mess_bill2_paid = paid['Mess Bill2'] || 0;

        const total_fee = room_rent + mess_bill1 + mess_bill2;
        const total_paid = room_rent_paid + mess_bill1_paid + mess_bill2_paid;

        let status = "Not Paid";
        if (
          room_rent_paid >= room_rent &&
          mess_bill1_paid >= mess_bill1 &&
          mess_bill2_paid >= mess_bill2
        ) {
          status = "Paid";
        } else if (total_paid > 0) {
          status = "Partial";
        }

        return {
          year: f.year,
          room_rent_paid: room_rent_paid.toFixed(2),
          room_rent_due: Math.max(room_rent - room_rent_paid, 0).toFixed(2),
          mess_bill1_paid: mess_bill1_paid.toFixed(2),
          mess_bill1_due: Math.max(mess_bill1 - mess_bill1_paid, 0).toFixed(2),
          mess_bill2_paid: mess_bill2_paid.toFixed(2),
          mess_bill2_due: Math.max(mess_bill2 - mess_bill2_paid, 0).toFixed(2),
          total_fee: total_fee.toFixed(2),
          total_paid: total_paid.toFixed(2),
          total_due: (total_fee - total_paid).toFixed(2),
          status
        };
      });

    /* ---------------- TOTALS ---------------- */
    const total_paid = feeSummary.reduce((s, f) => s + Number(f.total_paid), 0);
    const total_fee = feeSummary.reduce((s, f) => s + Number(f.total_fee), 0);
    const remaining_due = total_fee - total_paid;

    /* ---------------- RENDER ---------------- */
    res.render('student/viewfees', {
      student,
      feeSummary,
      receipts,               // ✅ includes Pending + Verified
      total_paid: total_paid.toFixed(2),
      remaining_due: remaining_due.toFixed(2)
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
    return res.redirect("/login/student");

  const student_id = req.session.user.student_id;

  try {
    /* ============================
       1️⃣ STUDENT DETAILS
       ============================ */
    const [[student]] = await db.promise().query(
      "SELECT * FROM students WHERE student_id=?",
      [student_id]
    );
    if (!student) return res.send("Student not found");

    const maxYear = parseInt(student.year);


    /* ============================
       2️⃣ YEARLY FEE STRUCTURE
       (OLD TABLE – KEEP)
       ============================ */
    const [feeRows] = await db.promise().query(
      "SELECT * FROM yearly_fee WHERE year <= ? ORDER BY year ASC",
      [maxYear]
    );

    /* ============================
       3️⃣ OLD VERIFIED RECEIPTS
       ============================ */
    const [oldReceipts] = await db.promise().query(
      `SELECT year, amount_paid, remarks
       FROM fee_receipts
       WHERE student_id=? AND status='Verified'`,
      [student_id]
    );

    const oldMap = {};
    oldReceipts.forEach(r => {
      if (!oldMap[r.year]) {
        oldMap[r.year] = { room: 0, mess1: 0, mess2: 0 };
      }

      const key = r.remarks.toLowerCase();
      if (key.includes("room")) oldMap[r.year].room += Number(r.amount_paid);
      else if (key.includes("mess bill1")) oldMap[r.year].mess1 += Number(r.amount_paid);
      else if (key.includes("mess bill2")) oldMap[r.year].mess2 += Number(r.amount_paid);
    });

    /* ============================
       4️⃣ NEW BANK PAYMENTS
       ============================ */
    const [newRows] = await db.promise().query(
      `SELECT academic_year, component, allocated_amount
       FROM student_payment_allocations
       WHERE student_id=?`,
      [student_id]
    );

    const newMap = {};
    newRows.forEach(r => {
      if (!newMap[r.academic_year]) {
        newMap[r.academic_year] = { room: 0, mess1: 0, mess2: 0 };
      }

      if (r.component === "ROOM_RENT") newMap[r.academic_year].room += Number(r.allocated_amount);
      if (r.component === "MESS_BILL_1") newMap[r.academic_year].mess1 += Number(r.allocated_amount);
      if (r.component === "MESS_BILL_2") newMap[r.academic_year].mess2 += Number(r.allocated_amount);
    });

    /* ============================
       5️⃣ MERGED FEE SUMMARY
       ============================ */
    const feeSummary = feeRows.map(y => {
  const year = y.year;

  // 🔑 convert DB values to numbers
  const roomTotal = Number(y.room_rent || 0);
  const mess1Total = Number(y.mess_bill1 || 0);
  const mess2Total = Number(y.mess_bill2 || 0);

  const roomPaid =
    (oldMap[year]?.room || 0) +
    (newMap[year]?.room || 0);

  const mess1Paid =
    (oldMap[year]?.mess1 || 0) +
    (newMap[year]?.mess1 || 0);

  const mess2Paid =
    (oldMap[year]?.mess2 || 0) +
    (newMap[year]?.mess2 || 0);

  const roomDue = Math.max(roomTotal - roomPaid, 0);
  const mess1Due = Math.max(mess1Total - mess1Paid, 0);
  const mess2Due = Math.max(mess2Total - mess2Paid, 0);

  const totalFee = roomTotal + mess1Total + mess2Total;
  const totalPaid = roomPaid + mess1Paid + mess2Paid;

  let status = "Not Paid";
  if (totalPaid >= totalFee) status = "Paid";
  else if (totalPaid > 0) status = "Partial";

  return {
    year,
    room_rent_paid: roomPaid.toFixed(2),
    room_rent_due: roomDue.toFixed(2),
    mess_bill1_paid: mess1Paid.toFixed(2),
    mess_bill1_due: mess1Due.toFixed(2),
    mess_bill2_paid: mess2Paid.toFixed(2),
    mess_bill2_due: mess2Due.toFixed(2),
    total_fee: totalFee.toFixed(2),
    total_paid: totalPaid.toFixed(2),
    total_due: (totalFee - totalPaid).toFixed(2),
    status
  };
});


    res.render("student/profile", { student, feeSummary });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading profile");
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
    /* ---------------- STUDENT ---------------- */
    const [[student]] = await db.promise().query(
      "SELECT * FROM students WHERE student_id = ?",
      [student_id]
    );
    if (!student) return res.send("Student not found");

    const studentYear = Number(student.year || 0); // ✅ SAFE FIX

    /* ---------------- YEARLY FEES ---------------- */
    const [yearlyFees] = await db.promise().query(
      "SELECT * FROM yearly_fee ORDER BY year ASC"
    );

    /* ---------------- ALL RECEIPTS (SHOW TO STUDENT) ---------------- */
    const [receipts] = await db.promise().query(
  `SELECT ref_id, year, amount_paid, remarks, status, pdf_path, created_at
   FROM fee_receipts
   WHERE student_id = ?
   ORDER BY created_at DESC`,
  [student_id]
);


    /* ---------------- ONLY VERIFIED FOR CALCULATION ---------------- */
    const verifiedReceipts = receipts.filter(r => r.status === 'Verified');

    /* ---------------- MAP PAYMENTS ---------------- */
    const paymentMap = {};

    verifiedReceipts.forEach(r => {
      const yr = Number(r.year);
      if (!yr) return;

      if (!paymentMap[yr]) {
        paymentMap[yr] = {
          'Room Rent': 0,
          'Mess Bill1': 0,
          'Mess Bill2': 0,
          'Others': 0
        };
      }

      let raw = (r.remarks || "").replace(/[_\s]/g, "").toLowerCase();
      let key = "Others";

      if (raw.includes("room")) key = "Room Rent";
      else if (raw.includes("messbill1")) key = "Mess Bill1";
      else if (raw.includes("messbill2")) key = "Mess Bill2";

      paymentMap[yr][key] += Number(r.amount_paid || 0);
    });

    /* ---------------- BUILD SUMMARY ---------------- */
    const feeSummary = yearlyFees
      .filter(f => Number(f.year) <= studentYear)
      .map(f => {
        const paid = paymentMap[f.year] || {};

        const room_rent = Number(f.room_rent || 0);
        const mess_bill1 = Number(f.mess_bill1 || 0);
        const mess_bill2 = Number(f.mess_bill2 || 0);

        const room_rent_paid = paid['Room Rent'] || 0;
        const mess_bill1_paid = paid['Mess Bill1'] || 0;
        const mess_bill2_paid = paid['Mess Bill2'] || 0;

        const total_fee = room_rent + mess_bill1 + mess_bill2;
        const total_paid = room_rent_paid + mess_bill1_paid + mess_bill2_paid;

        let status = "Not Paid";
        if (
          room_rent_paid >= room_rent &&
          mess_bill1_paid >= mess_bill1 &&
          mess_bill2_paid >= mess_bill2
        ) {
          status = "Paid";
        } else if (total_paid > 0) {
          status = "Partial";
        }

        return {
          year: f.year,
          room_rent_paid: room_rent_paid.toFixed(2),
          room_rent_due: Math.max(room_rent - room_rent_paid, 0).toFixed(2),
          mess_bill1_paid: mess_bill1_paid.toFixed(2),
          mess_bill1_due: Math.max(mess_bill1 - mess_bill1_paid, 0).toFixed(2),
          mess_bill2_paid: mess_bill2_paid.toFixed(2),
          mess_bill2_due: Math.max(mess_bill2 - mess_bill2_paid, 0).toFixed(2),
          total_fee: total_fee.toFixed(2),
          total_paid: total_paid.toFixed(2),
          total_due: (total_fee - total_paid).toFixed(2),
          status
        };
      });

    /* ---------------- TOTALS ---------------- */
    const total_paid = feeSummary.reduce((s, f) => s + Number(f.total_paid), 0);
    const total_fee = feeSummary.reduce((s, f) => s + Number(f.total_fee), 0);
    const remaining_due = total_fee - total_paid;

    /* ---------------- RENDER ---------------- */
    res.render('student/viewfees', {
      student,
      feeSummary,
      receipts,               // ✅ includes Pending + Verified
      total_paid: total_paid.toFixed(2),
      remaining_due: remaining_due.toFixed(2)
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
app.post(
  "/student/uploadReceipt",
  upload.single("sbi_pdf"),
  async (req, res) => {

    let conn;
    try {
      if (req.session.role !== "student")
        return res.redirect("/choose_login");

      const student_id = req.session.user.student_id;

      let {
        student_unique_id,
        ref_id,
        amount_paid,
        year,
        remarks
      } = req.body;

      if (!student_unique_id || !ref_id || !amount_paid || !year || !remarks)
        return res.send("⚠️ Fill all fields");

      amount_paid = parseFloat(amount_paid);
      year = parseInt(year);
      ref_id = ref_id.trim();

      if (!req.file) return res.send("❌ Receipt PDF missing");

      const pdf_path = path.join("uploads", "receipts", req.file.filename);

      conn = await db.promise().getConnection();
      await conn.beginTransaction();

      // 🔍 MATCH WITH SBI TRANSACTIONS (ONLY SBI LOGIC)
      const [[txn]] = await conn.query(
        `
        SELECT *
        FROM sbi_transactions
        WHERE ref_id = ?
          AND amount = ?
          AND status = 'Pending'
        `,
        [ref_id, amount_paid]
      );

      const status = txn ? "Verified" : "Pending";

      // 📄 INSERT RECEIPT
      await conn.query(
        `
        INSERT INTO fee_receipts
        (
          student_id,
          student_unique_id,
          ref_id,
          amount_paid,
          year,
          remarks,
          pdf_path,
          status,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
        `,
        [
          student_id,
          student_unique_id,
          ref_id,
          amount_paid,
          year,
          remarks,
          pdf_path,
          status
        ]
      );

      // ✅ IF AUTO VERIFIED → UPDATE SBI TRANSACTION
      if (status === "Verified") {
        await conn.query(
          `
          UPDATE sbi_transactions
          SET status = 'Verified'
          WHERE ref_id = ?
          `,
          [ref_id]
        );
      }

      await conn.commit();
      return res.redirect("/student/viewfees");

    } catch (err) {
      if (conn) await conn.rollback();
      console.error("❌ uploadReceipt error:", err);
      res.status(500).send("Upload failed");
    } finally {
      if (conn) conn.release();
    }
  }
);

app.get('/warden/acceptedReceipts', async (req, res) => {
  if (!req.session || req.session.role !== 'admin') {
    return res.redirect('/choose_login');
  }

  const [accepted] = await db.promise().query(`
    SELECT fr.*, s.name, s.student_unique_id
    FROM fee_receipts fr
    JOIN students s ON fr.student_id = s.student_id
    WHERE fr.status IN ('Verified','Accepted')
    ORDER BY fr.verified_at DESC
  `);

  res.render('warden/acceptedReceipts', {
    accepted,
    isSpa: false   // 🔑 IMPORTANT
  });
});


app.get("/viewReceipts", async (req, res) => {
  try {
   const [accepted] = await db.promise().query(`
  SELECT fr.*, s.name, s.student_unique_id
  FROM fee_receipts fr
  JOIN students s ON fr.student_id = s.student_id
  WHERE LOWER(fr.status) IN ('verified','accepted','paid','success')
  ORDER BY fr.verified_at DESC
`);


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
    const [attendance] = await db.promise().query(
      `SELECT date, period, status 
       FROM attendance 
       WHERE student_id = ?
       ORDER BY date DESC`,
      [student_id]
    );

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

  if (!hostel_id) {
    return res.send("Hostel ID is required");
  }

  bcrypt.hash(password, 10)
    .then((hash) => {
      db.query(
        "INSERT INTO wardens (name, email, password, hostel_id) VALUES (?, ?, ?, ?)",
        [name, email, hash, hostel_id],
        (err) => {
          if (err) {
            return res.send("Warden Registration Failed: " + err);
          }

          // ✅ after successful registration
          req.flash("success", "Registration successful — please login.");
          req.session.save(() => {
            res.redirect("/login/warden");
          });
        }
      );
    })
    .catch((err) => {
      console.error("Bcrypt Error:", err);
      res.send("Error while hashing password");
    });
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

    const student_id =
      req.session.user.student_id || req.session.user.id;

    let { student_unique_id, ref_id, amount_paid, year, remarks } = req.body;

    if (!student_unique_id || !ref_id || !amount_paid || !year || !remarks)
      return res.send("⚠️ Please fill all required fields.");

    student_unique_id = student_unique_id.trim().toUpperCase().replace(/\s+/g, "_");
    ref_id = ref_id.trim();
    amount_paid = parseFloat(amount_paid);
    year = parseInt(year);

    if (!req.file) return res.send("❌ No PDF uploaded.");

    const pdf_path = path.join("uploads", "receipts", req.file.filename);

    conn = await db.promise().getConnection();
    await conn.beginTransaction();

    const [[txn]] = await conn.query(
      `SELECT * FROM sbi_transactions 
       WHERE TRIM(ref_id)=?
         AND CAST(amount AS DECIMAL)=?
         AND status='Pending'`,
      [ref_id, amount_paid]
    );

    const status = txn ? "Verified" : "Pending";

    await conn.query(
      `INSERT INTO fee_receipts
       (student_id, student_unique_id, ref_id, amount_paid, pdf_path, year, status, remarks, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        student_id,
        student_unique_id,
        ref_id,
        amount_paid,
        pdf_path,
        year,
        status,
        remarks
      ]
    );

    if (status === "Verified") {
      await conn.query(
        "UPDATE sbi_transactions SET status='Verified' WHERE ref_id=?",
        [ref_id]
      );
    }

    await conn.commit();

    // 🔥 REDIRECT — THIS WAS MISSING
    return res.redirect("/student/viewfees");

  } catch (err) {
    if (conn) await conn.rollback();
    console.error("❌ uploadReceipt error:", err);
    res.status(500).send(err.message);
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
        // after successful registration in DB
req.flash('success', 'Registration successful — please login.');
req.session.save(() => res.redirect("/login/warden"));
        
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

      req.flash('success', 'Login successful — welcome back!');
req.session.save(err => {
  // redirect after session saved to persist flash
  return res.redirect('/warden/dashboard'); // or appropriate route
});
    });
  });
});


app.get("/warden/dashboard", async (req, res) => {
  if (!req.session.user || req.session.role !== "warden") {
    return res.redirect("/login/warden");
  }

  const wardenNameSafe = req.session.warden_name || "Warden";

  try {
    // 🔔 Latest notice
    let latestNotice = null;
    const [noticeRows] = await db.promise().query(
      "SELECT * FROM notices ORDER BY created_at DESC LIMIT 1"
    );
    latestNotice = noticeRows.length ? noticeRows[0] : null;

    // ✅ Approved today
    const [approvedToday] = await db.promise().query(
      `SELECT COUNT(*) AS count
       FROM outpasses
       WHERE status='Approved'
         AND accepted_by=?
         AND DATE(approved_at)=CURDATE()`,
      [wardenNameSafe]
    );

    // ✅ Students list
    const [studentsSafe] = await db.promise().query(
      `SELECT s.student_id, s.name, o.status, o.approved_at
       FROM students s
       JOIN outpasses o ON s.student_id = o.student_id
       WHERE o.accepted_by=?
       ORDER BY o.approved_at DESC`,
      [wardenNameSafe]
    );

    // ✅ Dashboard numbers
    const approvedCountSafe = approvedToday[0]?.count || 0;
    const pendingCountSafe = studentsSafe.filter(s => s.status === "Pending").length;
    const studentCountSafe = studentsSafe.length;
    const complaintCountSafe = 0; // later DB

    // ✅ Render (MATCHES EJS)
    res.render("warden/dashboard", {
      user: req.session.user,
      session: req.session,

      latestNotice,
      wardenNameSafe,
      pendingCountSafe,
      studentCountSafe,
      complaintCountSafe,
      approvedCountSafe,
      studentsSafe
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


// Warden login
app.post("/login/warden", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM wardens WHERE email = ?",
    [email],
    (err, rows) => {

      if (err) {
        console.error(err);
        return res.render("login_warden", {
          message: "Server error. Please try again.",
          messageType: "error"
        });
      }

      if (!rows.length) {
        return res.render("login_warden", {
          message: "Invalid Email or Password",
          messageType: "error"
        });
      }

      const wardenData = rows[0];

      bcrypt.compare(password, wardenData.password).then(match => {

        if (!match) {
          return res.render("login_warden", {
            message: "Invalid Email or Password",
            messageType: "error"
          });
        }

        // ✅ LOGIN SUCCESS
        req.session.user = wardenData;
        req.session.role = "warden";
        req.session.warden = wardenData;
        req.session.warden_id = wardenData.warden_id;
        req.session.warden_name = wardenData.name;

        req.flash("success", "Login successful — welcome back!");

        req.session.save(() => {
          return res.redirect("/warden/dashboard");
        });
      });
    }
  );
});


app.get("/warden/dashboard", async (req, res) => {
  if (req.session.role !== "warden")
    return res.redirect("/login/warden");

  const wardenName = req.session.warden_name;

  try {
    const loadPage = req.query.load || null; // 🔥 ADD THIS

    // ⭐ Fetch Latest Notice
    const [noticeRows] = await db.promise().query(
      "SELECT * FROM notices ORDER BY created_at DESC LIMIT 1"
    );
    const latestNotice = noticeRows.length ? noticeRows[0] : null;

    const [pending] = await db.promise().query(
      "SELECT COUNT(*) AS count FROM outpasses WHERE status='Pending'"
    );

    const [studentsCount] = await db.promise().query(
      "SELECT COUNT(*) AS count FROM students"
    );

    const [complaints] = await db.promise().query(
      "SELECT COUNT(*) AS count FROM complaints WHERE status='Pending'"
    );

    const [approvedToday] = await db.promise().query(
      `SELECT COUNT(*) AS count 
       FROM outpasses 
       WHERE status='Approved'
         AND accepted_by=? 
         AND DATE(approved_at)=CURDATE()`,
      [wardenName]
    );

    const [studentsWithOutpass] = await db.promise().query(
      `SELECT s.student_id, s.name, o.status, o.approved_at
       FROM students s
       JOIN outpasses o ON s.student_id = o.student_id
       WHERE o.accepted_by = ?
       ORDER BY o.approved_at DESC`,
      [wardenName]
    );

    res.render("warden/dashboard", {
      wardenNameSafe: wardenName || "Warden",
      pendingCountSafe: pending[0].count || 0,
      studentCountSafe: studentsCount[0].count || 0,
      complaintCountSafe: complaints[0].count || 0,
      approvedCountSafe: approvedToday[0].count || 0,
      studentsSafe: studentsWithOutpass || [],
      latestNotice,
      loadPage,                // 🔥 IMPORTANT
      success: req.flash("success")
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
    // 🔹 get blocks directly from DB
    const [blockRows] = await db.promise().query(
  "SELECT DISTINCT block FROM students WHERE block IS NOT NULL ORDER BY block"
);

    const blocks = blockRows.map(b => b.block);

    // 🔹 get rooms grouped by block
    const roomsByBlock = {};
    for (const b of blocks) {
      const [roomRows] = await db.promise().query(
        "SELECT DISTINCT room_no FROM students WHERE block = ? ORDER BY room_no",
        [b]
      );
      roomsByBlock[b] = roomRows.map(r => r.room_no);
    }

    const block   = req.query.block || '';
    const year    = req.query.year || '';
    const room_no = req.query.room_no || '';

    const rooms = block ? roomsByBlock[block] || [] : [];

    // 🔍 HARD DEBUG (DON’T SKIP)
    console.log("BLOCKS FROM DB:", blocks);
    console.log("SELECTED BLOCK:", block);
    console.log("ROOMS FOR BLOCK:", rooms);

    let students = [];

    if (block && year && room_no) {
      const today = new Date().toISOString().split("T")[0];

      const [rows] = await db.promise().query(`
        SELECT s.*,
        CASE WHEN EXISTS (
          SELECT 1 FROM outpasses o
          WHERE o.student_id = s.student_id
            AND o.status = 'Approved'
            AND ? BETWEEN o.out_date AND o.return_date
        )
        THEN 'On Leave' ELSE 'Available' END AS leave_status
        FROM students s
        WHERE s.block = ?
          AND s.year = ?
          AND s.room_no = ?
        ORDER BY s.name
      `, [today, block, year, room_no]);

      students = rows;
    }

    res.render('warden/markAttendance', {
  blocks,
  block,
  year,
  room_no,
  roomsByBlock,
  rooms,
  students
});


  } catch (err) {
    console.error("MarkAttendance Error:", err);
    res.status(500).send("Server Error");
  }
});




app.get("/warden/selectRoom", async (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "warden") {
      return res.redirect("/choose_login");
    }

    const [rooms] = await db.promise().query(
      "SELECT DISTINCT room_no FROM students ORDER BY room_no"
    );

    // SPA request
    if (req.headers["x-requested-with"] === "XMLHttpRequest") {
      return res.render("warden/selectRoom", { rooms });
    }

    // normal load (fallback)
    res.render("warden/dashboard", {
      page: "warden/selectRoom",
      rooms
    });

  } catch (err) {
    console.error(err);
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
  if (req.session.role !== "warden") {
    return res.redirect("/login/warden");
  }

  const isSpa = req.headers['x-requested-with'] === 'XMLHttpRequest';

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
    ORDER BY c.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching complaints:", err);
      return res.status(500).send("Server error while fetching complaints.");
    }

    res.render('warden/complaints', {
      isSpa,
      complaints: results,
      messages: {}
    });
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
app.get("/warden/approveOutpass", (req, res) => {
  if (req.session.role !== "warden") return res.redirect("/login/warden");

  const isSpa = req.headers["x-requested-with"] === "XMLHttpRequest";

  const query = `
    SELECT o.*, s.name AS name, s.room_no
    FROM outpasses o
    JOIN students s ON o.student_id = s.student_id
    ORDER BY o.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) return res.send("Error fetching outpasses: " + err);

    res.render("warden/approveOutpass", {
      isSpa,
      outpasses: results
    });
  });
});

app.post("/warden/approveOutpass/:id/:action", (req, res) => {
  const { id, action } = req.params;
  const status = action === "approve" ? "Approved" : "Rejected";

  const acceptedBy = req.session.warden_name || "Unknown Warden";
  const approvedAt = new Date();

  const updateQuery = `
    UPDATE outpasses
    SET status = ?, accepted_by = ?, approved_at = ?
    WHERE outpass_id = ?
  `;

  db.query(updateQuery, [status, acceptedBy, approvedAt, id], (err) => {
    if (err) {
      console.error("Outpass Update Error:", err);
      return res.json({ success: false });
    }

    const fetchQuery = `
      SELECT s.email, s.name, o.out_date, o.return_date, o.reason
      FROM outpasses o
      JOIN students s ON o.student_id = s.student_id
      WHERE o.outpass_id = ?
    `;

    db.query(fetchQuery, [id], (err2, results) => {
      if (err2 || results.length === 0) {
        return res.json({ success: true, status });
      }

      const student = results[0];

      const subject =
        status === "Approved"
          ? "Outpass Approved - Hostel Management"
          : "Outpass Rejected - Hostel Management";

      const message =
        status === "Approved"
          ? `Hello ${student.name},

Your outpass request has been approved.

Out Date: ${student.out_date}
Return Date: ${student.return_date}
Reason: ${student.reason}

Regards,
Hostel Warden`
          : `Hello ${student.name},

Your outpass request has been rejected.

Reason: ${student.reason}

Regards,
Hostel Warden`;

      transporter.sendMail(
        {
          from: "harshavardhanvangara@gmail.com",
          to: student.email,
          subject,
          text: message
        },
        () => {
          // 🔥 SPA response (NO redirect)
          if (req.headers["x-requested-with"] === "XMLHttpRequest") {
            return res.json({ success: true, status });
          }

          // fallback (non-SPA)
          res.redirect("/warden/approveOutpass");
        }
      );
    });
  });
});


app.get("/warden/emergencyOutpasses", (req, res) => {
  if (!req.session.user || req.session.role !== "warden") {
    return res.redirect("/choose_login");
  }

  const isSpa = req.headers["x-requested-with"] === "XMLHttpRequest";

  const query = `
    SELECT o.*, s.name AS student_name, s.room_no
    FROM outpasses o
    JOIN students s ON o.student_id = s.student_id
    WHERE o.status = 'Pending'
      AND o.outpass_type = 'Emergency'
    ORDER BY o.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.send("Error fetching emergency outpasses");
    }

    // ✅ IMPORTANT: correct EJS + isSpa pass
    res.render("warden/emergencyOutpasses", {
      outpasses: results,
      isSpa
    });
  });
});

// ============================================
// ✅ WARDEN: UPLOAD STUDENTS PAGE
// ============================================
app.get("/warden/upload-students", (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "warden") {
      return res.redirect("/choose_login");
    }

    res.render("warden/upload-students", {
      success: req.query.success,
      error: req.query.error
    });

  } catch (err) {
    console.error("❌ Error loading upload students page:", err);
    res.status(500).send("Error loading upload students page");
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
  if (!req.session.user || req.session.role !== "warden") {
    return res.redirect("/choose_login");
  }

  const messages = {};

  if (req.query.success) {
    messages.success = "Results uploaded & processed successfully!";
  }
  if (req.query.error) {
    messages.error = "Something went wrong while uploading results.";
  }

  res.render("warden/upload_results", { messages, isSpa: false });

});

app.post(
  "/warden/upload_results",
  upload.single("result_pdf"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.redirect("/warden/upload_results?error=1");
      }

      const { year, semester, result_type } = req.body;

      // ✅ VALIDATE RESULT TYPE
      if (!["regular", "supply", "revaluation"].includes(result_type)) {
        return res.redirect("/warden/upload_results?error=1");
      }

      /* ===============================
         1️⃣ SAVE PDF METADATA
         =============================== */
      const relativePath = path.join("uploads", "students", req.file.filename);

      await db.promise().query(
        `INSERT INTO results_pdf
         (file_path, year, semester, result_type, uploaded_by)
         VALUES (?, ?, ?, ?, ?)`,
        [relativePath, year, semester, result_type, "warden"]
      );

      /* ===============================
         2️⃣ READ PDF
         =============================== */
      const buffer = fs.readFileSync(path.resolve(req.file.path));
      const data = await pdfParse(buffer);
      const text = data.text;

      /* ===============================
         3️⃣ LOAD VALID STUDENTS
         =============================== */
      const [studentRows] = await db.promise().query(
        "SELECT student_id FROM students"
      );
      const validStudents = new Set(studentRows.map(r => r.student_id));

      /* ===============================
         4️⃣ PARSE RESULTS
         =============================== */
      const studentResults = {};
     const recordRegex =
  /(\d{2}B8[A-Z0-9]+)R\d{6}.*?(ABSENT|F|[SABCDE])\d+/g;


      let match;
      while ((match = recordRegex.exec(text)) !== null) {
        const studentId = match[1];
        const grade = match[2];

        if (!validStudents.has(studentId)) continue;

        if (!studentResults[studentId]) {
          studentResults[studentId] = 0;
        }

        if (grade === "F" || grade === "ABSENT") {
          studentResults[studentId]++;
        }
      }

      /* ===============================
         5️⃣ SAVE RESULTS
         =============================== */
      for (const studentId in studentResults) {
        await saveStudentResult(
          studentId,
          studentResults[studentId],
          year,
          semester,
          result_type
        );
      }

      res.redirect("/warden/upload_results?success=1");

    } catch (err) {
      console.error("❌ Error uploading results:", err);
      res.redirect("/warden/upload_results?error=1");
    }
  }
);
async function saveStudentResult(studentId, backlogs, year, semester, resultType) {

  const status = backlogs > 0 ? "Failed" : "Passed";

  const [existing] = await db.promise().query(
    `SELECT id FROM student_results
     WHERE student_id = ?
       AND year = ?
       AND semester = ?
       AND result_type = ?`,
    [studentId, year, semester, resultType]
  );

  if (existing.length) {

    await db.promise().query(
      `UPDATE student_results
       SET total_backlogs = ?,
           status = ?,
           updated_at = CURRENT_TIMESTAMP
       WHERE student_id = ?
         AND year = ?
         AND semester = ?
         AND result_type = ?`,
      [backlogs, status, studentId, year, semester, resultType]
    );

    console.log(`🔄 UPDATED → ${studentId} | ${year}-${semester} | ${resultType}`);

  } else {

    await db.promise().query(
      `INSERT INTO student_results
       (student_id, reg_no, year, semester, result_type, total_backlogs, status)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [studentId, studentId, year, semester, resultType, backlogs, status]
    );

    console.log(`➕ INSERTED → ${studentId} | ${year}-${semester} | ${resultType}`);
  }
}

app.get("/warden/uploadMessBill", (req, res) => {

  const isSpa = req.headers['x-requested-with'] === 'XMLHttpRequest';

  res.render("warden/uploadMessBill", {
    isSpa
  });
});


app.post(
  "/warden/uploadMessBill",
  upload.single("mess_bill_pdf"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).send("No file uploaded");
      }

      const ext = path.extname(req.file.originalname).toLowerCase();
      const uploadedBy = req.session?.warden?.name || "Admin";

      if (ext !== ".xls" && ext !== ".xlsx") {
        return res.status(400).send("❌ Please upload Excel file only");
      }

      /* =======================
         ✅ READ EXCEL FILE
         ======================= */
      const workbook = xlsx.readFile(req.file.path);
      const sheet = workbook.Sheets[workbook.SheetNames[0]];
      const rows = xlsx.utils.sheet_to_json(sheet, { header: 1 });

      /* =======================
         ✅ NORMALIZE EXCEL DATA
         ======================= */
   

// ❌ remove header row (Room No, Name, Year...)
rows.shift();

// ✅ PARSE ROWS BY COLUMN POSITION
const records = rows.map(r => ({
  room_no: r[1]?.toString().trim(),   // Room No (Column B)
  name: r[2]?.toString().trim(),      // Name (Column C)
  year: r[3],                         // Year (Column D)
  block: r[4],                        // Block (Column E)
  month: r[5]?.toString().trim(),     // th of Mess (Column F)
  amount: parseFloat(
    r[6]?.toString().replace(/[^\d.]/g, "")
  )                                   // Bill Amount (Column G)
}));




      let inserted = 0;
      let skipped = 0;

      /* =======================
         ✅ PROCESS EACH ROW
         ======================= */
      for (const row of records) {
        const { room_no, name, month, amount } = row;

        if (
  room_no === undefined ||
  name === undefined ||
  month === undefined ||
  amount === undefined ||
  isNaN(amount)
) {
  console.log("⛔ SKIPPED ROW:", { room_no, name, month, amount });
  skipped++;
  continue;
}


        /* =======================
           ✅ INSERT / UPDATE
           ======================= */
        const [result] = await db.promise().query(
  `
  INSERT INTO mess_bills (student_id, month, amount, uploaded_by)
  SELECT s.student_id, ?, ?, ?
  FROM students s
  WHERE s.room_no LIKE CONCAT('%', ?, '%')
    AND REPLACE(LOWER(s.name), '.', '') 
        LIKE CONCAT('%', REPLACE(LOWER(?), '.', ''), '%')
  ON DUPLICATE KEY UPDATE
    amount = VALUES(amount),
    uploaded_by = VALUES(uploaded_by)
  `,
  [month, amount, uploadedBy, room_no, name]
);


        if (result.affectedRows > 0) {
          await db.promise().query(
            `
            UPDATE students
            SET current_mess_bill = ?
            WHERE TRIM(LOWER(room_no)) = TRIM(LOWER(?))
              AND TRIM(LOWER(REPLACE(name,'.','')))
                  LIKE CONCAT('%', TRIM(LOWER(REPLACE(? ,'.',''))), '%')
            `,
            [amount, room_no, name]
          );

          inserted++;
        } else {
          skipped++;
        }
      }

      res.send(
        `✅ Mess bills assigned to ${inserted} students. Skipped ${skipped} rows.`
      );

    } catch (err) {
      console.error("❌ Mess Bill Upload Error:", err);
      res.status(500).send("Server error while uploading mess bill");
    }
  }
);




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
    if (req.session.role !== "warden") {
      return res.redirect("/login/warden");
    }

    const isSpa = req.headers["x-requested-with"] === "XMLHttpRequest";
    const { year, student_id, backlogs } = req.query;

    let where = [];
    let whereParams = [];
    let having = [];
    let havingParams = [];

    if (year) {
      where.push("s.year = ?");
      whereParams.push(year);
    }

    if (student_id) {
      where.push("s.student_id = ?");
      whereParams.push(student_id);
    }

    // ⬇ IMPORTANT: backlog filter goes to HAVING
    if (backlogs !== undefined && backlogs !== '') {
  having.push("IFNULL(SUM(sr.total_backlogs), 0) = ?");
  havingParams.push(Number(backlogs));
}

    const sql = `
      SELECT
        s.student_id,
        s.name,
        s.year,
        IFNULL(SUM(sr.total_backlogs), 0) AS remaining_backlogs,
        CASE 
          WHEN IFNULL(SUM(sr.total_backlogs), 0) <= 3 THEN 'Eligible'
          ELSE 'Not Eligible'
        END AS room_status
      FROM students s
      LEFT JOIN student_results sr ON s.student_id = sr.student_id
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      GROUP BY s.student_id, s.name, s.year
      ${having.length ? "HAVING " + having.join(" AND ") : ""}
    `;

    const [students] = await db.promise().query(
      sql,
      [...whereParams, ...havingParams]
    );

    res.render("warden/eligibility", {
      isSpa,
      students
    });

  } catch (err) {
    console.error("Eligibility Error:", err);
    res.status(500).send("Eligibility error");
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

    const [students] = await db.promise().query(`
      SELECT 
        s.student_id,
        s.name,
        s.email,
        s.room_no,
        s.course,
        s.year,
        s.total_fee,

        IFNULL(SUM(fr.amount_paid), 0) AS total_paid,
        (s.total_fee - IFNULL(SUM(fr.amount_paid), 0)) AS remaining_fee,

        s.profile_image
      FROM students s
      LEFT JOIN fee_receipts fr 
        ON fr.student_id = s.student_id
        AND fr.status = 'Verified'
      WHERE s.name LIKE ?
         OR s.student_id LIKE ?
         OR s.room_no LIKE ?
      GROUP BY s.student_id
      ORDER BY s.student_id
    `, [search, search, search]);

    res.render("warden/viewStudents", {
      students,
      search: req.query.search || ""
    });

  } catch (err) {
    console.error("❌ Warden viewStudents error:", err);
    res.status(500).send("Error fetching students");
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

  res.render("warden/uploadSBI", {
    success: req.query.success,
    error: req.query.error
  });
});

app.post(
  "/warden/uploadSBI",
  upload.single("sbi_excel"), // ✅ IMPORTANT
  async (req, res) => {

    if (!req.session.user || req.session.role !== "warden") {
      return res.redirect("/choose_login");
    }

    try {
      if (!req.file) {
        return res.render("warden/uploadSBI", {
          success: null,
          error: "No Excel uploaded"
        });
      }

      const XLSX = require("xlsx");

      const workbook = XLSX.readFile(req.file.path);
      const sheet = workbook.Sheets[workbook.SheetNames[0]];
      const rows = XLSX.utils.sheet_to_json(sheet, { defval: "" });

      let inserted = 0;

for (const row of rows) {

  const ref_id = String(row["Bank Reference No"] || "").trim();

  const amount = parseFloat(
    String(row["Amount"] || "").replace(/,/g, "")
  );

  if (!ref_id || isNaN(amount) || amount <= 0) continue;

  await db.promise().query(
    `
    INSERT IGNORE INTO sbi_transactions
    (ref_id, amount, status, uploaded_at)
    VALUES (?, ?, 'Pending', NOW())
    `,
    [ref_id, amount]
  );

  inserted++;
}

console.log("✅ Inserted transactions:", inserted);


      res.render("warden/uploadSBI", {
        success: `✅ SBI Excel uploaded. ${inserted} transactions saved.`,
        error: null
      });

    } catch (err) {
      console.error("❌ SBI Excel parse error:", err);
      res.render("warden/uploadSBI", {
        success: null,
        error: "Excel parsing failed"
      });
    }
  }
);



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
        // after successful registration in DB
req.flash('success', 'Registration successful — please login.');
req.session.save(() => res.redirect('/login/admin'));

        
      }
    );
  });
});

// Admin login
app.post("/login/admin", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM admins WHERE email=?", [email], (err, rows) => {

    if (err) {
      console.error(err);
      return res.render("login_admin", {
        message: "Server error. Please try again.",
        messageType: "error"
      });
    }

    if (!rows.length) {
      return res.render("login_admin", {
        message: "Invalid Email or Password",
        messageType: "error"
      });
    }

    bcrypt.compare(password, rows[0].password).then((match) => {

      if (!match) {
        return res.render("login_admin", {
          message: "Invalid Email or Password",
          messageType: "error"
        });
      }

      // ✅ SUCCESS (ONLY ONCE)
      req.session.user = rows[0];
      req.session.role = "admin";

      req.flash("success", "Login successful — welcome back!");

      return req.session.save(() => {
        res.redirect("/admin/dashboard");
      });
    });
  });
});








// ======================
// ADMIN DASHBOARD
// ======================
app.get("/admin/dashboard", async (req, res) => {
    if (!req.session.user || req.session.role !== "admin") {
        return res.redirect("/choose_login");
    }


    // 🔔 FETCH LATEST NOTICE
    let latestNotice = null;
    try {
        const [rows] = await db.promise().query(
            "SELECT * FROM notices ORDER BY created_at DESC LIMIT 1"
        );
        latestNotice = rows.length > 0 ? rows[0] : null;
    } catch (err) {
        console.error("Error fetching notice:", err);
    }

    // 👌 Render page with notice
    res.render("admin/dashboard", {
  user: req.session.user,
  session: req.session,
  latestNotice,
  success: req.flash("success")   // 🔥 ADD THIS


    });
});

app.get('/admin/complaints', async (req, res) => {
  if (!req.session.user || req.session.role !== 'admin') {
    return res.redirect('/login/admin');
  }

  let latestNotice = null;

  try {
    const [rows] = await db.promise().query(
      "SELECT * FROM notices ORDER BY created_at DESC LIMIT 1"
    );
    latestNotice = rows.length > 0 ? rows[0] : null;
  } catch (err) {
    console.error("Error fetching notice:", err);
  }

  // 👌 Render page with notice
  res.render("admin/dashboard", {
    user: req.session.user,
    session: req.session,
    latestNotice
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
        const pdfData = await pdfparse(pdfBuffer);

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
app.post("/warden/uploadSBI", upload.single("sbi_pdf"), async (req, res) => {
  if (!req.session.user || req.session.role !== "warden") {
    return res.redirect("/choose_login");
  }

  try {
    if (!req.file) return res.send("No PDF uploaded!");

    const pdfBuffer = fs.readFileSync(req.file.path);
    const pdfData = await pdfparse(pdfBuffer);

    const lines = pdfData.text.split("\n");
    let inserted = 0;

    for (const line of lines) {

      /*
        SAMPLE LINE:
        21/09/2024 BY TRANSFER-INB DUN2006175IU093905 17,000.00
      */

      const match = line.match(
        /(\d{2}\/\d{2}\/\d{4}).*?(DUN\d+IU\d+).*?([\d,]+\.\d{2})$/
      );

      if (!match) continue;

      const txn_date = match[1];
      const bank_ref_no = match[2];
      const amount = parseFloat(match[3].replace(/,/g, ""));

      if (!amount || amount <= 0) continue;

      console.log("INSERTING TXN:", txn_date, bank_ref_no, amount);

      await db.promise().query(`
        INSERT INTO bank_transactions
        (
          txn_date,
          transaction_date,
          total_amount,
          bank_ref_no,
          bank_source,
          uploaded_pdf,
          uploaded_by,
          status,
          created_at
        )
        VALUES (?, ?, ?, ?, 'SBI_COLLECT', ?, ?, 'UNMATCHED', NOW())
      `, [
        txn_date,
        txn_date,
        amount,
        bank_ref_no,
        req.file.filename,
        req.session.user
      ]);

      inserted++;
    }

    res.send(`✅ SBI PDF processed successfully. ${inserted} transactions inserted.`);

  } catch (err) {
    console.error("SBI PDF ERROR:", err);
    res.status(500).send("Error processing SBI PDF");
  }
});
app.get("/admin/upload-bank-statement", (req, res) => {
  if (!req.session.user || req.session.role !== "admin") {
    return res.redirect("/choose_login");
  }

  res.render("admin/upload-bank-statement");
});


app.post(
  "/admin/upload-bank-statement",
  upload.single("statement_file"),
  async (req, res) => {
    if (!req.file) return res.send("❌ No file uploaded");

    const pdfPath = req.file.path;
    const sourceType = req.body.source_type;

    try {
      // 🔥 CALL PYTHON HERE
      const transactions = await parseSbiPdf(pdfPath);

      if (!transactions.length) {
        return res.send("❌ No valid transactions found in PDF");
      }

      const uploadedBy =
        req.session?.user?.admin_id ||
        req.session?.admin?.admin_id ||
        1;

      let inserted = 0;

      for (const t of transactions) {
        const [result] = await db.promise().query(
          `
          INSERT IGNORE INTO bank_transactions
          (
            transaction_date,
            bank_ref_no,
            total_amount,
            payer_name,
            bank_source,
            uploaded_pdf,
            uploaded_by,
            status,
            created_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, 'UNMATCHED', NOW())
          `,
          [
            t.transaction_date,
            t.bank_ref_no,
            t.amount,
            "UNKNOWN",
            sourceType,
            req.file.filename,
            uploadedBy
          ]
        );

        inserted += result.affectedRows;
      }

      res.send(`
        ✅ Bank statement processed<br>
        📄 Parsed: ${transactions.length}<br>
        💾 Inserted: ${inserted}
      `);

    } catch (err) {
      console.error(err);
      res.status(500).send("❌ Error parsing PDF");
    }
  }
);


app.get("/warden/student/:student_id", async (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "warden") {
      return res.redirect("/choose_login");
    }

    const student_id = req.params.student_id;

    /* ============================
       1️⃣ STUDENT BASIC INFO
       ============================ */
    const [[student]] = await db.promise().query(
      `SELECT * FROM students WHERE student_id=?`,
      [student_id]
    );
    if (!student) return res.send("Student not found");

    const maxYear = Number(student.year);

    /* ============================
       2️⃣ ATTENDANCE SUMMARY
       ============================ */
    const [[attendanceSummary]] = await db.promise().query(
      `SELECT COUNT(*) AS total_classes,
              SUM(status='Present') AS present_count
       FROM attendance
       WHERE student_id=?`,
      [student_id]
    );

    /* ============================
       3️⃣ YEARLY FEE STRUCTURE (🔥 FIXED)
       ============================ */
    const [feeRows] = await db.promise().query(
  `
  SELECT
    CAST(year AS UNSIGNED) AS year,
    room_rent,
    mess_bill1,
    mess_bill2
  FROM yearly_fee
  WHERE CAST(year AS UNSIGNED) BETWEEN 1 AND ?
  ORDER BY CAST(year AS UNSIGNED)
  `,
  [maxYear]
);


    /* ============================
       4️⃣ OLD VERIFIED RECEIPTS
       ============================ */
    const [oldReceipts] = await db.promise().query(
      `
      SELECT CAST(year AS UNSIGNED) AS year,
             amount_paid,
             remarks
      FROM fee_receipts
      WHERE student_id=? AND status='Verified'
      `,
      [student_id]
    );

    const oldMap = {};
    oldReceipts.forEach(r => {
      const y = Number(r.year);
      if (!oldMap[y]) oldMap[y] = { room: 0, mess1: 0, mess2: 0 };

      const key = (r.remarks || "").toLowerCase();
      if (key.includes("room")) oldMap[y].room += Number(r.amount_paid);
      else if (key.includes("mess bill1")) oldMap[y].mess1 += Number(r.amount_paid);
      else if (key.includes("mess bill2")) oldMap[y].mess2 += Number(r.amount_paid);
    });

    /* ============================
       5️⃣ NEW BANK SPLITS
       ============================ */
    const [newRows] = await db.promise().query(
      `
      SELECT CAST(academic_year AS UNSIGNED) AS academic_year,
             component,
             allocated_amount
      FROM student_payment_allocations
      WHERE student_id=?
      `,
      [student_id]
    );

    const newMap = {};
    newRows.forEach(r => {
      const y = Number(r.academic_year);
      if (!newMap[y]) newMap[y] = { room: 0, mess1: 0, mess2: 0 };

      if (r.component === "ROOM_RENT") newMap[y].room += Number(r.allocated_amount);
      if (r.component === "MESS_BILL_1") newMap[y].mess1 += Number(r.allocated_amount);
      if (r.component === "MESS_BILL_2") newMap[y].mess2 += Number(r.allocated_amount);
    });

    /* ============================
       6️⃣ MERGED FEE SUMMARY (🔥 CORRECT)
       ============================ */
    const feeSummary = feeRows.map(y => {
      const year = Number(y.year);

      // FIXED AMOUNTS
      const roomTotal  = Number(y.room_rent);
      const mess1Total = Number(y.mess_bill1);
      const mess2Total = Number(y.mess_bill2);

      // PAID
      const roomPaid  = (oldMap[year]?.room || 0)  + (newMap[year]?.room || 0);
      const mess1Paid = (oldMap[year]?.mess1 || 0) + (newMap[year]?.mess1 || 0);
      const mess2Paid = (oldMap[year]?.mess2 || 0) + (newMap[year]?.mess2 || 0);

      const totalFee  = roomTotal + mess1Total + mess2Total;
      const totalPaid = roomPaid + mess1Paid + mess2Paid;

      return {
        year,

        room_rent: roomTotal.toFixed(2),
        mess_bill1: mess1Total.toFixed(2),
        mess_bill2: mess2Total.toFixed(2),

        room_rent_paid: roomPaid.toFixed(2),
        room_rent_due:  Math.max(roomTotal - roomPaid, 0).toFixed(2),

        mess_bill1_paid: mess1Paid.toFixed(2),
        mess_bill1_due:  Math.max(mess1Total - mess1Paid, 0).toFixed(2),

        mess_bill2_paid: mess2Paid.toFixed(2),
        mess_bill2_due:  Math.max(mess2Total - mess2Paid, 0).toFixed(2),

        total_fee: totalFee.toFixed(2),
        total_paid: totalPaid.toFixed(2),
        total_due: Math.max(totalFee - totalPaid, 0).toFixed(2),

        status:
          totalPaid >= totalFee
            ? "Paid"
            : totalPaid > 0
            ? "Partial"
            : "Not Paid"
      };
    });

    /* ============================
       7️⃣ RENDER
       ============================ */
    res.render("warden/student_profile", {
      student,
      attendanceSummary: attendanceSummary || {
        total_classes: 0,
        present_count: 0
      },
      feeSummary
    });

  } catch (err) {
    console.error("❌ Error loading student profile:", err);
    res.status(500).send("Server Error");
  }
});



// ✅ WARDEN VIEW STUDENT PROFILE (FINAL FIX)
app.get("/warden/room/:room_no", async (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "warden") {
      return res.redirect("/choose_login");
    }

    const { room_no } = req.params;

    const [students] = await db.promise().query(
      `SELECT student_id, student_unique_id, name, course, year
       FROM students WHERE room_no=? ORDER BY name`,
      [room_no]
    );

    for (let stu of students) {

      const [feeRows] = await db.promise().query(`
        SELECT yf.year AS academic_year,
               yf.amount AS total_fee,
               IFNULL(SUM(CASE WHEN fr.status='Verified' THEN fr.amount_paid END),0) AS verified_amount
        FROM yearly_fee yf
        LEFT JOIN fee_receipts fr
          ON fr.student_id=? AND yf.year=fr.year
        WHERE yf.year <= ?
        GROUP BY yf.year, yf.amount
      `,[stu.student_id, stu.year]);

      stu.feeSummary = feeRows.map(r=>({
        academic_year:r.academic_year,
        verified_amount:+r.verified_amount,
        due_amount:(+r.total_fee - +r.verified_amount)
      }));

      const [[att]] = await db.promise().query(
        `SELECT COUNT(*) total_classes,
                SUM(status='Present') present_count
         FROM attendance WHERE student_id=?`,
        [stu.student_id]
      );

      stu.attendanceSummary = att || { total_classes:0, present_count:0 };
    }

    // 🔑 SPA SUPPORT
    if(req.headers['x-requested-with']==='XMLHttpRequest'){
      return res.render("warden/room_students",{ room_no, students });
    }

    res.render("warden/dashboard",{
      page:"warden/room_students",
      room_no,
      students
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
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

  SELECT fr.receipt_id,
         fr.student_id,
         COALESCE(s.name, 'Not Found') AS name,
         COALESCE(s.course, '-') AS course,
         COALESCE(s.year, '-') AS year,
         COALESCE(s.room_no, '-') AS room_no,
         fr.ref_id,
         fr.amount_paid,
         fr.status,
         fr.pdf_path,
         fr.created_at
  FROM fee_receipts fr
  LEFT JOIN students s 
       ON LOWER(TRIM(fr.student_id)) = LOWER(TRIM(s.student_id))
  ORDER BY fr.created_at DESC
`);



    res.render("warden/viewReceipts", { receipts });

  } catch (err) {

    console.error("❌ Error loading receipts:", err);

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

    /* ============================
       1️⃣ STUDENT BASIC INFO
       ============================ */
    const [[student]] = await db.promise().query(
      `SELECT * FROM students WHERE student_id=?`,
      [student_id]
    );
    if (!student) return res.send("Student not found");

    const maxYear = parseInt(student.year);

    /* ============================
       2️⃣ ATTENDANCE SUMMARY
       ============================ */
    const [[attendanceSummary]] = await db.promise().query(
      `SELECT COUNT(*) AS total_classes,
              SUM(status='Present') AS present_count
       FROM attendance WHERE student_id=?`,
      [student_id]
    );

    /* ============================
       3️⃣ YEARLY FEE STRUCTURE
       ============================ */
    const [feeRows] = await db.promise().query(
      `SELECT * FROM yearly_fee WHERE year <= ? ORDER BY year`,
      [maxYear]
    );

    /* ============================
       4️⃣ OLD VERIFIED RECEIPTS
       ============================ */
    const [oldReceipts] = await db.promise().query(
      `SELECT year, amount_paid, remarks
       FROM fee_receipts
       WHERE student_id=? AND status='Verified'`,
      [student_id]
    );

    const oldMap = {};
    oldReceipts.forEach(r => {
      if (!oldMap[r.year]) {
        oldMap[r.year] = { room: 0, mess1: 0, mess2: 0 };
      }

      const key = (r.remarks || "").toLowerCase();
      if (key.includes("room")) oldMap[r.year].room += Number(r.amount_paid);
      else if (key.includes("mess bill1")) oldMap[r.year].mess1 += Number(r.amount_paid);
      else if (key.includes("mess bill2")) oldMap[r.year].mess2 += Number(r.amount_paid);
    });

    /* ============================
       5️⃣ NEW BANK SPLITS
       ============================ */
    const [newRows] = await db.promise().query(
      `SELECT academic_year, component, allocated_amount
       FROM student_payment_allocations
       WHERE student_id=?`,
      [student_id]
    );

    const newMap = {};
    newRows.forEach(r => {
      if (!newMap[r.academic_year]) {
        newMap[r.academic_year] = { room: 0, mess1: 0, mess2: 0 };
      }

      if (r.component === "ROOM_RENT") newMap[r.academic_year].room += Number(r.allocated_amount);
      if (r.component === "MESS_BILL_1") newMap[r.academic_year].mess1 += Number(r.allocated_amount);
      if (r.component === "MESS_BILL_2") newMap[r.academic_year].mess2 += Number(r.allocated_amount);
    });

    /* ============================
       6️⃣ MERGED FEE SUMMARY
       ============================ */
    const feeSummary = feeRows.map(y => {
      const year = y.year;

      const roomTotal = Number(y.room_rent || 0);
      const mess1Total = Number(y.mess_bill1 || 0);
      const mess2Total = Number(y.mess_bill2 || 0);

      const roomPaid =
        (oldMap[year]?.room || 0) +
        (newMap[year]?.room || 0);

      const mess1Paid =
        (oldMap[year]?.mess1 || 0) +
        (newMap[year]?.mess1 || 0);

      const mess2Paid =
        (oldMap[year]?.mess2 || 0) +
        (newMap[year]?.mess2 || 0);

      const totalFee = roomTotal + mess1Total + mess2Total;
      const totalPaid = roomPaid + mess1Paid + mess2Paid;

      return {
        academic_year: year,
        room_rent: roomTotal.toFixed(2),
        mess_bill1: mess1Total.toFixed(2),
        mess_bill2: mess2Total.toFixed(2),
        total_fee: totalFee.toFixed(2),
        paid_amount: totalPaid.toFixed(2),
        due_amount: Math.max(totalFee - totalPaid, 0).toFixed(2)
      };
    });

    /* ============================
       7️⃣ RENDER ADMIN VIEW
       ============================ */
    res.render("admin/student_profile", {
      student,
      attendanceSummary: attendanceSummary || {
        total_classes: 0,
        present_count: 0
      },
      feeSummary
    });

  } catch (err) {
    console.error("❌ Admin student profile error:", err);
    res.status(500).send("Server Error");
  }
});


app.get("/admin/viewStudents", async (req, res) => {
  if (!req.session.user || req.session.role !== "admin") {
    return res.redirect("/choose_login");
  }

  try {
    const search = req.query.search ? `%${req.query.search}%` : "%%";

    const [students] = await db.promise().query(`
      SELECT 
        s.student_id,
        s.name,
        s.email,
        s.room_no,
        s.course,
        s.year,
        s.total_fee,

        IFNULL(SUM(fr.amount_paid), 0) AS total_paid,
        (s.total_fee - IFNULL(SUM(fr.amount_paid), 0)) AS remaining_fee,

        s.profile_image
      FROM students s
      LEFT JOIN fee_receipts fr 
        ON fr.student_id = s.student_id
        AND fr.status = 'Verified'
      WHERE s.name LIKE ?
         OR s.student_id LIKE ?
         OR s.room_no LIKE ?
      GROUP BY s.student_id
      ORDER BY s.student_id
    `, [search, search, search]);

    res.render("admin/viewStudents", {
      students,
      search: req.query.search || "",
      session: req.session
    });

  } catch (err) {
    console.error("❌ Admin viewStudents error:", err);
    res.status(500).send("Error fetching students");
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
  if (!req.session || req.session.role !== 'admin') {
    return res.redirect('/choose_login');
  }

  try {
    const [accepted] = await db.promise().query(`
      SELECT fr.*, s.name, s.student_unique_id
      FROM fee_receipts fr
      JOIN students s ON fr.student_id = s.student_id
      WHERE LOWER(fr.status) IN ('paid','verified','accepted','success')
      ORDER BY fr.verified_at DESC
    `);

    console.log('ADMIN RECEIPTS:', accepted.length);

    res.render('admin/acceptedReceipts', { accepted });
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error");
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
            // after successful registration in DB
req.flash('success', 'Registration successful — please login.');
req.session.save(() => res.redirect('/login/security'));

           
          }
        );
      }
    );
  });
});


// Security login
app.post("/login/security", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email=? AND role='security'",
    [email],
    (err, rows) => {

      if (err) {
        console.error(err);
        return res.render("login_security", {
          message: "Server error. Please try again.",
          messageType: "error"
        });
      }

      if (!rows.length) {
        return res.render("login_security", {
          message: "Invalid Email or Password",
          messageType: "error"
        });
      }


      bcrypt.compare(password, rows[0].password).then((match) => {

        if (!match) {
          return res.render("login_security", {
            message: "Invalid Email or Password",
            messageType: "error"
          });
        }

        // ✅ SUCCESS
        req.session.user = rows[0];
        req.session.role = "security";

        req.flash("success", "Login successful — welcome back!");

        req.session.save(() => {
          return res.redirect("/security/dashboard");
        });
      });
    }
  );

});



app.get("/security/dashboard", async (req, res) => {
  try {
    if (!req.session.user || req.session.role !== "security") {
      return res.redirect("/login/security");
    }

    const isSpa =
      req.xhr || req.headers["x-requested-with"] === "XMLHttpRequest";

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

    const roomQuery = req.query.room || "";
    if (roomQuery.trim() !== "") {
      sql += " AND s.room_no = ?";
      params.push(roomQuery.trim());
    }

    sql += " ORDER BY o.approved_at DESC";

    const [outpasses] = await db.promise().query(sql, params);
    const countToday = outpasses.length;

    // 🔥 SPA request
    if (isSpa) {
      return res.render("security/todayOutpasses", {
        outpasses,
        countToday,
        isSpa: true
      });
    }

    // Normal page
    res.render("security/dashboard", {
      user: req.session.user,
      session: req.session,
      outpasses,
      roomQuery,
      countToday,
      success: req.flash("success")
    });

  } catch (err) {
    console.error("❌ Security Dashboard Error:", err);
    res.status(500).send("Error loading security dashboard");
  }
});



//View outpasses
app.get("/security/viewOutpasses", (req, res) => {

  if (!req.session.user || req.session.role !== "security") {
    return res.redirect("/login/security");
  }

  db.query(
    "SELECT * FROM outpasses WHERE status IN ('Approved','Exited') ORDER BY out_date DESC",
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Error fetching outpasses");
      }

      res.render("security/viewOutpasses", {
        outpasses: results,
        session: req.session
      });
    }
  );
});




    




// Mark Exit
app.post("/security/markExit/:id", (req, res) => {
  if (!req.session.user || req.session.role !== "security") {
    return res.status(401).json({ success: false });
  }

  db.query(
    "UPDATE outpasses SET status='Exited' WHERE outpass_id=?",
    [req.params.id],
    err => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false });
      }

      // ✅ SPA (fetch)
      if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
        return res.json({ success: true, status: "Exited" });
      }

      // ✅ Normal page
      res.redirect("/security/viewOutpasses");
    }
  );
});


// Mark Return
app.post("/security/markReturn/:id", (req, res) => {
  if (!req.session.user || req.session.role !== "security") {
    return res.status(401).json({ success: false });
  }

  db.query(
    "UPDATE outpasses SET status='Returned' WHERE outpass_id=?",
    [req.params.id],
    err => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false });
      }

      // ✅ SPA (fetch)
      if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
        return res.json({ success: true, status: "Returned" });
      }

      // ✅ Normal page
      res.redirect("/security/viewOutpasses");
    }
  );
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

    // 🔥 SPA request → return ONLY rows
    if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
      return res.render("security/partials/todayOutpassesRows", {
        outpasses: rows
      });
    }

    // normal request
    res.render("security/todayOutpasses", { outpasses: rows });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error searching outpasses");
  }
});

app.get("/security/emergencyOutpasses", async (req, res) => {
  try {
    const [rows] = await db.promise().query(`
      SELECT 
        o.*,
        s.name AS student_name,
        s.room_no
      FROM outpasses o
      LEFT JOIN students s 
        ON o.student_id = s.student_id
      WHERE 
        o.outpass_type = 'Emergency'
        AND o.status = 'Approved'
      ORDER BY o.created_at DESC
    `);

    res.render("security/emergencyOutpasses", {
      outpasses: rows
    });

  } catch (err) {
    console.error("❌ Emergency Outpasses Error:", err);
    res.status(500).send("Error loading emergency outpasses");
  }
});
// Show notice form
app.get("/notice/create", (req, res) => {
    res.render("notice_form");
});

// Save notice
app.post("/notice/create", (req, res) => {
    const { title, description } = req.body;

    // Detect user role (Admin/Warden)
    const role = req.session?.user?.role || "Admin";
    const hostelId = req.session?.user?.hostel_id || null;

    const sql = `
        INSERT INTO notices (title, description, posted_by, hostel_id)
        VALUES (?, ?, ?, ?)
    `;

    db.query(sql, [title, description, role, hostelId], (err) => {
        if (err) {
            console.log("Notice Insert Error:", err);
            req.flash("error", "Failed to post notice.");
            return res.redirect("back");
        }

        req.flash("success", "Notice posted successfully!");
        res.redirect("back");
    });
});

// Show notice form
app.get("/notice/create", (req, res) => {

  if (!req.session.user || !["warden", "admin"].includes(req.session.role)) {
    return res.redirect("/choose_login");
  }

  const isSpa = req.headers["x-requested-with"] === "XMLHttpRequest";

  res.render("notice_form", {
    isSpa,
    role: req.session.role   // 🔥 pass role if needed
  });
});



// Save notice
app.post("/notice/create", (req, res) => {
  const { title, description } = req.body;

  const role = req.session.role;
  const hostelId = req.session.user?.hostel_id || null;

  db.query("DELETE FROM notices", err => {
    if (err) {
      req.flash("error", "Failed to update notice.");
      return res.redirect("back");
    }

    const q = `
      INSERT INTO notices (title, description, posted_by, hostel_id, created_at)
      VALUES (?, ?, ?, ?, NOW())
    `;

    db.query(q, [title, description, role, hostelId], err => {
      if (err) {
        req.flash("error", "Failed to post notice.");
        return res.redirect("back");
      }

      const redirectTo =
        role === "admin"
          ? "/admin/dashboard"
          : "/warden/dashboard";

      req.flash("success", "Notice posted successfully!");
      res.redirect(redirectTo);
    });
  });
});

app.get("/admin/bank-transactions", async (req, res) => {
  try {
    const q = req.query.q ? `%${req.query.q}%` : "%%";

    const [rows] = await db.promise().query(`
      SELECT *
      FROM bank_transactions
      WHERE 
        bank_ref_no LIKE ?
        OR bank_source LIKE ?
        OR total_amount LIKE ?
      ORDER BY created_at DESC
    `, [q, q, q]);

    res.render("admin/bank-transactions", {
      rows,
      query: req.query.q || ""
    });

  } catch (err) {
    console.error(err);
    res.send("Error loading bank transactions");
  }
});

app.get("/admin/bank/:id/verify", async (req, res) => {
  const id = req.params.id;

  const [[txn]] = await db.promise().query(
    "SELECT * FROM bank_transactions WHERE id=?",
    [id]
  );

  if (!txn) return res.send("Transaction not found");

  res.render("admin/verify_bank_txn", { txn });
});

app.post("/admin/bank/:id/verify", async (req, res) => {
  await db.promise().query(
    "UPDATE bank_transactions SET status='PARTIALLY_MATCHED' WHERE id=?",
    [req.params.id]
  );

  res.redirect(`/admin/bank/${req.params.id}/assign`);
});

app.get("/admin/bank/:id/assign", async (req, res) => {
  const id = req.params.id;

  const [[txn]] = await db.promise().query(
    "SELECT * FROM bank_transactions WHERE id=?",
    [id]
  );

  const [students] = await db.promise().query(
    "SELECT student_id, name FROM students"
  );

  res.render("admin/assign_student_payment", { txn, students });
});
app.post("/admin/bank/:id/split", async (req, res) => {
  const conn = await db.promise().getConnection();

  try {
    await conn.beginTransaction();

    const bankTxnId = req.params.id;
    const {
      student_id,
      academic_year,
      room_rent,
      mess1,
      mess2
    } = req.body;

    const components = [
      { type: "ROOM_RENT", amount: room_rent },
      { type: "MESS_BILL_1", amount: mess1 },
      { type: "MESS_BILL_2", amount: mess2 }
    ];

    let allocated = 0;

    for (let c of components) {
      const amt = Number(c.amount || 0);
      if (amt <= 0) continue;

      allocated += amt;

      // allocation table
      await conn.query(`
        INSERT INTO student_payment_allocations
        (bank_txn_id, student_id, academic_year, component, allocated_amount)
        VALUES (?, ?, ?, ?, ?)
      `, [bankTxnId, student_id, academic_year, c.type, amt]);

      // yearly fee update
      await conn.query(`
        UPDATE yearly_fee_components
        SET paid_amount = paid_amount + ?,
            remaining_amount = total_amount - (paid_amount + ?)
        WHERE student_id=? AND component=? AND academic_year=?
      `, [amt, amt, student_id, c.type, academic_year]);

      // ledger credit
      await conn.query(`
        INSERT INTO student_ledger
        (student_id, source_type, credit, bank_txn_id, reference_note)
        VALUES (?, ?, ?, ?, ?)
      `, [student_id, c.type, amt, bankTxnId, "Bank payment"]);
    }

    // get bank amount
    const [[txn]] = await conn.query(
      "SELECT total_amount FROM bank_transactions WHERE id=?",
      [bankTxnId]
    );

    const extra = txn.total_amount - allocated;

    if (extra > 0) {
      await conn.query(`
        INSERT INTO refunds_adjustments
        (student_id, bank_txn_id, extra_amount, status)
        VALUES (?, ?, ?, 'HOLD')
      `, [student_id, bankTxnId, extra]);
    }

    await conn.query(
      "UPDATE bank_transactions SET status='FULLY_MATCHED' WHERE id=?",
      [bankTxnId]
    );

    await conn.commit();
    res.redirect("/admin/bank-transactions");

  } catch (err) {
    await conn.rollback();
    console.error(err);
    res.send("Payment split failed");

  } finally {
    conn.release();
  }
});




// app.post("/admin/bank-transaction/add", async (req, res) => {
//   const {
//     txn_date,
//     transaction_date,
//     total_amount,
//     bank_ref_no,
//     payer_name,
//     bank_source
//   } = req.body;

//   await db.promise().query(`
//     INSERT INTO bank_transactions
//     (
//       txn_date,
//       transaction_date,
//       total_amount,
//       bank_ref_no,
//       payer_name,
//       bank_source,
//       status,
//       created_at
//     )
//     VALUES (?, ?, ?, ?, ?, ?, 'UNMATCHED', NOW())
//   `, [
//     txn_date,
//     transaction_date,
//     total_amount,
//     bank_ref_no,
//     payer_name,
//     bank_source
//   ]);

//   res.redirect("/admin/bank-transactions");
// });

app.post("/payment/claim", async (req, res) => {
  const { student_id, amount, ref_no, payment_date, proof_type } = req.body;

  await db.promise().query(`
    INSERT INTO payment_claims
    (student_id, amount, ref_no, payment_date, proof_type, status)
    VALUES (?, ?, ?, ?, ?, 'SUBMITTED')
  `, [student_id, amount, ref_no, payment_date, proof_type]);

  res.redirect("/student/payments");
});
app.post('/admin/bank-verify', async (req, res) => {
  try {
    const { bank_txn_id } = req.body;

    // 1️⃣ Fetch bank transaction
    const [[txn]] = await db.promise().query(`
      SELECT * FROM bank_transactions
      WHERE id=? AND status='PENDING'
    `, [bank_txn_id]);

    if (!txn) {
      return res.send("Invalid or already processed transaction");
    }

    // 2️⃣ Try auto-detection
    const student_id = await findStudentForTransaction({
      amount: txn.amount,
      reference_no: txn.reference_no,
      txn_date: txn.txn_date
    });

    if (!student_id) {
      // ❗ Admin must manually assign
      return res.redirect(`/admin/manual-match/${bank_txn_id}`);
    }

    // 3️⃣ Create verification record
    await db.promise().query(`
      INSERT INTO verification_matches
      (bank_txn_id, student_id, verified_by, verified_at)
      VALUES (?, ?, ?, NOW())
    `, [bank_txn_id, student_id, req.session.admin_id]);

    // 4️⃣ Mark txn verified
    await db.promise().query(`
      UPDATE bank_transactions
      SET status='VERIFIED'
      WHERE id=?
    `, [bank_txn_id]);

    // 5️⃣ Go to split screen
    res.redirect(`/admin/payment/split/${bank_txn_id}`);

  } catch (err) {
    console.error(err);
    res.status(500).send("Bank verification failed");
  }
});
app.get("/admin/manual-match/:bank_txn_id", async (req, res) => {
  const { bank_txn_id } = req.params;

  // Bank transaction
  const [[txn]] = await db.promise().query(`
    SELECT * FROM bank_transactions WHERE id=?
  `, [bank_txn_id]);

  // Pending student claims (same amount ±2 days)
  const [claims] = await db.promise().query(`
    SELECT c.*, s.name
    FROM payment_claims c
    JOIN students s ON s.student_id = c.student_id
    WHERE c.status='SUBMITTED'
      AND c.amount = ?
      AND c.payment_date BETWEEN DATE_SUB(?, INTERVAL 2 DAY)
                            AND DATE_ADD(?, INTERVAL 2 DAY)
  `, [txn.amount, txn.txn_date, txn.txn_date]);

  res.render("admin/manual_match", {
    txn,
    claims
  });
});
app.post("/admin/manual-match/confirm", async (req, res) => {
  const { bank_txn_id, claim_id } = req.body;

  // get student from claim
  const [[claim]] = await db.promise().query(`
    SELECT student_id FROM payment_claims WHERE id=?
  `, [claim_id]);

  await db.promise().query(`
    INSERT INTO verification_matches
    (bank_txn_id, claim_id, verified_by, verified_at)
    VALUES (?, ?, ?, NOW())
  `, [bank_txn_id, claim_id, req.session.admin_id]);

  await db.promise().query(`
    UPDATE payment_claims SET status='VERIFIED' WHERE id=?
  `, [claim_id]);

  await db.promise().query(`
    UPDATE bank_transactions SET status='VERIFIED' WHERE id=?
  `, [bank_txn_id]);

  res.redirect(`/admin/payment/split/${bank_txn_id}`);
});

app.post("/admin/payment/verify", async (req, res) => {
  const { bank_txn_id, claim_id } = req.body;

  await db.promise().query(`
    INSERT INTO verification_matches
    (bank_txn_id, claim_id, verified_by, verified_at)
    VALUES (?, ?, ?, NOW())
  `, [bank_txn_id, claim_id, req.session.admin_id]);
  await db.promise().query(`
  UPDATE bank_transactions SET status='VERIFIED' WHERE id=?
`, [bank_txn_id]);


  await db.promise().query(`
    UPDATE payment_claims SET status='VERIFIED' WHERE id=?
  `, [claim_id]);

  res.redirect("/admin/verify-payments");
});
app.get("/admin/verify-payments", async (req, res) => {
  const { claim_id } = req.query;

  if (!claim_id) {
    return res.send("Claim ID missing");
  }

  // 1️⃣ Get the claim
  const [[claim]] = await db.promise().query(
    "SELECT * FROM payment_claims WHERE id=?",
    [claim_id]
  );

  if (!claim) {
    return res.send("Claim not found");
  }

  // 2️⃣ Find possible bank transactions (same amount, pending)
  const [txns] = await db.promise().query(
    `
    SELECT *
    FROM bank_transactions
    WHERE amount = ?
      AND status = 'PENDING'
    ORDER BY id DESC
    `,
    [claim.amount]
  );

  res.render("admin/verify-payments", {
    claim,
    txns
  });
});


app.get("/admin/payment-split", async (req, res) => {
  const { bank_txn_id } = req.query;

  if (!bank_txn_id) {
    return res.send("Bank Transaction ID missing");
  }

  // 1️⃣ Get bank transaction
  const [[txn]] = await db.promise().query(
    "SELECT * FROM bank_transactions WHERE id=?",
    [bank_txn_id]
  );

  if (!txn) {
    return res.send("Bank transaction not found");
  }

  // 2️⃣ Get verified claims linked to this txn
  const [claims] = await db.promise().query(
    `
    SELECT pc.*
    FROM payment_claims pc
    JOIN verification_matches vm ON vm.claim_id = pc.id
    WHERE vm.bank_txn_id = ?
      AND pc.status = 'VERIFIED'
    `,
    [bank_txn_id]
  );

  res.render("admin/payment-split", {
    txn,
    claims
  });
});

app.post("/admin/payment-split", async (req, res) => {
  const conn = await db.promise().getConnection();

  try {
    await conn.beginTransaction();

    const {
      bank_txn_id,
      student_id,
      academic_year,
      room_rent,
      mess1,
      mess2
    } = req.body;

    const splits = [
      { label: "Room Rent", component: "ROOM_RENT", amount: room_rent },
      { label: "Mess Bill1", component: "MESS_BILL_1", amount: mess1 },
      { label: "Mess Bill2", component: "MESS_BILL_2", amount: mess2 }
    ];

    let totalAllocated = 0;

    for (let s of splits) {
      const amt = Number(s.amount || 0);
      if (amt <= 0) continue;

      totalAllocated += amt;

      /* ===============================
         1️⃣ student_payment_allocations
         =============================== */
      await conn.query(`
        INSERT INTO student_payment_allocations
        (bank_txn_id, student_id, component, allocated_amount, academic_year)
        VALUES (?, ?, ?, ?, ?)
      `, [bank_txn_id, student_id, s.component, amt, academic_year]);

      /* ===============================
         2️⃣ yearly_fee_components
         =============================== */
      await conn.query(`
        UPDATE yearly_fee_components
        SET paid_amount = paid_amount + ?
        WHERE student_id=? AND component=? AND academic_year=?
      `, [amt, student_id, s.component, academic_year]);

      /* ===============================
         3️⃣ 🔥 fee_receipts (PROFILE FIX)
         =============================== */
      await conn.query(`
        INSERT INTO fee_receipts
        (student_id, year, amount_paid, remarks, status, ref_no, receipt_path)
        VALUES (?, ?, ?, ?, 'Verified', ?, ?)
      `, [
        student_id,
        academic_year,          // MUST be 1 / 2 / 3 / 4
        amt,
        s.label,                // Room Rent / Mess Bill1 / Mess Bill2
        `BANK-${bank_txn_id}`,
        'ADMIN_VERIFIED'
      ]);
    }

    /* ===============================
       4️⃣ Update yearly status
       =============================== */
    await updateYearlyFee(student_id, academic_year);

    /* ===============================
       5️⃣ Handle extra / advance
       =============================== */
    const [[txn]] = await conn.query(
      "SELECT total_amount FROM bank_transactions WHERE id=? FOR UPDATE",
      [bank_txn_id]
    );

    const extra = txn.total_amount - totalAllocated;

    if (extra > 0) {
      await conn.query(`
        INSERT INTO refunds_adjustments
        (student_id, bank_txn_id, extra_amount, status)
        VALUES (?, ?, ?, 'HOLD')
      `, [student_id, bank_txn_id, extra]);
    }

    /* ===============================
       6️⃣ Mark transaction complete
       =============================== */
    await conn.query(`
      UPDATE bank_transactions
      SET status='FULLY_MATCHED'
      WHERE id=?
    `, [bank_txn_id]);

    await conn.commit();
    res.redirect("/admin/payment-summary/" + bank_txn_id);

  } catch (err) {
    await conn.rollback();
    console.error("❌ PAYMENT SPLIT ERROR:", err);
    res.status(500).send("Payment split failed");
  } finally {
    conn.release();
  }
});

app.post("/ledger/add", async (req, res) => {
  const { student_id, credit, ref_id } = req.body;

  await db.promise().query(`
    INSERT INTO student_ledger
    (student_id, ref_type, ref_id, credit, created_at)
    VALUES (?, 'BANK_TXN', ?, ?, NOW())
  `, [student_id, ref_id, credit]);

  res.send("Ledger updated");
});

// Show manual match page
app.get("/admin/payment/manual-match/:bankTxnId", async (req, res) => {
  const bankTxnId = req.params.bankTxnId;

  const [[txn]] = await db.promise().query(
    "SELECT * FROM bank_transactions WHERE id=?",
    [bankTxnId]
  );

  const [claims] = await db.promise().query(`
    SELECT c.*, s.name
    FROM payment_claims c
    JOIN students s ON s.student_id=c.student_id
    WHERE c.status='SUBMITTED'
      AND ABS(c.amount - ?) <= 5
  `, [txn.amount]);

  res.render("admin/manual_match", { txn, claims });
});
app.post("/admin/payment/manual-match", async (req, res) => {
  const { bank_txn_id, claim_id } = req.body;

  await db.promise().query(`
    INSERT INTO verification_matches
    (bank_txn_id, claim_id, verified_by, verified_at)
    VALUES (?, ?, ?, NOW())
  `, [bank_txn_id, claim_id, req.session.admin_id]);

  await db.promise().query(`
    UPDATE payment_claims SET status='VERIFIED' WHERE id=?
  `, [claim_id]);

  res.redirect("/admin/verify-payments");
});
app.get("/admin/payment-split", async (req, res) => {
  const [txns] = await db.promise().query(`
    SELECT * FROM bank_transactions WHERE status='VERIFIED'
  `);

  res.render("admin/payment-split", { txns });
});
app.get("/admin/verify-payments", async (req, res) => {
  const [claims] = await db.promise().query(`
    SELECT pc.*, s.name 
    FROM payment_claims pc
    JOIN students s ON s.student_id = pc.student_id
    WHERE pc.status='SUBMITTED'
  `);

  const [txns] = await db.promise().query(`
    SELECT * FROM bank_transactions WHERE status='PENDING'
  `);

  res.render("admin/verify-payments", { claims, txns });
});
app.get("/admin/refunds", async (req, res) => {
  const [refunds] = await db.promise().query(`
    SELECT
      id,
      student_id,
      bank_txn_id,
      extra_amount AS amount,
      status,
      processed_at AS created_at
    FROM refunds_adjustments
    ORDER BY id DESC
  `);

  res.render("admin/refunds", { refunds });
});


app.post("/admin/refund/approve", async (req, res) => {
  const { refund_id } = req.body;

  try {
    await db.promise().query(
      "UPDATE refunds SET status='REFUNDED' WHERE id=?",
      [refund_id]
    );

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

app.post("/admin/verify/:id", async (req, res) => {
  const id = req.params.id;

  try {
    await db.promise().query(
      "UPDATE bank_transactions SET status = 'FULLY_MATCHED' WHERE id = ?",
      [id]
    );

    res.redirect("/admin/bank-transactions");

  } catch (err) {
    console.error("VERIFY POST ERROR:", err);
    res.send("❌ Error verifying transaction");
  }
});
app.get("/admin/verify/:id", async (req, res) => {
  const id = req.params.id;

  try {
    const [[txn]] = await db.promise().query(
      "SELECT * FROM bank_transactions WHERE id = ?",
      [id]
    );

    if (!txn) {
      return res.send("❌ Transaction not found");
    }

    // simple verify page render
    res.render("admin/verify_transaction", { txn });

  } catch (err) {
    console.error("VERIFY GET ERROR:", err);
    res.send("❌ Error loading verification page");
  }
});


// =====================================
// START SERVER
// =====================================
app.listen(3000, () => console.log("🚀 Server running on http://localhost:3000"));

