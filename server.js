const express = require("express");

const app = express();   // <-- CREATE APP FIRST
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





const receiptsDir = path.join(__dirname, "uploads", "receipts");

// 🔥 ensure directory exists (important for Render + localhost)
if (!fs.existsSync(receiptsDir)) {
  fs.mkdirSync(receiptsDir, { recursive: true });
}

console.log("pdfParse type:", typeof pdfParse);

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
      dir = path.join(__dirname, "uploads", "adhaar");
      break;

    case "profile_image":
      dir = path.join(__dirname, "uploads", "profile_images");
      break;
      case "student_photo":
  dir = path.join(__dirname, "uploads", "profile_images");
  break;

case "student_aadhaar_file":
case "father_aadhaar_file":
  dir = path.join(__dirname, "uploads", "adhaar");
  break;

case "payment_receipt":
  dir = path.join(__dirname, "uploads", "receipts");
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
    // Student Photo
if (file.fieldname === "student_photo") {
    return cb(null, `${Date.now()}_photo${ext}`);
}

// Student Aadhaar
if (file.fieldname === "student_aadhaar_file") {
    return cb(null, `${Date.now()}_student_aadhaar${ext}`);
}

// Father Aadhaar
if (file.fieldname === "father_aadhaar_file") {
    return cb(null, `${Date.now()}_father_aadhaar${ext}`);
}

// Payment Receipt
if (file.fieldname === "payment_receipt") {
    return cb(null, `${Date.now()}_payment_receipt${ext}`);
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
    if (
    file.fieldname === "student_aadhaar" ||
    file.fieldname === "father_aadhaar" ||
    file.fieldname === "profile_image" ||

    // New Admission Images
    file.fieldname === "student_photo" ||
    file.fieldname === "student_aadhaar_file" ||
    file.fieldname === "father_aadhaar_file"
)  {
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
    host: 'altaria.proxy.rlwy.net',   // Railway host
    user: 'root',                     // Railway username
    password: 'TtEyIJakTnqudcllzTMJNoBoEiopNkck',     // Railway password
    database: 'hostel_management',              // Railway database name
    port: 32878,                      // Railway port
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});
const promiseDb = db.promise();

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
    // 4.5️⃣ Include New Bank Split Payments
const [allocations] = await db.promise().query(`
SELECT
CAST(academic_year AS UNSIGNED) AS academic_year,
component,
allocated_amount
FROM student_payment_allocations
WHERE student_id=?
`, [student_id]);

allocations.forEach(a => {

    const yr = Number(a.academic_year);

    if (!paymentMap[yr]) {
        paymentMap[yr] = {
            'Room Rent': 0,
            'Mess Bill1': 0,
            'Mess Bill2': 0,
            'Others': 0
        };
    }

    if (a.component === "ROOM_RENT") {
        paymentMap[yr]['Room Rent'] += Number(a.allocated_amount);
    }

    if (a.component === "MESS_BILL_1") {
        paymentMap[yr]['Mess Bill1'] += Number(a.allocated_amount);
    }

    if (a.component === "MESS_BILL_2") {
        paymentMap[yr]['Mess Bill2'] += Number(a.allocated_amount);
    }

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




// app.post("/student/upload-aadhaar", upload.fields([
//   { name: "student_aadhaar", maxCount: 1 },
//   { name: "father_aadhaar", maxCount: 1 }
// ]), async (req, res) => {

//   if (!req.session.user || req.session.role !== "student")
//     return res.redirect("/login/student");

//   const student_id = req.session.user.student_id;

//   try {
//     /* ============================
//        1️⃣ STUDENT DETAILS
//        ============================ */
//     const [[student]] = await db.promise().query(
//       "SELECT * FROM students WHERE student_id=?",
//       [student_id]
//     );
//     if (!student) return res.send("Student not found");

//     const maxYear = parseInt(student.year);


//     /* ============================
//        2️⃣ YEARLY FEE STRUCTURE
//        (OLD TABLE – KEEP)
//        ============================ */
//     const [feeRows] = await db.promise().query(
//       "SELECT * FROM yearly_fee WHERE year <= ? ORDER BY year ASC",
//       [maxYear]
//     );

//     /* ============================
//        3️⃣ OLD VERIFIED RECEIPTS
//        ============================ */
//     const [oldReceipts] = await db.promise().query(
//       `SELECT year, amount_paid, remarks
//        FROM fee_receipts
//        WHERE student_id=? AND status='Verified'`,
//       [student_id]
//     );

//     const oldMap = {};
//     oldReceipts.forEach(r => {
//       if (!oldMap[r.year]) {
//         oldMap[r.year] = { room: 0, mess1: 0, mess2: 0 };
//       }

//       const key = r.remarks.toLowerCase();
//       if (key.includes("room")) oldMap[r.year].room += Number(r.amount_paid);
//       else if (key.includes("mess bill1")) oldMap[r.year].mess1 += Number(r.amount_paid);
//       else if (key.includes("mess bill2")) oldMap[r.year].mess2 += Number(r.amount_paid);
//     });

//     /* ============================
//        4️⃣ NEW BANK PAYMENTS
//        ============================ */
//     const [newRows] = await db.promise().query(
//       `SELECT academic_year, component, allocated_amount
//        FROM student_payment_allocations
//        WHERE student_id=?`,
//       [student_id]
//     );

//     const newMap = {};
//     newRows.forEach(r => {
//       if (!newMap[r.academic_year]) {
//         newMap[r.academic_year] = { room: 0, mess1: 0, mess2: 0 };
//       }

//       if (r.component === "ROOM_RENT") newMap[r.academic_year].room += Number(r.allocated_amount);
//       if (r.component === "MESS_BILL_1") newMap[r.academic_year].mess1 += Number(r.allocated_amount);
//       if (r.component === "MESS_BILL_2") newMap[r.academic_year].mess2 += Number(r.allocated_amount);
//     });

//     /* ============================
//        5️⃣ MERGED FEE SUMMARY
//        ============================ */
//     const feeSummary = feeRows.map(y => {
//   const year = y.year;

//   // 🔑 convert DB values to numbers
//   const roomTotal = Number(y.room_rent || 0);
//   const mess1Total = Number(y.mess_bill1 || 0);
//   const mess2Total = Number(y.mess_bill2 || 0);

//   const roomPaid =
//     (oldMap[year]?.room || 0) +
//     (newMap[year]?.room || 0);

//   const mess1Paid =
//     (oldMap[year]?.mess1 || 0) +
//     (newMap[year]?.mess1 || 0);

//   const mess2Paid =
//     (oldMap[year]?.mess2 || 0) +
//     (newMap[year]?.mess2 || 0);

//   const roomDue = Math.max(roomTotal - roomPaid, 0);
//   const mess1Due = Math.max(mess1Total - mess1Paid, 0);
//   const mess2Due = Math.max(mess2Total - mess2Paid, 0);

//   const totalFee = roomTotal + mess1Total + mess2Total;
//   const totalPaid = roomPaid + mess1Paid + mess2Paid;

//   let status = "Not Paid";
//   if (totalPaid >= totalFee) status = "Paid";
//   else if (totalPaid > 0) status = "Partial";

//   return {
//     year,
//     room_rent_paid: roomPaid.toFixed(2),
//     room_rent_due: roomDue.toFixed(2),
//     mess_bill1_paid: mess1Paid.toFixed(2),
//     mess_bill1_due: mess1Due.toFixed(2),
//     mess_bill2_paid: mess2Paid.toFixed(2),
//     mess_bill2_due: mess2Due.toFixed(2),
//     total_fee: totalFee.toFixed(2),
//     total_paid: totalPaid.toFixed(2),
//     total_due: (totalFee - totalPaid).toFixed(2),
//     status
//   };
// });


//     res.render("student/profile", { student, feeSummary });

//   } catch (err) {
//     console.error(err);
//     res.status(500).send("Error loading profile");
//   }
// });



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
      const paid = paymentMap[Number(y.year)] || {};
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


app.post("/student/upload-aadhaar",
  upload.fields([
    { name: "student_aadhaar", maxCount: 1 },
    { name: "father_aadhaar", maxCount: 1 }
  ]),
  async (req, res) => {

    if (!req.session.user || req.session.role !== "student")
      return res.redirect("/login/student");

    try {
      const studentId = req.session.user.student_id;

      const studentFile =
        req.files?.student_aadhaar?.[0]?.filename || null;

      const fatherFile =
        req.files?.father_aadhaar?.[0]?.filename || null;

      await db.promise().query(
        `UPDATE students
         SET student_aadhaar = COALESCE(?, student_aadhaar),
             father_aadhaar = COALESCE(?, father_aadhaar)
         WHERE student_id = ?`,
        [studentFile, fatherFile, studentId]
      );

      res.redirect("/student/profile");

    } catch (err) {
      console.error(err);
      res.status(500).send("Upload failed");
    }
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
app.get("/warden/new-admission", (req, res) => {

    res.render("warden/new_admission");

});
app.get("/public_admission", (req, res) => {
    res.render("public_admission");
});
app.get("/admission-success", (req, res) => {
    res.render("admission_success");
});
app.post(
    "/warden/new-admission",

    upload.fields([
        { name: "student_photo", maxCount: 1 },
        { name: "student_aadhaar_file", maxCount: 1 },
        { name: "father_aadhaar_file", maxCount: 1 },
        { name: "payment_receipt", maxCount: 1 }
    ]),

    async (req, res) => {

        try {

            const data = req.body;
            const files = req.files;

            const year = new Date().getFullYear();

            // Get next admission number
            const [rows] = await promiseDb.query(
                "SELECT COUNT(*) AS total FROM student_admissions"
            );

            const nextNo = rows[0].total + 1;

            const admissionNo =
                `HM${year}-${String(nextNo).padStart(4, "0")}`;

            await promiseDb.query(

                `INSERT INTO student_admissions(

                    admission_no,

                    student_id,
                    student_unique_id,

                    name,
                    father_name,

                    course,
                    year,

                    village,

                    student_mobile,
                    parent_mobile,

                    email,

                    student_aadhaar,
                    father_aadhaar,

                    payment_ref_id,

                    payment_receipt,

                    student_photo,

                    student_aadhaar_file,

                    father_aadhaar_file,

                    registration_source

                )

                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,

                [

                    admissionNo,

                    data.student_id,
                    data.student_unique_id,

                    data.name,
                    data.father_name,

                    data.course,
                    data.year,

                    data.village,

                    data.student_mobile,
                    data.parent_mobile,

                    data.email,

                    data.student_aadhaar,
                    data.father_aadhaar,

                    data.payment_ref_id,

                    files.payment_receipt
                        ? files.payment_receipt[0].filename
                        : null,

                    files.student_photo
                        ? files.student_photo[0].filename
                        : null,

                    files.student_aadhaar_file
                        ? files.student_aadhaar_file[0].filename
                        : null,

                    files.father_aadhaar_file
                        ? files.father_aadhaar_file[0].filename
                        : null,

                    "WARDEN"

                ]

            );

            res.redirect("/warden/pending-admissions");

        }

        catch (err) {

            console.log(err);

            res.send(err);

        }

    }

);
app.post("/public_admission",

    upload.fields([
        { name: "student_photo", maxCount: 1 },
        { name: "student_aadhaar_file", maxCount: 1 },
        { name: "father_aadhaar_file", maxCount: 1 },
        { name: "payment_receipt", maxCount: 1 }
    ]),

    async (req, res) => {

        try {

            const data = req.body;
            const files = req.files;

            const year = new Date().getFullYear();

            // Get next admission number
            const [rows] = await promiseDb.query(
                "SELECT COUNT(*) AS total FROM student_admissions"
            );

            const nextNo = rows[0].total + 1;

            const admissionNo =
                `HM${year}-${String(nextNo).padStart(4, "0")}`;

            await promiseDb.query(

                `INSERT INTO student_admissions(

                    admission_no,

                    student_id,
                    student_unique_id,

                    name,
                    father_name,

                    course,
                    year,

                    village,

                    student_mobile,
                    parent_mobile,

                    email,

                    student_aadhaar,
                    father_aadhaar,

                    payment_ref_id,

                    payment_receipt,

                    student_photo,

                    student_aadhaar_file,

                    father_aadhaar_file,

                    registration_source

                )

                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,

                [

                    admissionNo,

                    data.student_id,
                    data.student_unique_id,

                    data.name,
                    data.father_name,

                    data.course,
                    data.year,

                    data.village,

                    data.student_mobile,
                    data.parent_mobile,

                    data.email,

                    data.student_aadhaar,
                    data.father_aadhaar,

                    data.payment_ref_id,

                    files.payment_receipt
                        ? files.payment_receipt[0].filename
                        : null,

                    files.student_photo
                        ? files.student_photo[0].filename
                        : null,

                    files.student_aadhaar_file
                        ? files.student_aadhaar_file[0].filename
                        : null,

                    files.father_aadhaar_file
                        ? files.father_aadhaar_file[0].filename
                        : null,

                    "WARDEN"

                ]

            );

            res.redirect("/admission-success");

        }

        catch (err) {

            console.log(err);

            res.send(err);

        }

    }

);

app.get("/warden/pending-admissions", async (req, res) => {

    try {

        const [students] = await promiseDb.query(`
            SELECT *
            FROM student_admissions
            ORDER BY created_at DESC
        `);

        res.render("warden/pending_admissions", {
            students
        });

    } catch (err) {

        console.log(err);
        res.send(err);

    }

});
app.get("/warden/admission/:id", async (req, res) => {

    try {

        const [rows] = await promiseDb.query(
            "SELECT * FROM student_admissions WHERE id=?",
            [req.params.id]
        );

        if (rows.length === 0) {
            return res.send("Admission Not Found");
        }

        res.render("warden/admission_details", {
    admission: rows[0]
});

    } catch (err) {
        console.log(err);
        res.send(err);
    }

});


app.post("/warden/admission/approve/:id", async (req, res) => {

    try {

        const admissionId = req.params.id;

        // Get admission data
        const [rows] = await promiseDb.query(
            "SELECT * FROM student_admissions WHERE id=?",
            [admissionId]
        );

        if (rows.length === 0) {
            return res.send("Admission not found");
        }

        const student = rows[0];
        const hashedPassword = await bcrypt.hash("123456", 10);
        const { room_no } = req.body;
        const joinYear = String(student.year_of_join);

// Generate Hostel ID
const [hostelRows] = await promiseDb.query(
    "SELECT hostel_id FROM students WHERE hostel_id LIKE ? ORDER BY hostel_id DESC LIMIT 1",
    [`${joinYear}%`]
);

let hostelId;

if (hostelRows.length > 0 && hostelRows[0].hostel_id) {

    const lastSeq = parseInt(hostelRows[0].hostel_id.substring(4), 10);

    hostelId = joinYear + String(lastSeq + 1).padStart(6, "0");

} else {

    hostelId = joinYear + "000001";

}

        // Check duplicate Student ID
        const [exists] = await promiseDb.query(
            "SELECT student_id FROM students WHERE student_id=?",
            [student.student_id]
        );

        if (exists.length > 0) {
            return res.send("Student already exists.");
        }

        // Insert into students table
       await promiseDb.query(

            `INSERT INTO students
            (
                student_id,
                name,
                email,
                password,
                hostel_id,
                room_no,
                course,
                year,
                student_unique_id,
                student_mobile,
                father_name,
                father_mobile,
                year_of_join,
                student_aadhaar,
                father_aadhaar,
                profile_image,
                status
            )
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,

            [

                student.student_id,
                student.name,
                student.email || "",

                hashedPassword,
                hostelId,
                room_no,

                student.course,
                student.year,

                student.student_unique_id,

                student.student_mobile,

                student.father_name,

                student.parent_mobile,

                student.year_of_join,

                student.student_aadhaar,
                student.father_aadhaar,

                student.student_photo,

                "ACTIVE"

            ]

        );

        // Update admission status
        await promiseDb.query(

            "UPDATE student_admissions SET status='APPROVED' WHERE id=?",

            [admissionId]

        );

        res.redirect("/warden/pending-admissions");

    }

    catch (err) {

        console.log(err);

        res.send(err);

    }

});
app.get('/warden/acceptedReceipts', async (req, res) => {
  if (!req.session || req.session.role !== 'admin') {
    return res.redirect('/choose_login');
  }

  const [accepted] = await promiseDb.query(`
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

  } ca
