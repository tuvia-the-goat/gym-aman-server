// server/index.js
const http = require("http");
const initializeSocket = require("./socket");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();

// Initialize app
const app = express();
const server = http.createServer(app);
const { io, emitNewEntry } = initializeSocket(server);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";

// Middleware
app.use(cors());
app.use(express.json());
app.set("emitNewEntry", emitNewEntry);

// MongoDB connection
mongoose
  .connect(
    process.env.MONGODB_URI || "mongodb://localhost:27017/gym-management",
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }
  )
  .then(async () => {
    console.log("MongoDB connected");
    // try {
    //   // Get the collection
    //   const collection = mongoose.connection.collection('entries');

    //   // Drop the index
    //   await collection.dropIndex('traineeId_1_entryDate_1');
    // } catch {

    // }
  })
  .catch((err) => console.error("MongoDB connection error:", err));

// Define schemas
const EntryStatus = {
  SUCCESS: "success",
  NO_MEDICAL_APPROVAL: "noMedicalApproval",
  NOT_REGISTERED: "notRegistered",
  NOT_ASSOCIATED: "notAssociated",
};

const AdminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["generalAdmin", "gymAdmin"], required: true },
  baseId: { type: mongoose.Schema.Types.ObjectId, ref: "Base" },
});

const BaseSchema = new mongoose.Schema({
  name: { type: String, required: true },
  location: { type: String, required: true },
});

const DepartmentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  baseId: { type: mongoose.Schema.Types.ObjectId, ref: "Base", required: true },
  numOfPeople: { type: Number, default: 0 },
});

const SubDepartmentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  departmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Department",
    required: true,
  },
  numOfPeople: { type: Number, default: 0 },
});

const TraineeSchema = new mongoose.Schema({
  personalId: { type: String, required: true, unique: true },
  fullName: { type: String, required: true },
  medicalProfile: {
    type: String,
    enum: ["97", "82", "72", "64", "45", "25"],
    required: true,
  },
  departmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Department",
    required: true,
  },
  subDepartmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "SubDepartment",
  },
  phoneNumber: { type: String, required: true },
  medicalApproval: {
    approved: { type: Boolean, default: false },
    expirationDate: { type: Date, default: null },
  },
  baseId: { type: mongoose.Schema.Types.ObjectId, ref: "Base", required: true },
  // New fields
  gender: { type: String, enum: ["male", "female"], required: true },
  birthDate: { type: Date, required: true },
  orthopedicCondition: { type: Boolean, required: true },
  medicalFormScore: {
    type: String,
    enum: ["fullScore", "notRequired", "reserve", "partialScore"],
    required: true,
  },
  medicalCertificateProvided: { type: Boolean, default: false },
  medicalLimitation: { type: String }, // Optional field
});

const EntrySchema = new mongoose.Schema(
  {
    traineeId: { type: mongoose.Schema.Types.ObjectId, ref: "Trainee" }, // Make optional for non-registered entries
    entryDate: { type: String, required: true },
    entryTime: { type: String, required: true },
    traineeFullName: { type: String }, // Make optional for non-registered entries
    traineePersonalId: { type: String, required: true },
    subDepartmentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "SubDepartment",
    },
    departmentId: { type: mongoose.Schema.Types.ObjectId, ref: "Department" }, // Make optional for non-registered entries
    baseId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Base",
      required: true,
    },
    status: { type: String, enum: Object.values(EntryStatus) },
  },
  { timestamps: true }
);

// Create models
const Admin = mongoose.model("Admin", AdminSchema);
const Base = mongoose.model("Base", BaseSchema);
const Department = mongoose.model("Department", DepartmentSchema);
const SubDepartment = mongoose.model("SubDepartment", SubDepartmentSchema);
const Trainee = mongoose.model("Trainee", TraineeSchema);
const Entry = mongoose.model("Entry", EntrySchema);

// Middleware to verify jwt token
const authMiddleware = async (req, res, next) => {
  const token = req.header("x-auth-token");

  if (!token) {
    return res.status(401).json({ message: "No token, authorization denied" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Token is not valid" });
  }
};

// Routes

// Initialize default data (only if collections are empty)
app.get("/api/initialize", async (req, res) => {
  try {
    const adminsCount = await Admin.countDocuments();
    const basesCount = await Base.countDocuments();

    if (adminsCount === 0 && basesCount === 0) {
      // Create default base
      const defaultBase = new Base({
        name: "גלילות",
        location: "מרכז",
      });
      await defaultBase.save();

      // Create default department
      const defaultDepartment = new Department({
        name: "ארטק",
        baseId: defaultBase._id,
        numOfPeople: 0,
      });
      await defaultDepartment.save();

      // Create default admins
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash("12345", salt);

      const generalAdmin = new Admin({
        username: "generalAdmin",
        password: hashedPassword,
        role: "generalAdmin",
      });
      await generalAdmin.save();

      const gymAdmin = new Admin({
        username: "gymAdmin",
        password: hashedPassword,
        role: "gymAdmin",
        baseId: defaultBase._id,
      });
      await gymAdmin.save();

      return res.json({ message: "System initialized with default data" });
    }

    res.json({ message: "System already initialized" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Auth routes
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const admin = await Admin.findOne({ username });

    if (!admin) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // For this example, we're comparing plain text. In a real app, use bcrypt.
    const isMatch = await bcrypt.compare(password, admin.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const payload = {
      id: admin._id,
      username: admin.username,
      role: admin.role,
      baseId: admin.baseId,
    };

    jwt.sign(payload, JWT_SECRET, { expiresIn: "1d" }, (err, token) => {
      if (err) throw err;
      res.json({ token, admin: payload });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/auth/verify", authMiddleware, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.id).select("-password");
    res.json(admin);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Base routes
app.get("/api/bases", async (req, res) => {
  try {
    const bases = await Base.find();
    res.json(bases);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get base by ID
app.get("/api/bases/:id", async (req, res) => {
  try {
    const base = await Base.findById(req.params.id);
    if (!base) {
      return res.status(404).json({ message: "Base not found" });
    }
    res.json(base);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/bases", authMiddleware, async (req, res) => {
  const { name, location } = req.body;

  // Only allBasesAdmin can create new bases
  if (req.admin.role !== "generalAdmin") {
    return res.status(403).json({ message: "Not authorized" });
  }

  try {
    const newBase = new Base({
      name,
      location,
    });

    const base = await newBase.save();
    res.json(base);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/entries/non-registered", async (req, res) => {
  const { entryDate, entryTime, traineePersonalId, baseId, status } = req.body;

  try {
    // Check if there's already an entry for this person today
    const existingEntry = await Entry.findOne({
      traineePersonalId,
      entryDate,
    });

    if (existingEntry) {
      return res
        .status(400)
        .json({ message: "כבר קיימת כניסה היום למספר זיהוי זה" });
    }

    const newEntry = new Entry({
      entryDate,
      entryTime,
      traineePersonalId,
      baseId,
      status: status || EntryStatus.NOT_REGISTERED,
    });

    const entry = await newEntry.save();

    // Emit the new entry event
    const emitNewEntry = req.app.get("emitNewEntry");
    emitNewEntry(entry, entry.baseId);

    res.json(entry);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Department routes
app.get("/api/departments", async (req, res) => {
  try {
    const departments = await Department.find();
    res.json(departments);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/departments", authMiddleware, async (req, res) => {
  const { name, baseId, numOfPeople } = req.body;

  try {
    // Check if the admin is authorized for this base
    if (
      req.admin.role === "gymAdmin" &&
      req.admin.baseId.toString() !== baseId
    ) {
      return res.status(403).json({ message: "Not authorized for this base" });
    }

    const newDepartment = new Department({
      name,
      baseId,
      numOfPeople,
    });

    const department = await newDepartment.save();
    res.json(department);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get all subDepartments
app.get("/api/subDepartments", async (req, res) => {
  try {
    const subDepartments = await SubDepartment.find();
    res.json(subDepartments);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get subDepartments by departmentId
app.get("/api/subDepartments/department/:departmentId", async (req, res) => {
  try {
    const subDepartments = await SubDepartment.find({
      departmentId: req.params.departmentId,
    });
    res.json(subDepartments);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Create new subDepartment
app.post("/api/subDepartments", authMiddleware, async (req, res) => {
  const { name, departmentId, numOfPeople } = req.body;

  try {
    // Check if the department exists
    const department = await Department.findById(departmentId);
    if (!department) {
      return res.status(404).json({ message: "Department not found" });
    }

    // Check if the admin is authorized for this department's base
    if (
      req.admin.role === "gymAdmin" &&
      req.admin.baseId.toString() !== department.baseId.toString()
    ) {
      return res
        .status(403)
        .json({ message: "Not authorized for this department" });
    }

    const newSubDepartment = new SubDepartment({
      name,
      departmentId,
      numOfPeople,
    });

    const subDepartment = await newSubDepartment.save();
    res.json(subDepartment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Trainee routes
app.get("/api/trainees", async (req, res) => {
  try {
    const trainees = await Trainee.find();
    res.json(trainees);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/trainees", async (req, res) => {
  const {
    personalId,
    fullName,
    medicalProfile,
    departmentId,
    subDepartmentId, // Add this line
    phoneNumber,
    baseId,
    gender,
    birthDate,
    orthopedicCondition,
    medicalFormScore,
    medicalCertificateProvided,
    medicalLimitation,
    medicalApproval,
  } = req.body;

  try {
    // Check if trainee already exists
    const existingTrainee = await Trainee.findOne({ personalId });
    if (existingTrainee) {
      return res.status(400).json({ message: "המשתמש כבר קיים במערכת" });
    }

    const newTrainee = new Trainee({
      personalId,
      fullName,
      medicalProfile,
      departmentId,
      subDepartmentId, // Add this line
      phoneNumber,
      baseId,
      gender,
      birthDate,
      orthopedicCondition,
      medicalFormScore,
      medicalApproval,
      // Only include these optional fields if they exist
      ...(medicalFormScore === "partialScore" && {
        medicalCertificateProvided,
      }),
      ...(medicalLimitation && { medicalLimitation }),
    });

    const trainee = await newTrainee.save();
    res.json(trainee);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Updated route for medical approval
app.put(
  "/api/trainees/:id/medical-approval",
  authMiddleware,
  async (req, res) => {
    const {
      approved,
      expirationDate,
      medicalFormScore,
      medicalCertificateProvided,
      medicalLimitation,
      orthopedicCondition,
    } = req.body;

    try {
      const trainee = await Trainee.findById(req.params.id);

      if (!trainee) {
        return res.status(404).json({ message: "Trainee not found" });
      }

      // Check if the admin is authorized for this base
      if (
        req.admin.role === "gymAdmin" &&
        req.admin.baseId.toString() !== trainee.baseId.toString()
      ) {
        return res
          .status(403)
          .json({ message: "Not authorized for this trainee" });
      }

      // Update medical approval
      trainee.medicalApproval = {
        approved,
        // Use provided expirationDate or calculate one year from now if approved
        expirationDate:
          expirationDate ||
          (approved ? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) : null),
      };

      // Update optional medical fields if provided
      if (medicalFormScore !== undefined) {
        trainee.medicalFormScore = medicalFormScore;
      }

      if (medicalCertificateProvided !== undefined) {
        trainee.medicalCertificateProvided = medicalCertificateProvided;
      }

      if (medicalLimitation !== undefined) {
        trainee.medicalLimitation = medicalLimitation;
      }

      if (orthopedicCondition !== undefined) {
        trainee.orthopedicCondition = orthopedicCondition;
      }

      const updatedTrainee = await trainee.save();
      res.json(updatedTrainee);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Transfer trainees between subdepartments
app.put(
  "/api/trainees/transfer-subdepartment",
  authMiddleware,
  async (req, res) => {
    const { oldSubDepartmentId, newSubDepartmentId } = req.body;

    try {
      // Get the new subdepartment to verify it exists and get its departmentId
      const newSubDepartment = await SubDepartment.findById(newSubDepartmentId);
      if (!newSubDepartment) {
        return res.status(404).json({ message: "תת-המסגרת החדשה לא נמצאה" });
      }

      // Update all trainees in the old subdepartment with both new subdepartment and department
      const result = await Trainee.updateMany(
        { subDepartmentId: oldSubDepartmentId },
        {
          subDepartmentId: newSubDepartmentId,
          departmentId: newSubDepartment.departmentId, // Update the departmentId to match the new subdepartment's department
        }
      );

      res.json({
        message: `הועברו ${result.modifiedCount} חניכים לתת-המסגרת החדשה`,
        modifiedCount: result.modifiedCount,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "שגיאת שרת" });
    }
  }
);

// Entry routes
app.get("/api/entries", async (req, res) => {
  try {
    const entries = await Entry.find().sort({ createdAt: -1 });

    res.json(entries);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/entries", async (req, res) => {
  const {
    traineeId,
    entryDate,
    entryTime,
    traineeFullName,
    traineePersonalId,
    departmentId,
    subDepartmentId,
    baseId,
    status, // Add subDepartmentId here
  } = req.body;

  console.log({
    traineePersonalId,
    entryDate,
  });

  try {
    // Check if trainee already entered today
    const existingEntry = await Entry.findOne({
      traineePersonalId,
      entryDate,
      baseId,
      status: { $in: [EntryStatus.SUCCESS, EntryStatus.NOT_ASSOCIATED] },
    });

    if (existingEntry) {
      return res
        .status(400)
        .json({ message: "המשתמש כבר נכנס היום, הצהרת בריאות בתוקף" });
    }

    const newEntry = new Entry({
      traineeId,
      entryDate,
      entryTime,
      traineeFullName,
      traineePersonalId,
      departmentId,
      subDepartmentId, // Add this line
      baseId,
      status: status || EntryStatus.SUCCESS, // Default to success for registered users
    });

    const entry = await newEntry.save();

    // Emit the new entry event
    const emitNewEntry = req.app.get("emitNewEntry");
    emitNewEntry(entry, entry.baseId);

    res.json(entry);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Admin routes
app.post("/api/admins", authMiddleware, async (req, res) => {
  const { username, password, role, baseId } = req.body;
  // Only allBasesAdmin can create new admins
  if (req.admin.role !== "generalAdmin") {
    return res.status(403).json({ message: "Not authorized" });
  }

  try {
    // Check if username already exists
    const existingAdmin = await Admin.findOne({ username });
    if (existingAdmin) {
      return res.status(400).json({ message: "Username already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newAdmin = new Admin({
      username,
      password: hashedPassword,
      role,
      baseId: role === "gymAdmin" ? baseId : undefined,
    });

    const admin = await newAdmin.save();

    // Don't return the password
    const adminResponse = {
      _id: admin._id,
      username: admin.username,
      role: admin.role,
      baseId: admin.baseId,
    };

    res.json(adminResponse);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get all admins
app.get("/api/admins", authMiddleware, async (req, res) => {
  // Only allBasesAdmin can get all admins
  if (req.admin.role !== "generalAdmin") {
    return res.status(403).json({ message: "Not authorized" });
  }

  try {
    const admins = await Admin.find().select("-password");
    res.json(admins);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Reset admin password
app.put("/api/admins/:id/reset-password", authMiddleware, async (req, res) => {
  // Only allBasesAdmin can reset passwords
  if (req.admin.role !== "generalAdmin") {
    return res.status(403).json({ message: "Not authorized" });
  }

  const { newPassword } = req.body;
  if (!newPassword) {
    return res.status(400).json({ message: "New password is required" });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    const admin = await Admin.findByIdAndUpdate(
      req.params.id,
      { password: hashedPassword },
      { new: true }
    ).select("-password");

    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    res.json(admin);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Paginated entries route
app.get("/api/entries/paginated", authMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20; // Fixed limit
    const skip = (page - 1) * limit;

    // Build filter query
    const query = {};

    // Apply base filter based on admin role
    if (req.admin.role === "gymAdmin") {
      // Gym admins can only see their own base
      query.baseId = req.admin.baseId;
    } else if (req.admin.role === "generalAdmin" && req.query.baseId) {
      // General admins can see specific base or all bases
      query.baseId = req.query.baseId;
    }

    // Apply other filters if provided
    if (req.query.departmentId) {
      query.departmentId = req.query.departmentId;
    }

    if (req.query.subDepartmentId) {
      query.subDepartmentId = req.query.subDepartmentId;
    }

    if (req.query.search) {
      // Search by trainee name or ID
      query.$or = [
        { traineeFullName: { $regex: req.query.search, $options: "i" } },
        { traineePersonalId: { $regex: req.query.search, $options: "i" } },
      ];
    }

    // Date range filter
    if (req.query.startDate && req.query.endDate) {
      query.entryDate = {
        $gte: req.query.startDate,
        $lte: req.query.endDate,
      };
    }

    // Get total count
    const total = await Entry.countDocuments(query);

    // Get paginated entries
    const entries = await Entry.find(query)
      .sort({ entryDate: -1, entryTime: -1 }) // Sort by date and time, newest first
      .skip(skip)
      .limit(limit);

    res.json({
      entries,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Base update routes
app.put("/api/bases/:id", authMiddleware, async (req, res) => {
  const { name, location } = req.body;
  const baseId = req.params.id;

  // Only allBasesAdmin can update bases
  if (req.admin.role !== "generalAdmin") {
    return res.status(403).json({ message: "Not authorized" });
  }

  try {
    const base = await Base.findById(baseId);

    if (!base) {
      return res.status(404).json({ message: "Base not found" });
    }

    base.name = name;
    base.location = location;

    const updatedBase = await base.save();
    res.json(updatedBase);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/bases/:id", authMiddleware, async (req, res) => {
  const baseId = req.params.id;

  // Only allBasesAdmin can delete bases
  if (req.admin.role !== "generalAdmin") {
    return res.status(403).json({ message: "Not authorized" });
  }

  try {
    // Check if base exists
    const base = await Base.findById(baseId);
    if (!base) {
      return res.status(404).json({ message: "Base not found" });
    }

    // Check if base is being used by departments
    const departmentsCount = await Department.countDocuments({ baseId });
    if (departmentsCount > 0) {
      return res.status(400).json({
        message:
          "Cannot delete base with associated departments. Delete the departments first.",
      });
    }

    // Check if base is being used by admins
    const adminsCount = await Admin.countDocuments({ baseId });
    if (adminsCount > 0) {
      return res.status(400).json({
        message:
          "Cannot delete base with associated administrators. Change admin associations first.",
      });
    }

    // Delete the base
    await Base.findByIdAndDelete(baseId);
    res.json({ message: "Base deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Department update routes
app.put("/api/departments/:id", authMiddleware, async (req, res) => {
  const { name, numOfPeople } = req.body;
  const departmentId = req.params.id;

  try {
    const department = await Department.findById(departmentId);

    if (!department) {
      return res.status(404).json({ message: "Department not found" });
    }

    // Check if the admin is authorized for this base
    if (
      req.admin.role === "gymAdmin" &&
      req.admin.baseId.toString() !== department?.baseId?.toString()
    ) {
      return res.status(403).json({ message: "Not authorized for this base" });
    }

    department.name = name;
    department.numOfPeople = numOfPeople;

    const updatedDepartment = await department.save();
    res.json(updatedDepartment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/departments/:id", authMiddleware, async (req, res) => {
  const departmentId = req.params.id;

  try {
    // Check if department exists
    const department = await Department.findById(departmentId);
    if (!department) {
      return res.status(404).json({ message: "Department not found" });
    }

    // Check if admin is authorized for this department's base
    if (
      req.admin.role === "gymAdmin" &&
      req.admin.baseId.toString() !== department.baseId.toString()
    ) {
      return res
        .status(403)
        .json({ message: "Not authorized for this department" });
    }

    // Check if department is being used by subdepartments
    const subDepartmentsCount = await SubDepartment.countDocuments({
      departmentId,
    });
    if (subDepartmentsCount > 0) {
      return res.status(400).json({
        message:
          "Cannot delete department with associated sub-departments. Delete the sub-departments first.",
      });
    }

    // Check if department is being used by trainees
    const traineesCount = await Trainee.countDocuments({ departmentId });
    if (traineesCount > 0) {
      return res.status(400).json({
        message:
          "Cannot delete department with associated trainees. Change trainee associations first.",
      });
    }

    // Delete the department
    await Department.findByIdAndDelete(departmentId);
    res.json({ message: "Department deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// SubDepartment update routes
app.put("/api/subDepartments/:id", authMiddleware, async (req, res) => {
  const { name, departmentId, numOfPeople } = req.body;
  const subDepartmentId = req.params.id;

  try {
    // Check if the subDepartment exists
    const subDepartment = await SubDepartment.findById(subDepartmentId);
    if (!subDepartment) {
      return res.status(404).json({ message: "SubDepartment not found" });
    }

    // Check if the department exists
    const department = await Department.findById(departmentId);
    if (!department) {
      return res.status(404).json({ message: "Department not found" });
    }

    // Check if the admin is authorized for this department's base
    if (
      req.admin.role === "gymAdmin" &&
      req.admin.baseId.toString() !== department.baseId.toString()
    ) {
      return res
        .status(403)
        .json({ message: "Not authorized for this department" });
    }

    subDepartment.name = name;
    subDepartment.departmentId = departmentId;
    subDepartment.numOfPeople = numOfPeople;

    const updatedSubDepartment = await subDepartment.save();
    res.json(updatedSubDepartment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/subDepartments/:id", authMiddleware, async (req, res) => {
  const subDepartmentId = req.params.id;

  try {
    // Check if subDepartment exists
    const subDepartment = await SubDepartment.findById(subDepartmentId);
    if (!subDepartment) {
      return res.status(404).json({ message: "SubDepartment not found" });
    }

    // Get the department to check base permission
    const department = await Department.findById(subDepartment.departmentId);
    if (!department) {
      return res
        .status(404)
        .json({ message: "Associated department not found" });
    }

    // Check if admin is authorized for this department's base
    if (
      req.admin.role === "gymAdmin" &&
      req.admin.baseId.toString() !== department.baseId.toString()
    ) {
      return res
        .status(403)
        .json({ message: "Not authorized for this sub-department" });
    }

    // Check if subDepartment is being used by trainees
    const traineesCount = await Trainee.countDocuments({ subDepartmentId });
    if (traineesCount > 0) {
      return res.status(400).json({
        message:
          "Cannot delete sub-department with associated trainees. Change trainee associations first.",
      });
    }

    // Delete the subDepartment
    await SubDepartment.findByIdAndDelete(subDepartmentId);
    res.json({ message: "SubDepartment deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
}); // Paginated trainees route with filtering
app.get("/api/trainees/paginated", authMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 30; // Default limit per page
    const skip = (page - 1) * limit;

    // Build filter query
    const query = {};

    // Apply base filter if gymAdmin
    if (req.query.baseId && req.admin.role === "gymAdmin") {
      query.baseId = req.query.baseId;
    }

    // Apply search filter if provided
    if (req.query.search) {
      // Search by trainee name or ID
      query.$or = [
        { fullName: { $regex: req.query.search, $options: "i" } },
        { personalId: { $regex: req.query.search, $options: "i" } },
      ];
    }

    // Medical approval filter
    if (req.query.showOnlyExpired === "true") {
      query.$or = [
        { "medicalApproval.approved": false },
        {
          $and: [
            { "medicalApproval.approved": true },
            { "medicalApproval.expirationDate": { $lt: new Date() } },
          ],
        },
      ];
    }

    // Expiration date filter
    if (req.query.expirationDate) {
      const expirationDate = new Date(req.query.expirationDate);
      query["medicalApproval.approved"] = true;
      query["medicalApproval.expirationDate"] = { $lt: expirationDate };
    }

    // Get total count
    const total = await Trainee.countDocuments(query);

    // Get paginated trainees
    const trainees = await Trainee.find(query)
      .sort({ fullName: 1 }) // Sort by name
      .skip(skip)
      .limit(limit);

    res.json({
      trainees,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// trainees that trained in the last week
app.get("/api/trainees/last-week", authMiddleware, async (req, res) => {
  try {
    // Get the date from 7 days ago
    const today = new Date();
    const lastWeek = new Date();
    lastWeek.setDate(today.getDate() - 7);

    // Format dates to match the string format used in EntrySchema
    const todayStr = today.toISOString().split("T")[0];
    const lastWeekStr = lastWeek.toISOString().split("T")[0];

    // Query to find entries from the last week with successful status
    const recentEntries = await Entry.find({
      entryDate: {
        $gte: lastWeekStr,
        $lte: todayStr,
      },
      status: "success",
    }).distinct("traineeId");

    // Query to find the trainees who have these entries
    const activeTrainees = await Trainee.find({
      _id: { $in: recentEntries },
      ...(req.admin.role === "gymAdmin" ? { baseId: req.admin.baseId } : {}),
    });
    res.json(activeTrainees);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Update trainee profile
app.put("/api/trainees/:id", authMiddleware, async (req, res) => {
  const {
    personalId,
    fullName,
    medicalProfile,
    departmentId,
    subDepartmentId,
    baseId,
    gender,
    birthDate,
    orthopedicCondition,
    medicalFormScore,
    medicalCertificateProvided,
    medicalLimitation,
    medicalApproval,
  } = req.body;

  try {
    console.log(gender);

    const trainee = await Trainee.findById(req.params.id);

    if (!trainee) {
      return res.status(404).json({ message: "המתאמן לא נמצא" });
    }

    // Check if the admin is authorized for this base
    if (
      req.admin.role === "gymAdmin" &&
      req.admin.baseId.toString() !== baseId
    ) {
      return res.status(403).json({ message: "אין הרשאה לעדכן מתאמן זה" });
    }

    // Check if personalId is being changed and if it already exists
    if (personalId !== trainee.personalId) {
      const existingTrainee = await Trainee.findOne({ personalId });
      if (existingTrainee) {
        return res.status(400).json({ message: "מספר אישי כבר קיים במערכת" });
      }
    }

    // Update trainee fields
    trainee.personalId = personalId;
    trainee.fullName = fullName;
    trainee.medicalProfile = medicalProfile;
    trainee.departmentId = departmentId;
    trainee.subDepartmentId = subDepartmentId;
    trainee.baseId = baseId;
    trainee.gender = gender;
    trainee.birthDate = birthDate;
    trainee.orthopedicCondition = orthopedicCondition;
    trainee.medicalFormScore = medicalFormScore;
    trainee.medicalApproval = medicalApproval;

    // Update optional fields if provided
    if (medicalCertificateProvided !== undefined) {
      trainee.medicalCertificateProvided = medicalCertificateProvided;
    }
    if (medicalLimitation !== undefined) {
      trainee.medicalLimitation = medicalLimitation;
    }

    const updatedTrainee = await trainee.save();
    res.json(updatedTrainee);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "שגיאת שרת" });
  }
});

// Add new search route
app.get("/api/departments/search", authMiddleware, async (req, res) => {
  try {
    const { query } = req.query;
    const admin = req.admin;

    if (!admin) {
      return res.status(403).json({ message: "Not authorized" });
    }

    let baseDepartmentsIds;
    if (admin?.role !== "generalAdmin") {
      // Get all departments from the base
      baseDepartmentsIds = (
        await Department.find({
          baseId: admin.baseId,
        })
      ).map((dept) => dept._id);
    }

    // Get the relevant subdepartments
    const subDepartments = await SubDepartment.find({
      name: { $regex: query.toLowerCase() },
      ...(admin?.role !== "generalAdmin" && {
        departmentId: { $in: baseDepartmentsIds },
      }),
    });

    // Get unique department IDs that contain matching subdepartments
    const departmentIdsWithMatchingSubs = [
      ...new Set(subDepartments.map((sub) => sub.departmentId)),
    ];

    // Get departments that match the query or contain matching subdepartments
    const departments = await Department.find({
      $or: [
        {
          name: { $regex: query.toLowerCase() },
          ...(admin?.role === "gymAdmin" && { baseId: admin.baseId }),
        },
        { _id: { $in: departmentIdsWithMatchingSubs } },
      ],
    });

    res.json({
      departments,
      subDepartments,
    });
  } catch (error) {
    console.error("Error searching departments:", error);
    res.status(500).json({ message: "Error searching departments" });
  }
});

// Create department with multiple subdepartments
app.post(
  "/api/departments/with-subdepartments",
  authMiddleware,
  async (req, res) => {
    const { name, baseId, subDepartments, numOfPeople } = req.body;

    try {
      // Check if the admin is authorized for this base
      if (
        req.admin.role === "gymAdmin" &&
        req.admin.baseId.toString() !== baseId
      ) {
        return res
          .status(403)
          .json({ message: "Not authorized for this base" });
      }

      // Create the department
      const newDepartment = new Department({
        name,
        baseId,
        numOfPeople,
      });

      const department = await newDepartment.save();

      // Create all subdepartments
      const createdSubDepartments = await Promise.all(
        subDepartments.map(async ({ name, numOfPeople }) => {
          const newSubDepartment = new SubDepartment({
            name,
            departmentId: department._id,
            numOfPeople,
          });
          return await newSubDepartment.save();
        })
      );

      res.json({
        department,
        subDepartments: createdSubDepartments,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Paginated departments route
app.get("/api/departments/paginated", authMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Build filter query
    const query = {};

    // Apply base filter based on admin role
    if (req.admin.role === "gymAdmin") {
      // Gym admins can only see their own base
      query.baseId = req.admin.baseId;
    } else if (req.admin.role === "generalAdmin" && req.query.baseId) {
      // General admins can see specific base or all bases
      query.baseId = req.query.baseId;
    }

    // Apply search filter if provided
    if (req.query.search) {
      query.name = { $regex: req.query.search, $options: "i" };
    }

    // Get total count
    const total = await Department.countDocuments(query);

    // Get paginated departments
    const departments = await Department.find(query)
      .sort({ name: 1 }) // Sort by name
      .skip(skip)
      .limit(limit);

    res.json({
      departments,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get today's successful entries
app.get("/api/entries/today-successful", authMiddleware, async (req, res) => {
  try {
    const today = new Date().toISOString().split("T")[0];
    const query = {
      entryDate: today,
      status: "success",
    };

    // Apply base filter if provided
    if (req.query.baseId) {
      query.baseId = req.query.baseId;
    } else if (req.admin.role === "gymAdmin") {
      query.baseId = req.admin.baseId;
    }

    const count = await Entry.countDocuments(query);
    res.json({ count });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get all successful entries today without base filtering
app.get(
  "/api/entries/today-successful-all",
  authMiddleware,
  async (req, res) => {
    try {
      const today = new Date().toISOString().split("T")[0];
      const query = {
        entryDate: today,
        status: "success",
      };

      const count = await Entry.countDocuments(query);
      res.json({ count });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Get entries from last hour
app.get("/api/entries/last-hour", authMiddleware, async (req, res) => {
  try {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    const query = {
      $or: [
        {
          entryDate: now.toISOString().split("T")[0],
          entryTime: { $gte: oneHourAgo.toTimeString().split(" ")[0] },
        },
        {
          entryDate: oneHourAgo.toISOString().split("T")[0],
          entryTime: { $gte: oneHourAgo.toTimeString().split(" ")[0] },
        },
      ],
    };

    // Apply base filter if provided
    if (req.query.baseId) {
      query.baseId = req.query.baseId;
    } else if (req.admin.role === "gymAdmin") {
      query.baseId = req.admin.baseId;
    }

    const entries = await Entry.find(query)
      .sort({ entryDate: -1, entryTime: -1 })
      .limit(10);

    res.json(entries);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get medical approval stats
app.get(
  "/api/trainees/medical-approval-stats",
  authMiddleware,
  async (req, res) => {
    try {
      const query = {};

      // Apply base filter if provided
      if (req.query.baseId) {
        query.baseId = req.query.baseId;
      } else if (req.admin.role === "gymAdmin") {
        query.baseId = req.admin.baseId;
      }

      const now = new Date();
      const approved = await Trainee.countDocuments({
        ...query,
        "medicalApproval.approved": true,
        "medicalApproval.expirationDate": { $gt: now },
      });

      const notApproved = await Trainee.countDocuments({
        ...query,
        $or: [
          { "medicalApproval.approved": false },
          { "medicalApproval.expirationDate": { $lte: now } },
        ],
      });

      res.json({ approved, notApproved });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Get top trainees from last month
app.get("/api/trainees/top", authMiddleware, async (req, res) => {
  try {
    const now = new Date();
    const lastMonth = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    // Build match conditions
    const matchConditions = {
      entryDate: {
        $gte: lastMonth.toISOString().split("T")[0],
        $lte: now.toISOString().split("T")[0],
      },
      status: EntryStatus.SUCCESS,
      traineeId: { $exists: true, $ne: null },
    };

    if (req.query.baseId) {
      matchConditions.baseId = new mongoose.Types.ObjectId(req.query.baseId);
    } else if (req.admin.role === "gymAdmin") {
      matchConditions.baseId = new mongoose.Types.ObjectId(req.admin.baseId);
    }

    // Use aggregation pipeline to get top trainees in a single query
    const topTrainees = await Entry.aggregate([
      // Match entries from last month with success status
      {
        $match: matchConditions,
      },
      {
        $group: {
          _id: "$traineeId",
          count: { $sum: 1 },
        },
      },
      // Sort by count in descending order
      {
        $sort: { count: -1 },
      },
      // Limit to top 7
      {
        $limit: 7,
      },
      // Lookup trainee details
      {
        $lookup: {
          from: "trainees",
          localField: "_id",
          foreignField: "_id",
          as: "trainee",
        },
      },
      // Unwind trainee array
      {
        $unwind: "$trainee",
      },
      // Lookup department details
      {
        $lookup: {
          from: "departments",
          localField: "trainee.departmentId",
          foreignField: "_id",
          as: "department",
        },
      },
      // Unwind department array
      {
        $unwind: {
          path: "$department",
          preserveNullAndEmptyArrays: true,
        },
      },
      // Lookup subdepartment details
      {
        $lookup: {
          from: "subdepartments",
          localField: "trainee.subDepartmentId",
          foreignField: "_id",
          as: "subDepartment",
        },
      },
      // Unwind subdepartment array
      {
        $unwind: {
          path: "$subDepartment",
          preserveNullAndEmptyArrays: true,
        },
      },
      // Lookup base details if general admin
      ...(req.admin.role === "generalAdmin"
        ? [
            {
              $lookup: {
                from: "bases",
                localField: "trainee.baseId",
                foreignField: "_id",
                as: "base",
              },
            },
            {
              $unwind: {
                path: "$base",
                preserveNullAndEmptyArrays: true,
              },
            },
          ]
        : []),
      // Project final format
      {
        $project: {
          id: "$_id",
          name: "$trainee.fullName",
          count: 1,
          departmentName: { $ifNull: ["$department.name", "-"] },
          subDepartmentName: { $ifNull: ["$subDepartment.name", "-"] },
          ...(req.admin.role === "generalAdmin" && {
            baseName: { $ifNull: ["$base.name", "-"] },
          }),
        },
      },
    ]);

    res.json(topTrainees);
  } catch (err) {
    console.error("Error in top trainees:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/trainees/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { populate } = req.query;

    // Build the query
    let query = Trainee.findById(id);

    // Add population if specified
    if (populate) {
      const fieldsToPopulate = populate.split(",");
      fieldsToPopulate.forEach((field) => {
        query = query.populate(field.trim());
      });
    }

    const trainee = await query.exec();

    if (!trainee) {
      return res.status(404).json({ message: "Trainee not found" });
    }

    res.json(trainee);
  } catch (error) {
    console.error("Error fetching trainee:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
