import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;
const CLIENT_URL = (
  process.env.CLIENT_URL || "https://mentor-lagbe-self.vercel.app"
).replace(/\/$/, "");
const JWT_SECRET =
  process.env.JWT_SECRET || "mentorlagbe_fallback_jwt_secret_change_in_env";

// ==================== MIDDLEWARES ====================
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: [
      CLIENT_URL,
      "https://mentor-lagbe-self.vercel.app",
      "http://localhost:3000",
    ],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// ==================== MONGODB CONNECTION ====================
const client = new MongoClient(process.env.MONGODB_URL, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
});

const database = client.db("MentorLagbe");

const users = database.collection("user");
const sessions = database.collection("session");
const tuitions = database.collection("tuitions");
const applications = database.collection("applications");
const payments = database.collection("payments");

app.get("/", (req, res) => {
  res.send("MentorLagbe backend is running!");
});

// ==================== HELPER: RESOLVE BETTERAUTH SESSION ====================
async function getUserFromBetterAuthCookie(req) {
  let rawToken =
    req.cookies?.["better-auth.session_token"] ||
    req.cookies?.["__Secure-better-auth.session_token"] ||
    null;

  if (!rawToken && req.headers.cookie) {
    const cookies = Object.fromEntries(
      req.headers.cookie.split(";").map((c) => {
        const [key, ...v] = c.trim().split("=");
        return [key, decodeURIComponent(v.join("="))];
      }),
    );
    rawToken =
      cookies["better-auth.session_token"] ||
      cookies["__Secure-better-auth.session_token"];
  }

  if (!rawToken) return null;

  const token = rawToken.split(".")[0];
  const session = await sessions.findOne({ token });
  if (!session) return null;

  const userId = session.userId;
  const user =
    (await users.findOne({ _id: userId })) ||
    (ObjectId.isValid(userId)
      ? await users.findOne({ _id: new ObjectId(userId) })
      : null);

  return user || null;
}

// ==================== JWT ISSUE ENDPOINT ====================
app.post("/jwt", async (req, res) => {
  try {
    const user = await getUserFromBetterAuthCookie(req);

    if (!user) {
      return res
        .status(401)
        .send({ success: false, message: "Unauthorized: No active session" });
    }

    const payload = {
      userId: user._id.toString(),
      email: user.email,
      role: user.role || "student",
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

    res.send({
      success: true,
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isPremium: Boolean(user.isPremium),
      },
    });
  } catch (error) {
    console.error("JWT Issue Error:", error);
    res
      .status(500)
      .send({ success: false, message: "Failed to generate JWT token" });
  }
});

// ==================== AUTH & ROLE MIDDLEWARES ====================
const verifyToken = async (req, res, next) => {
  try {
    const cookieUser = await getUserFromBetterAuthCookie(req);
    let user = null;

    if (req.headers.authorization?.startsWith("Bearer ")) {
      const bearerToken = req.headers.authorization.split(" ")[1];
      if (bearerToken && bearerToken !== "null" && bearerToken !== "undefined") {
        try {
          const decoded = jwt.verify(bearerToken, JWT_SECRET);
          if (decoded?.userId) {
            user =
              (await users.findOne({ _id: decoded.userId })) ||
              (ObjectId.isValid(decoded.userId)
                ? await users.findOne({ _id: new ObjectId(decoded.userId) })
                : null);
          } else if (decoded?.email) {
            user = await users.findOne({ email: decoded.email });
          }
        } catch {
          user = null;
        }
      }
    }

    if (user && cookieUser && user._id.toString() !== cookieUser._id.toString()) {
      return res
        .status(401)
        .send({ message: "Unauthorized: Stale JWT token, please refresh" });
    }

    if (!user) {
      user = cookieUser;
    }

    if (!user) {
      return res
        .status(401)
        .send({ message: "Unauthorized: Invalid or missing token" });
    }

    if (user.banned) {
      return res
        .status(403)
        .send({ message: "Forbidden: Your account has been suspended" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("verifyToken Error:", error);
    return res.status(500).send({ message: "Internal Server Error" });
  }
};

const verifyStudent = (req, res, next) => {
  if (req.user.role !== "student") {
    return res.status(403).send({ message: "Forbidden: Student access only" });
  }
  next();
};

const verifyMentor = (req, res, next) => {
  if (req.user.role !== "mentor" && req.user.role !== "tutor") {
    return res.status(403).send({ message: "Forbidden: Mentor access only" });
  }
  next();
};

const verifyTutor = verifyMentor;

const verifyAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).send({ message: "Forbidden: Admin access only" });
  }
  next();
};

// ==================== USERS RELATED APIS ====================

// Current logged-in user info (including isPremium & role)
app.get("/users/me", verifyToken, async (req, res) => {
  res.send(req.user);
});

// Get all users (Admin only, with role & search filter)
app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const query = {};
    if (req.query.role && req.query.role !== "all") {
      query.role = req.query.role;
    }
    if (req.query.search) {
      query.$or = [
        { name: { $regex: req.query.search, $options: "i" } },
        { email: { $regex: req.query.search, $options: "i" } },
      ];
    }

    const limit = req.query.limit ? parseInt(req.query.limit, 10) : 0;
    const cursor = users.find(query).sort({ createdAt: -1 });
    if (limit > 0) cursor.limit(limit);

    const result = await cursor.toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch users" });
  }
});

// Check user premium status
app.get("/users/:id/premium", async (req, res) => {
  try {
    const id = req.params.id;
    const user =
      (await users.findOne(
        { _id: id },
        { projection: { isPremium: 1, plan: 1 } },
      )) ||
      (ObjectId.isValid(id)
        ? await users.findOne(
            { _id: new ObjectId(id) },
            { projection: { isPremium: 1, plan: 1 } },
          )
        : null);

    res.send(user || { isPremium: false, plan: "free" });
  } catch (error) {
    res.status(500).send({ message: "Failed to check premium status" });
  }
});

// Update user role (Admin only)
app.patch("/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { role } = req.body;
    if (!["student", "mentor", "tutor", "admin"].includes(role)) {
      return res.status(400).send({ message: "Invalid role" });
    }

    const filter = ObjectId.isValid(id)
      ? { _id: new ObjectId(id) }
      : { _id: id };
    const result = await users.updateOne(filter, {
      $set: { role, updatedAt: new Date() },
    });
    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ message: "Failed to update role" });
  }
});

// Block / Unblock user (Admin only)
app.patch("/users/:id/ban", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { banned } = req.body;

    if (req.user._id.toString() === id) {
      return res.status(400).send({
        success: false,
        message: "You cannot block your own account.",
      });
    }

    const filter = ObjectId.isValid(id)
      ? { _id: new ObjectId(id) }
      : { _id: id };
    const result = await users.updateOne(filter, {
      $set: { banned: Boolean(banned), updatedAt: new Date() },
    });

    res.send({ success: true, result });
  } catch (error) {
    res
      .status(500)
      .send({ success: false, message: "Failed to update ban status" });
  }
});

// ==================== TUITION POSTS RELATED APIS ====================

// Get all tuitions (Filters, Search, Budget Range, Pagination & Limit)
app.get("/tuitions", async (req, res) => {
  try {
    const andConditions = [];

    if (req.query.category && req.query.category !== "all") {
      andConditions.push({ category: req.query.category });
    }
    if (req.query.isOnline === "true" || req.query.isOnline === "false") {
      andConditions.push({ isOnline: req.query.isOnline === "true" });
    }
    if (req.query.mentorId && req.query.mentorEmail) {
      andConditions.push({
        $or: [
          { authorId: req.query.mentorId },
          { authorEmail: req.query.mentorEmail },
        ],
      });
    } else if (req.query.mentorId) {
      andConditions.push({ authorId: req.query.mentorId });
    } else if (req.query.mentorEmail) {
      andConditions.push({ authorEmail: req.query.mentorEmail });
    }
    if (req.query.status && req.query.status !== "all") {
      andConditions.push({ status: req.query.status });
    }
    if (req.query.adminStatus && req.query.adminStatus !== "all") {
      andConditions.push({ adminStatus: req.query.adminStatus });
    }

    if (req.query.minBudget || req.query.maxBudget) {
      const budgetFilter = {};
      if (req.query.minBudget) budgetFilter.$gte = Number(req.query.minBudget);
      if (req.query.maxBudget) budgetFilter.$lte = Number(req.query.maxBudget);
      andConditions.push({ budget: budgetFilter });
    }

    if (req.query.search) {
      andConditions.push({
        $or: [
          { title: { $regex: req.query.search, $options: "i" } },
          { subject: { $regex: req.query.search, $options: "i" } },
          { location: { $regex: req.query.search, $options: "i" } },
          { description: { $regex: req.query.search, $options: "i" } },
        ],
      });
    }

    const query = andConditions.length > 0 ? { $and: andConditions } : {};

    if (req.query.page) {
      const page = Math.max(1, parseInt(req.query.page, 10) || 1);
      const limit = Math.max(1, parseInt(req.query.limit, 10) || 9);
      const skip = (page - 1) * limit;

      const [data, total] = await Promise.all([
        tuitions
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray(),
        tuitions.countDocuments(query),
      ]);

      return res.send({
        data,
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      });
    }

    const limit = req.query.limit ? parseInt(req.query.limit, 10) : 0;
    const cursor = tuitions.find(query).sort({ createdAt: -1 });
    if (limit > 0) cursor.limit(limit);

    const result = await cursor.toArray();
    res.send(result);
  } catch (error) {
    console.error("Get Tuitions Error:", error);
    res.status(500).send({ message: "Failed to fetch tuitions" });
  }
});

// Get single tuition details by ID
app.get("/tuitions/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid tuition ID" });
    }
    const result = await tuitions.findOne({ _id: new ObjectId(id) });
    if (!result) {
      return res.status(404).send({ message: "Tuition post not found" });
    }
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch tuition details" });
  }
});

// Post new tuition (Mentor/Tutor only + Free Limit Check: max 2 posts)
app.post("/tuitions", verifyToken, verifyTutor, async (req, res) => {
  try {
    const tuitionData = req.body;
    const mentorId = req.user._id.toString();
    const mentorEmail = req.user.email || "";

    if (!req.user.isPremium) {
      const postCount = await tuitions.countDocuments({
        $or: [
          { authorId: mentorId },
          ...(mentorEmail ? [{ authorEmail: mentorEmail }] : []),
        ],
      });

      if (postCount >= 2) {
        return res.status(403).send({
          success: false,
          requiresPricing: true,
          message:
            "Free limit exceeded. You can only post a maximum of 2 tuitions. Please upgrade to Pro.",
        });
      }
    }

    const newTuition = {
      ...tuitionData,
      image:
        typeof tuitionData.image === "string" ? tuitionData.image.trim() : "",
      budget: Number(tuitionData.budget) || 0,
      authorId: mentorId,
      authorName: req.user.name || "Mentor",
      authorEmail: mentorEmail,
      status: "active",
      adminStatus: "pending",
      applicantsCount: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await tuitions.insertOne(newTuition);
    res.send({ success: true, result });
  } catch (error) {
    console.error("Create Tuition Error:", error);
    res.status(500).send({ success: false, message: "Failed to create post" });
  }
});

// Update tuition (Mentor edits/closes own post)
app.patch("/tuitions/:id", verifyToken, verifyTutor, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid tuition ID" });
    }

    const { adminStatus, _id, authorId, authorEmail, ...safeUpdate } = req.body;

    const filter = {
      _id: new ObjectId(id),
      $or: [
        { authorId: req.user._id.toString() },
        { authorEmail: req.user.email },
      ],
    };

    const result = await tuitions.updateOne(filter, {
      $set: {
        ...safeUpdate,
        updatedAt: new Date(),
      },
    });

    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ success: false, message: "Failed to update post" });
  }
});

// Admin: Approve, Reject, or Re-approve tuition post
app.patch(
  "/admin/tuitions/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const id = req.params.id;
      const { adminStatus } = req.body;

      if (!ObjectId.isValid(id)) {
        return res
          .status(400)
          .send({ success: false, message: "Invalid tuition ID" });
      }
      if (!["approved", "rejected", "pending"].includes(adminStatus)) {
        return res
          .status(400)
          .send({ success: false, message: "Invalid status value" });
      }

      const result = await tuitions.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            adminStatus,
            updatedAt: new Date(),
          },
        },
      );

      res.send({ success: true, result });
    } catch (error) {
      res
        .status(500)
        .send({ success: false, message: "Failed to update admin status" });
    }
  },
);

// Delete tuition post (Mentor own post OR Admin any post)
app.delete("/tuitions/:id", verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid tuition ID" });
    }

    const filter =
      req.user.role === "admin"
        ? { _id: new ObjectId(id) }
        : {
            _id: new ObjectId(id),
            $or: [
              { authorId: req.user._id.toString() },
              { authorEmail: req.user.email },
            ],
          };

    const result = await tuitions.deleteOne(filter);
    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ success: false, message: "Failed to delete post" });
  }
});

// ==================== APPLICATIONS RELATED APIS ====================

app.get("/applications", verifyToken, async (req, res) => {
  try {
    const query = {};
    if (req.query.applicantId) {
      query.userId = req.query.applicantId;
    }
    if (req.query.tuitionId) {
      if (!ObjectId.isValid(req.query.tuitionId)) {
        return res.status(400).send({ message: "Invalid tuition ID" });
      }
      const tuition = await tuitions.findOne({
        _id: new ObjectId(req.query.tuitionId),
      });

      if (
        !tuition ||
        (tuition.authorId !== req.user._id.toString() &&
          tuition.authorEmail !== req.user.email &&
          req.user.role !== "admin")
      ) {
        return res.status(403).send({ message: "Forbidden" });
      }
      query.tuitionId = req.query.tuitionId;
    }

    const result = await applications
      .find(query)
      .sort({ appliedAt: -1 })
      .toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch applications" });
  }
});

// Apply for a tuition (Student only + Duplicate & Active/Approved check)
app.post("/applications", verifyToken, verifyStudent, async (req, res) => {
  try {
    const application = req.body;
    const studentId = req.user._id.toString();

    if (!ObjectId.isValid(application.tuitionId)) {
      return res
        .status(400)
        .send({ success: false, message: "Invalid tuition ID" });
    }

    const tuition = await tuitions.findOne({
      _id: new ObjectId(application.tuitionId),
    });

    if (
      !tuition ||
      tuition.status !== "active" ||
      tuition.adminStatus !== "approved"
    ) {
      return res.status(400).send({
        success: false,
        message: "This tuition post is closed or unavailable.",
      });
    }

    const activeApplication = await applications.findOne({
      tuitionId: application.tuitionId,
      userId: studentId,
      status: { $ne: "rejected" },
    });

    if (activeApplication) {
      return res.status(400).send({
        success: false,
        message: "You have already applied for this tuition.",
      });
    }

    const result = await applications.insertOne({
      ...application,
      userId: studentId,
      studentName: req.user.name || "Student",
      studentEmail: req.user.email || "",
      tuitionTitle: tuition.title,
      status: "pending",
      appliedAt: new Date(),
      studentClass: req.user.studentClass || "",
      studentInstitution: req.user.institution || "",
      studentLocation: req.user.location || "",
    });

    await tuitions.updateOne(
      { _id: new ObjectId(application.tuitionId) },
      { $inc: { applicantsCount: 1 } },
    );

    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ success: false, message: "Failed to apply" });
  }
});

// Update application status (Mentor/Admin)
app.patch("/applications/:id", verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid application ID" });
    }

    const result = await applications.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: req.body.status, updatedAt: new Date() } },
    );
    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ message: "Failed to update application status" });
  }
});

// Cancel/Delete a pending application (Student only)
app.delete("/applications/:id", verifyToken, verifyStudent, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) {
      return res
        .status(400)
        .send({ success: false, message: "Invalid application ID" });
    }

    const existing = await applications.findOne({
      _id: new ObjectId(id),
      userId: req.user._id.toString(),
    });

    if (!existing) {
      return res
        .status(404)
        .send({ success: false, message: "Application not found" });
    }

    if (existing.status !== "pending") {
      return res.status(400).send({
        success: false,
        message: "Only pending applications can be canceled.",
      });
    }

    await applications.deleteOne({ _id: new ObjectId(id) });

    if (existing.tuitionId && ObjectId.isValid(existing.tuitionId)) {
      await tuitions.updateOne(
        { _id: new ObjectId(existing.tuitionId), applicantsCount: { $gt: 0 } },
        { $inc: { applicantsCount: -1 } },
      );
    }

    res.send({ success: true, message: "Application canceled successfully." });
  } catch (error) {
    res
      .status(500)
      .send({ success: false, message: "Failed to cancel application" });
  }
});

// ==================== PROFILE & PUBLIC MENTORS APIS ====================

// 1. Update logged-in user's own profile (Mentor, Student, Admin)
app.patch("/users/me/profile", verifyToken, async (req, res) => {
  try {
    const userId = req.user._id;
    const {
      name,
      image,
      bio,
      phone,
      gender,
      location,
      education,
      currentOccupation,
      cvUrl,
      expertSubjects,
      studentClass,
      institution,
    } = req.body;

    const updateFields = {
      updatedAt: new Date(),
    };

    if (name !== undefined) updateFields.name = String(name).trim();
    if (image !== undefined) updateFields.image = String(image).trim();
    if (bio !== undefined) updateFields.bio = String(bio).trim();
    if (phone !== undefined) updateFields.phone = String(phone).trim();
    if (gender !== undefined) updateFields.gender = String(gender).trim();
    if (location !== undefined) updateFields.location = String(location).trim();

    if (req.user.role === "mentor" || req.user.role === "tutor") {
      if (education !== undefined)
        updateFields.education = String(education).trim();
      if (currentOccupation !== undefined)
        updateFields.currentOccupation = String(currentOccupation).trim();
      if (cvUrl !== undefined) updateFields.cvUrl = String(cvUrl).trim();
      if (Array.isArray(expertSubjects)) {
        updateFields.expertSubjects = expertSubjects
          .map((s) => String(s).trim())
          .filter(Boolean);
      }
    }

    if (req.user.role === "student") {
      if (studentClass !== undefined)
        updateFields.studentClass = String(studentClass).trim();
      if (institution !== undefined)
        updateFields.institution = String(institution).trim();
    }

    await users.updateOne({ _id: userId }, { $set: updateFields });
    const updatedUser = await users.findOne({ _id: userId });

    res.send({ success: true, user: updatedUser });
  } catch (error) {
    console.error("Update Profile Error:", error);
    res
      .status(500)
      .send({ success: false, message: "Failed to update profile" });
  }
});

// 2. Public: Get all mentors (with search, subject, sort=top & limit)
app.get("/mentors", async (req, res) => {
  try {
    const query = {
      role: "mentor",
      banned: { $ne: true },
    };

    if (req.query.search) {
      query.$or = [
        { name: { $regex: req.query.search, $options: "i" } },
        { location: { $regex: req.query.search, $options: "i" } },
        { education: { $regex: req.query.search, $options: "i" } },
        { expertSubjects: { $regex: req.query.search, $options: "i" } },
      ];
    }

    if (req.query.subject && req.query.subject !== "all") {
      query.expertSubjects = { $regex: req.query.subject, $options: "i" };
    }

    const mentorList = await users
      .find(query, {
        projection: {
          name: 1,
          email: 1,
          image: 1,
          bio: 1,
          gender: 1,
          location: 1,
          education: 1,
          currentOccupation: 1,
          cvUrl: 1,
          expertSubjects: 1,
          isPremium: 1,
          createdAt: 1,
        },
      })
      .sort({ isPremium: -1, createdAt: -1 })
      .toArray();

    const enriched = await Promise.all(
      mentorList.map(async (m) => {
        const mentorTuitions = await tuitions
          .find(
            {
              $or: [{ authorId: m._id.toString() }, { authorEmail: m.email }],
            },
            { projection: { _id: 1, status: 1, adminStatus: 1 } },
          )
          .toArray();

        const postsCount = mentorTuitions.filter(
          (t) => t.adminStatus === "approved" && t.status === "active",
        ).length;

        const tuitionIds = mentorTuitions.map((t) => t._id.toString());

        let studentsCount = 0;
        let applicantsCount = 0;

        if (tuitionIds.length > 0) {
          const acceptedUserIds = await applications.distinct("userId", {
            tuitionId: { $in: tuitionIds },
            status: "accepted",
          });
          studentsCount = acceptedUserIds.length;

          applicantsCount = await applications.countDocuments({
            tuitionId: { $in: tuitionIds },
            status: { $ne: "rejected" },
          });
        }

        return {
          ...m,
          postsCount,
          studentsCount,
          applicantsCount,
        };
      }),
    );

    if (req.query.sort === "top") {
      enriched.sort((a, b) => {
        if (b.studentsCount !== a.studentsCount) {
          return b.studentsCount - a.studentsCount;
        }
        if (b.applicantsCount !== a.applicantsCount) {
          return b.applicantsCount - a.applicantsCount;
        }
        if (b.postsCount !== a.postsCount) {
          return b.postsCount - a.postsCount;
        }
        return Number(Boolean(b.isPremium)) - Number(Boolean(a.isPremium));
      });
    }

    const limit = parseInt(req.query.limit, 10);
    const finalResult =
      !isNaN(limit) && limit > 0 ? enriched.slice(0, limit) : enriched;

    res.send(finalResult);
  } catch (error) {
    console.error("Get Mentors Error:", error);
    res.status(500).send({ message: "Failed to fetch mentors" });
  }
});

// 3. Public: Get single mentor profile + their approved tuition posts
app.get("/mentors/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const mentor =
      (await users.findOne({ _id: id, role: "mentor" })) ||
      (ObjectId.isValid(id)
        ? await users.findOne({ _id: new ObjectId(id), role: "mentor" })
        : null);

    if (!mentor) {
      return res.status(404).send({ message: "Mentor not found" });
    }

    const mentorPosts = await tuitions
      .find({
        $or: [
          { authorId: mentor._id.toString() },
          { authorEmail: mentor.email },
        ],
        adminStatus: "approved",
        status: "active",
      })
      .sort({ createdAt: -1 })
      .toArray();

    res.send({
      mentor: {
        _id: mentor._id,
        name: mentor.name,
        email: mentor.email,
        image: mentor.image,
        bio: mentor.bio,
        gender: mentor.gender,
        location: mentor.location,
        education: mentor.education,
        currentOccupation: mentor.currentOccupation,
        cvUrl: mentor.cvUrl,
        expertSubjects: mentor.expertSubjects || [],
        isPremium: mentor.isPremium,
        createdAt: mentor.createdAt,
      },
      posts: mentorPosts,
    });
  } catch (error) {
    console.error("Get Single Mentor Error:", error);
    res.status(500).send({ message: "Failed to fetch mentor profile" });
  }
});

// ==================== STRIPE PAYMENT APIS ====================

// Create Stripe Checkout Session (Both Mentor & Student Pro Upgrade)
app.post("/payments/create-checkout-session", verifyToken, async (req, res) => {
  try {
    const userRole = req.user.role || "student";

    if (userRole === "admin") {
      return res
        .status(403)
        .send({ success: false, message: "Admin accounts do not need Pro." });
    }

    if (req.user.isPremium) {
      return res
        .status(400)
        .send({ success: false, message: "You are already on the Pro Plan." });
    }

    const isMentor = userRole === "mentor" || userRole === "tutor";
    const defaultPlanName = isMentor ? "Mentor Pro Plan" : "Student Pro Plan";
    const defaultPrice = isMentor ? 500 : 300;

    const {
      planName = defaultPlanName,
      price = defaultPrice,
      successPath,
      cancelPath,
    } = req.body;

    const defaultSuccess = isMentor
      ? "/dashboard/mentor/pricing/success"
      : "/payment/success";
    const defaultCancel = isMentor
      ? "/dashboard/mentor/pricing?canceled=true"
      : "/payment/cancel";

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      customer_email: req.user.email,
      line_items: [
        {
          price_data: {
            currency: "bdt",
            product_data: {
              name: planName,
              description: isMentor
                ? "Unlimited tuition posts & verified Pro badge on MentorLagbe"
                : "Priority booking & verified Pro Student badge on MentorLagbe",
            },
            unit_amount: Math.round(Number(price) * 100),
          },
          quantity: 1,
        },
      ],
      metadata: {
        userId: req.user._id.toString(),
        userRole,
        planName,
      },
      success_url: `${CLIENT_URL}${successPath || defaultSuccess}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${CLIENT_URL}${cancelPath || defaultCancel}`,
    });

    res.send({ success: true, url: session.url, sessionId: session.id });
  } catch (error) {
    console.error("Stripe Checkout Error:", error);
    res.status(500).send({ success: false, message: error.message });
  }
});

// Verify Stripe Payment & Upgrade User to Premium
app.post("/payments/verify-session", verifyToken, async (req, res) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) {
      return res
        .status(400)
        .send({ success: false, message: "Session ID is required" });
    }

    const stripeSession = await stripe.checkout.sessions.retrieve(sessionId);
    if (stripeSession.payment_status !== "paid") {
      return res
        .status(400)
        .send({ success: false, message: "Payment not completed" });
    }

    const userId = req.user._id.toString();

    if (
      stripeSession.metadata?.userId &&
      stripeSession.metadata.userId !== userId
    ) {
      return res
        .status(403)
        .send({ success: false, message: "Unauthorized payment session" });
    }

    const existingPayment = await payments.findOne({
      stripeSessionId: sessionId,
    });

    if (!existingPayment) {
      await payments.insertOne({
        userId,
        userName: req.user.name || "User",
        userEmail: req.user.email,
        userRole: req.user.role || "student",
        planName: stripeSession.metadata?.planName || "Pro Plan",
        amount: stripeSession.amount_total / 100,
        currency: stripeSession.currency,
        stripeSessionId: sessionId,
        status: "paid",
        createdAt: new Date(),
      });
    }

    const filter = ObjectId.isValid(userId)
      ? { _id: new ObjectId(userId) }
      : { _id: userId };

    await users.updateOne(filter, {
      $set: { isPremium: true, plan: "pro", upgradedAt: new Date() },
    });

    res.send({ success: true, message: "Account upgraded to Pro!" });
  } catch (error) {
    console.error("Stripe Verify Error:", error);
    res
      .status(500)
      .send({ success: false, message: "Payment verification failed" });
  }
});

// Get Payments (Admin sees all, Mentor/Student sees own)
app.get("/payments", verifyToken, async (req, res) => {
  try {
    const query =
      req.user.role === "admin"
        ? {}
        : {
            $or: [
              { userId: req.user._id.toString() },
              ...(req.user.email ? [{ userEmail: req.user.email }] : []),
            ],
          };

    const result = await payments.find(query).sort({ createdAt: -1 }).toArray();
    res.send(result);
  } catch (error) {
    console.error("Get Payments Error:", error);
    res.status(500).send({ message: "Failed to fetch payments" });
  }
});

if (!process.env.VERCEL) {
  app.listen(port, () => {
    console.log(`MentorLagbe backend is running on port ${port}`);
  });
}

export default app;