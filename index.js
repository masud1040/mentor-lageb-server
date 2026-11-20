import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";

// ==================== MIDDLEWARES ====================
app.use(express.json());
app.use(
  cors({
    origin: [CLIENT_URL, "http://localhost:3000"],
    credentials: true,
  }),
);

// ==================== MONGODB CONNECTION ====================
const client = new MongoClient(process.env.MONGODB_URL);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.error("MongoDB Connection Error:", err);
  }
}

const connectedClient = await connectToMongoDB();
const database = connectedClient.db("MentorLagbe");

const users = database.collection("user");
const sessions = database.collection("session");
const tuitions = database.collection("tuitions");
const applications = database.collection("applications");
const payments = database.collection("payments");

app.get("/", (req, res) => {
  res.send("MentorLagbe backend is running!");
});

// ==================== AUTH & ROLE MIDDLEWARES ====================
const verifyToken = async (req, res, next) => {
  try {
    let rawToken = null;

    // 1. Authorization header theke token check
    if (req.headers.authorization?.startsWith("Bearer ")) {
      rawToken = req.headers.authorization.split(" ")[1];
    }

    // 2. Cookie theke BetterAuth session token check
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

    if (!rawToken) {
      return res.status(401).send({ message: "Unauthorized: No token found" });
    }

    const token = rawToken.split(".")[0];
    const session = await sessions.findOne({ token });
    if (!session) {
      return res.status(401).send({ message: "Unauthorized: Invalid session" });
    }

    const userId = session.userId;
    const user =
      (await users.findOne({ _id: userId })) ||
      (ObjectId.isValid(userId)
        ? await users.findOne({ _id: new ObjectId(userId) })
        : null);

    if (!user) {
      return res.status(401).send({ message: "Unauthorized: User not found" });
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
  if (req.user.role !== "mentor") {
    return res.status(403).send({ message: "Forbidden: Mentor access only" });
  }
  next();
};

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
      (await users.findOne({ _id: id }, { projection: { isPremium: 1 } })) ||
      (ObjectId.isValid(id)
        ? await users.findOne(
            { _id: new ObjectId(id) },
            { projection: { isPremium: 1 } },
          )
        : null);

    res.send(user || { isPremium: false });
  } catch (error) {
    res.status(500).send({ message: "Failed to check premium status" });
  }
});

// Update user role (Admin only)
app.patch("/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { role } = req.body;
    if (!["student", "mentor", "admin"].includes(role)) {
      return res.status(400).send({ message: "Invalid role" });
    }

    const filter = ObjectId.isValid(id)
      ? { _id: new ObjectId(id) }
      : { _id: id };
    const result = await users.updateOne(filter, { $set: { role } });
    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ message: "Failed to update role" });
  }
});

// Block / Unblock user (Admin only)
app.patch("/users/:id/ban", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { banned } = req.body; // true | false

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
      $set: { banned: Boolean(banned), updatedAt: new Dat() + e() },
    });

    res.send({ success: true, result });
  } catch (error) {
    res
      .status(500)
      .send({ success: false, message: "Failed to update ban status" });
  }
});

// ==================== TUITION POSTS RELATED APIS ====================

// Get all tuitions (Filters, Search, Budget Range & Limit)
app.get("/tuitions", async (req, res) => {
  try {
    const query = {};

    if (req.query.category && req.query.category !== "all") {
      query.category = req.query.category;
    }
    if (req.query.isOnline === "true" || req.query.isOnline === "false") {
      query.isOnline = req.query.isOnline === "true";
    }
    if (req.query.mentorId && req.query.mentorEmail) {
      query.$or = [
        { authorId: req.query.mentorId },
        { authorEmail: req.query.mentorEmail },
      ];
    } else if (req.query.mentorId) {
      query.authorId = req.query.mentorId;
    } else if (req.query.mentorEmail) {
      query.authorEmail = req.query.mentorEmail;
    }
    if (req.query.status && req.query.status !== "all") {
      query.status = req.query.status;
    }
    if (req.query.adminStatus && req.query.adminStatus !== "all") {
      query.adminStatus = req.query.adminStatus;
    }

    // Budget range filter
    if (req.query.minBudget || req.query.maxBudget) {
      query.budget = {};
      if (req.query.minBudget) query.budget.$gte = Number(req.query.minBudget);
      if (req.query.maxBudget) query.budget.$lte = Number(req.query.maxBudget);
    }

    // Search filter
    if (req.query.search) {
      query.$or = [
        { title: { $regex: req.query.search, $options: "i" } },
        { subject: { $regex: req.query.search, $options: "i" } },
        { location: { $regex: req.query.search, $options: "i" } },
        { description: { $regex: req.query.search, $options: "i" } },
      ];
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

// Post new tuition (Mentor only + Free Limit Check: max 2 posts)
app.post("/tuitions", verifyToken, verifyMentor, async (req, res) => {
  try {
    const tuitionData = req.body;
    const mentorId = req.user._id.toString();

    if (!req.user.isPremium) {
      const postCount = await tuitions.countDocuments({ authorId: mentorId });
      if (postCount >= 2) {
        return res.status(403).send({
          success: false,
          requiresPricing: true,
          message:
            "Free limit exceeded. You can only post a maximum of 2 tuitions. Please upgrade your plan.",
        });
      }
    }

    const newTuition = {
      ...tuitionData,
      budget: Number(tuitionData.budget) || 0,
      authorId: mentorId,
      authorName: req.user.name || "Mentor",
      authorEmail: req.user.email || "",
      status: "active", // active | closed
      adminStatus: "pending", // pending | approved | rejected
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
app.patch("/tuitions/:id", verifyToken, verifyMentor, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid tuition ID" });
    }

    // Mentor nijera adminStatus change korte parbe na
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
      const { adminStatus } = req.body; // 'approved' | 'rejected' | 'pending'

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
      status: "pending", // pending | accepted | rejected
      appliedAt: new Date(),
      studentClass: req.user.studentClass || '',
      studentInstitution: req.user.institution || '',
      studentLocation: req.user.location || '',
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

// ==================== PROFILE & PUBLIC MENTORS APIS ====================

// 1. Update logged-in user's own profile (Mentor & Student both)
app.patch('/users/me/profile', verifyToken, async (req, res) => {
  try {
    const userId = req.user._id;
    const {
      name,
      image,
      bio,
      gender,
      location,
      // Mentor fields
      education,
      currentOccupation,
      cvUrl,
      expertSubjects,
      // Student fields
      studentClass,
      institution,
    } = req.body;

    const updateFields = {
      updatedAt: new Date(),
    };

    if (name !== undefined) updateFields.name = String(name).trim();
    if (image !== undefined) updateFields.image = String(image).trim();
    if (bio !== undefined) updateFields.bio = String(bio).trim();
    if (gender !== undefined) updateFields.gender = String(gender).trim();
    if (location !== undefined) updateFields.location = String(location).trim();

    if (req.user.role === 'mentor') {
      if (education !== undefined) updateFields.education = String(education).trim();
      if (currentOccupation !== undefined)
        updateFields.currentOccupation = String(currentOccupation).trim();
      if (cvUrl !== undefined) updateFields.cvUrl = String(cvUrl).trim();
      if (Array.isArray(expertSubjects)) {
        updateFields.expertSubjects = expertSubjects
          .map((s) => String(s).trim())
          .filter(Boolean);
      }
    }

    if (req.user.role === 'student') {
      if (studentClass !== undefined)
        updateFields.studentClass = String(studentClass).trim();
      if (institution !== undefined)
        updateFields.institution = String(institution).trim();
    }

    await users.updateOne({ _id: userId }, { $set: updateFields });
    const updatedUser = await users.findOne({ _id: userId });

    res.send({ success: true, user: updatedUser });
  } catch (error) {
    console.error('Update Profile Error:', error);
    res.status(500).send({ success: false, message: 'Failed to update profile' });
  }
});

// 2. Public: Get all mentors (with search & subject filter)
// 2. Public: Get all mentors (with search, subject, sort=top & limit)
app.get('/mentors', async (req, res) => {
  try {
    const query = {
      role: 'mentor',
      banned: { $ne: true },
    };

    if (req.query.search) {
      query.$or = [
        { name: { $regex: req.query.search, $options: 'i' } },
        { location: { $regex: req.query.search, $options: 'i' } },
        { education: { $regex: req.query.search, $options: 'i' } },
        { expertSubjects: { $regex: req.query.search, $options: 'i' } },
      ];
    }

    if (req.query.subject && req.query.subject !== 'all') {
      query.expertSubjects = { $regex: req.query.subject, $options: 'i' };
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
            { projection: { _id: 1, status: 1, adminStatus: 1 } }
          )
          .toArray();

        const postsCount = mentorTuitions.filter(
          (t) => t.adminStatus === 'approved' && t.status === 'active'
        ).length;

        const tuitionIds = mentorTuitions.map((t) => t._id.toString());

        let studentsCount = 0;
        let applicantsCount = 0;

        if (tuitionIds.length > 0) {
          const acceptedUserIds = await applications.distinct('userId', {
            tuitionId: { $in: tuitionIds },
            status: 'accepted',
          });
          studentsCount = acceptedUserIds.length;

          applicantsCount = await applications.countDocuments({
            tuitionId: { $in: tuitionIds },
            status: { $ne: 'rejected' },
          });
        }

        return {
          ...m,
          postsCount,
          studentsCount,
          applicantsCount,
        };
      })
    );

    // Home page-er Top Mentors ranking: Beshi student -> Beshi applicant -> Beshi post -> Pro
    if (req.query.sort === 'top') {
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
    console.error('Get Mentors Error:', error);
    res.status(500).send({ message: 'Failed to fetch mentors' });
  }
});

// 3. Public: Get single mentor profile + their approved tuition posts
app.get('/mentors/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const mentor =
      (await users.findOne({ _id: id, role: 'mentor' })) ||
      (ObjectId.isValid(id)
        ? await users.findOne({ _id: new ObjectId(id), role: 'mentor' })
        : null);

    if (!mentor) {
      return res.status(404).send({ message: 'Mentor not found' });
    }

    const mentorPosts = await tuitions
      .find({
        $or: [
          { authorId: mentor._id.toString() },
          { authorEmail: mentor.email },
        ],
        adminStatus: 'approved',
        status: 'active',
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
    console.error('Get Single Mentor Error:', error);
    res.status(500).send({ message: 'Failed to fetch mentor profile' });
  }
});







// ==================== STRIPE PAYMENT APIS ====================

// Create Stripe Checkout Session (Mentor Premium Upgrade)
app.post("/payments/create-checkout-session", verifyToken, async (req, res) => {
  try {
    const { planName = "Mentor Pro Plan", price = 500 } = req.body;

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      customer_email: req.user.email,
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: planName,
              description: "Unlimited tuition posts on MentorLagbe",
            },
            unit_amount: Math.round(Number(price) * 100),
          },
          quantity: 1,
        },
      ],
      metadata: {
        userId: req.user._id.toString(),
        planName,
      },
      success_url: `${CLIENT_URL}/dashboard/mentor/pricing?success=true&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${CLIENT_URL}/dashboard/mentor/pricing?canceled=true`,
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

    // Prevent duplicate payment record
    const existingPayment = await payments.findOne({
      stripeSessionId: sessionId,
    });

    if (!existingPayment) {
      await payments.insertOne({
        userId,
        userEmail: req.user.email,
        planName: stripeSession.metadata?.planName || "Mentor Pro Plan",
        amount: stripeSession.amount_total / 100,
        currency: stripeSession.currency,
        stripeSessionId: sessionId,
        status: "paid",
        createdAt: new Date(),
      });
    }

    // Upgrade user to premium
    const filter = ObjectId.isValid(userId)
      ? { _id: new ObjectId(userId) }
      : { _id: userId };

    await users.updateOne(filter, {
      $set: { isPremium: true, upgradedAt: new Date() },
    });

    res.send({ success: true, message: "Account upgraded to Premium!" });
  } catch (error) {
    console.error("Stripe Verify Error:", error);
    res
      .status(500)
      .send({ success: false, message: "Payment verification failed" });
  }
});

// Get payments history (Admin sees all, user sees own)
app.get("/payments", verifyToken, async (req, res) => {
  try {
    const query =
      req.user.role === "admin" ? {} : { userId: req.user._id.toString() };
    const result = await payments.find(query).sort({ createdAt: -1 }).toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch payments" });
  }
});

app.listen(port, () => {
  console.log(`MentorLagbe backend is running on port ${port}`);
});

export default app;
