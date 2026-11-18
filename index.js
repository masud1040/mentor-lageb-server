import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { MongoClient, ObjectId } from 'mongodb';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(express.json());
app.use(cors());

//MongoDB কানেকশন
const client = new MongoClient(process.env.MONGODB_URL);

export async function connectToMongoDB() {
    try {
        await client.connect();
        console.log("You successfully connected to MongoDB!");
        return client;
    } catch (err) {
        console.dir(err);
    }
}
//all db 
const connectedClient = await connectToMongoDB();
const database = connectedClient.db("mentorlagbedb");
const users = database.collection("users");
const sessions = database.collection("sessions");
const tuitions = database.collection("tuitions");
const applications = database.collection("applications");
const payments = database.collection("payments");

app.get('/', (req, res) => {
    res.send('MentorLagbe backend is looping and running!')
})
// ==================== AUTH & ROLE MIDDLEWARES ====================
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    const query = { token };
    const session = await sessions.findOne(query);
    if (!session) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    const userId = session.userId;
    const userQuery = { _id: new ObjectId(userId) };
    const user = await users.findOne(userQuery);
    if (!user) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    req.user = user;
    next();
}

const verifyStudent = async (req, res, next) => {
    if (req.user.role !== 'student') {
        res.status(403).send({ message: 'Forbidden: Student access only' });
        return;
    }
    next();
}

const verifyMentor = async (req, res, next) => {
    if (req.user.role !== 'mentor') {
        res.status(403).send({ message: 'Forbidden: Mentor access only' });
        return;
    }
    next();
}

const verifyAdmin = async (req, res, next) => {
    if (req.user.role !== 'admin') {
        res.status(403).send({ message: 'Forbidden: Admin access only' });
        return;
    }
    next();
}

// ==================== USERS RELATED APIS ====================
app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
    const cursor = users.find({});
    const result = await cursor.toArray();
    res.send(result);
})

app.get('/users/:id/premium', async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await users.findOne(query, { projection: { isPremium: 1 } });
    res.send(result);
})

app.patch('/users/:id/role', verifyToken, verifyAdmin, async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const updatedDoc = {
        $set: {
            role: req.body.role,
        }
    }
    const result = await users.updateOne(query, updatedDoc);
    res.send(result);
})


// ==================== TUITION POSTS RELATED APIS ====================

// Get all tuitions (with filters & search) + Public/Student view
app.get('/tuitions', async (req, res) => {
    const query = {};
    if (req.query) {
        if (req.query.category) {
            query.category = req.query.category;
        }
        if (req.query.isOnline) {
            query.isOnline = req.query.isOnline === 'true';
        }
        if (req.query.mentorId) {
            query.authorId = req.query.mentorId;
        }
        // Public/Student browse e shudhu active posts dekhabe, mentor tar nijer shob dekhbe
        if (req.query.status) {
            query.status = req.query.status;
        }
        if (req.query.search) {
            query.$or = [
                { title: { $regex: req.query.search, $options: 'i' } },
                { subject: { $regex: req.query.search, $options: 'i' } },
                { location: { $regex: req.query.search, $options: 'i' } },
                { description: { $regex: req.query.search, $options: 'i' } }
            ];
        }
    }

    const cursor = tuitions.find(query).sort({ createdAt: -1 });
    const result = await cursor.toArray();
    res.send(result);
})

// Get single tuition details by ID
app.get('/tuitions/:id', async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await tuitions.findOne(query);
    res.send(result);
})

// Post new tuition (Mentor only + Free Limit Check: max 2 posts)
app.post('/tuitions', verifyToken, verifyMentor, async (req, res) => {
    const tuitionData = req.body;
    const mentorId = req.user._id.toString();

    // Check if user is premium or not
    if (!req.user.isPremium) {
        const postCount = await tuitions.countDocuments({ authorId: mentorId });
        if (postCount >= 2) {
            return res.status(403).send({ 
                success: false, 
                requiresPricing: true, 
                message: 'Free limit exceeded. You can only post a maximum of 2 tuitions. Please upgrade your plan.' 
            });
        }
    }

    const newTuition = {
        ...tuitionData,
        authorId: mentorId,
        authorName: req.user.name || 'Mentor',
        status: 'active',       // active / closed
        adminStatus: 'pending', // pending / approved / rejected
        applicantsCount: 0,
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    const result = await tuitions.insertOne(newTuition);
    res.send({ success: true, result });
})

// Update tuition status (Close post / Edit)
app.patch('/tuitions/:id', verifyToken, verifyMentor, async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id), authorId: req.user._id.toString() };
    
    const updatedDoc = {
        $set: {
            ...req.body,
            updatedAt: new Date()
        }
    };

    const result = await tuitions.updateOne(query, updatedDoc);
    res.send(result);
})

// Delete tuition post (Mentor only)
app.delete('/tuitions/:id', verifyToken, verifyMentor, async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id), authorId: req.user._id.toString() };
    const result = await tuitions.deleteOne(query);
    res.send(result);
})




app.listen(port, () => {
    console.log(`MentorLagbe backend is running on port ${port}`)
})

export default app;