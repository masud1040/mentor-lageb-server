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

app.listen(port, () => {
    console.log(`MentorLagbe backend is running on port ${port}`)
})

export default app;