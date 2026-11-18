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


app.listen(port, () => {
    console.log(`MentorLagbe backend is running on port ${port}`)
})

export default app;