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

// HireLoop এর স্টাইলে MongoDB কানেকশন
const client = new MongoClient(process.env.MONGODB_URL);



app.listen(port, () => {
    console.log(`MentorLagbe backend is running on port ${port}`)
})

export default app;