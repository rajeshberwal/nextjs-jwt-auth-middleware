import { MongoClient } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

const client = new MongoClient(`${process.env.MONGO_URI}`);

export async function connectToDatabase() {
  try {
    await client.connect();
  } catch (err) {
    console.log(err);
  }
  return client;
}
