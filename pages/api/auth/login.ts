import bcrpt from "bcryptjs";
import { SignJWT, type JWTPayload } from "jose";
import { NextApiRequest, NextApiResponse } from "next";
import { connectToDatabase } from "../../../lib/db";

import dotenv from "dotenv";

dotenv.config();

// Sign the JWT with the payload and the secret
// Note: Next.js Edge Functions do not support jsonwebtoken, so we use jose instead
// (The Next.js Edge Runtime is based on standard Web APIs, which is used by Middleware and Edge API Routes.)
// @link: https://nextjs.org/docs/api-reference/edge-runtime
export async function sign(
  payload: JWTPayload,
  secret: string
): Promise<string> {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 60 * 60; // one hour

  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setExpirationTime(exp)
    .setIssuedAt(iat)
    .setNotBefore(iat)
    .sign(new TextEncoder().encode(secret));
}

// Login API Handler
// @link: https://nextjs.org/docs/api-routes/introduction
export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== "POST") {
    return;
  }

  // get email and password from request body
  const { email, password } = req.body;

  // connect to database
  const client = await connectToDatabase();

  // get user from database
  const usersCollection = client.db().collection("users");
  const user = await usersCollection.findOne({ email: email });

  // if no user found, return error
  if (!user) {
    client.close();
    return res.status(404).json({ message: "User not found" });
  }

  // compare password with hashed password
  const isValid = await bcrpt.compare(password, user.password);

  // if password is not valid, return error
  if (!isValid) {
    client.close();
    return res.status(403).json({ message: "Invalid password" });
  }

  // sign JWT
  const token = await sign({ id: user._id }, `${process.env.JWT_SECRET}`);

  // set header
  res.setHeader("Set-Cookie", `token=${token}; HttpOnly; Path=/`);

  // return user
  res.status(200).json({ token: token, userId: user._id.toString() });
}
