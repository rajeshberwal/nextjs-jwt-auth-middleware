import { jwtVerify, type JWTPayload } from "jose";
import { NextResponse, NextRequest } from "next/server";

export async function middleware(req: NextRequest) {
  // for public routes, we don't need to check for a token
  const pathname = req.nextUrl.pathname;
  if (
    pathname.startsWith("/_next") || // exclude Next.js internals
    pathname.startsWith("/static") || // exclude static files
    pathname.startsWith("/api") // exclude API routes
  )
    return NextResponse.next();

  // check if cookie is present
  const auth = req.headers.get("Cookie");

  if (!auth) {
    return NextResponse.rewrite(new URL("/auth/login", req.url));
  }

  // get token from cookie
  const token = auth.split("=")[1];

  // if no token found, redirect to login page
  if (!token || token === "") {
    return NextResponse.rewrite(new URL("/auth/login", req.url));
  }

  // verify token
  let decodedToken;
  try {
    decodedToken = await jwtVerify(
      token,
      new TextEncoder().encode(`${process.env.JWT_SECRET}`)
    );
  } catch (err) {
    return NextResponse.rewrite(new URL("/auth/login", req.url));
  }

  // if token is not valid, redirect to login page
  if (!decodedToken) {
    console.log("Token is null or undefined");
    return NextResponse.rewrite(new URL("/auth/login", req.url));
  }

  return NextResponse.next();
}
