import { PrismaAdapter } from "@auth/prisma-adapter";
import { db } from "~/server/db";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcrypt";
import type { NextAuthOptions } from "next-auth";

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(db),
  providers: [
    CredentialsProvider({
      name: "Sign in with Email",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (
          !credentials ||
          typeof credentials.email !== "string" ||
          typeof credentials.password !== "string"
        ) {
          return null;
        }

        // find user by email
        const user = await db.user.findUnique({
          where: { email: credentials.email },
        });

        // no user with that email
        if (!user || !user.password) {
          return null;
        }

        // check if password is correct
        const isValid = await bcrypt.compare(
          String(credentials.password),
          user.password,
        );

        if (!isValid) {
          return null;
        }

        return user; // return full user (NextAuth strips sensitive fields)
      },
    }),
  ],
  session: {
    strategy: "database",
  },
  secret: process.env.AUTH_SECRET,
  pages: {
    signIn: "/auth/login",
    newUser: "/auth/signup",
  },
};
