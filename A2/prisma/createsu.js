/*
 * Complete this script so that it is able to add a superuser to the database
 * Usage example:
 *   node prisma/createsu.js clive123 clive.su@mail.utoronto.ca SuperUser123!
 */
"use strict";

const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const prisma = new PrismaClient();

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 3) {
    process.exit(1);
  }

  const [utorid, email, password] = args;

  if (!/^[a-zA-Z0-9]{7,8}$/.test(utorid)) {
    console.error("Invalid utorid");
    process.exit(1);
  }

  if (!/^[^\s@]+@(mail\.)?utoronto\.ca$/.test(email)) {
    console.error("Invalid email");
    process.exit(1);
  }

  const passwordHash = await bcrypt.hash(password, 10);

  try {
    await prisma.user.create({
      data: {
        utorid,
        email,
        name: "Superuser",
        passwordHash,
        role: "superuser",
        verified: true,
        lastLogin: new Date(),
      },
    });
  } catch {
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();
