#!/usr/bin/env node
"use strict";

const port = (() => {
  const args = process.argv;

  if (args.length !== 3) {
    console.error("usage: node index.js port");
    process.exit(1);
  }

  const num = parseInt(args[2], 10);
  if (isNaN(num)) {
    console.error("error: argument must be an integer.");
    process.exit(1);
  }

  return num;
})();

require("dotenv").config();
const express = require("express");
const { expressjwt: jwt } = require("express-jwt");
const jwtLib = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();
const app = express();

app.use(express.json());

const jwtMiddleware = jwt({
  secret: process.env.JWT_SECRET,
  algorithms: ["HS256"],
  credentialsRequired: false,
});

app.use(jwtMiddleware);

const roleCheckMiddleware = (minimumRole) => {
  const roleLevels = { regular: 1, cashier: 2, manager: 3, superuser: 4 };

  return async (req, res, next) => {
    if (!req.auth || !req.auth.userId) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    try {
      const user = await prisma.user.findUnique({
        where: { id: req.auth.userId },
        select: { role: true },
      });

      if (!user) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const userLevel = roleLevels[user.role] || 0;
      const requiredLevel = roleLevels[minimumRole] || 0;

      if (userLevel < requiredLevel) {
        return res.status(403).json({ error: "Forbidden" });
      }

      req.user = user;
      next();
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  };
};

const validateUtorid = (utorid) => {
  return typeof utorid === "string" && /^[a-zA-Z0-9]{7,8}$/.test(utorid);
};

const validateName = (name) => {
  return typeof name === "string" && name.length >= 1 && name.length <= 50;
};

const validateEmail = (email) => {
  return (
    typeof email === "string" && /^[^\s@]+@(mail\.)?utoronto\.ca$/.test(email)
  );
};

const validatePassword = (password) => {
  if (
    typeof password !== "string" ||
    password.length < 8 ||
    password.length > 20
  ) {
    return false;
  }
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  return hasUppercase && hasLowercase && hasNumber && hasSpecial;
};

const resetRateLimiter = new Map();

app.post("/auth/tokens", async (req, res) => {
  try {
    const { utorid, password, ...extraFields } = req.body;

    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!utorid || !password) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const user = await prisma.user.findUnique({
      where: { utorid },
    });

    if (!user || !user.passwordHash) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() },
    });

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    const token = jwtLib.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      token,
      expiresAt: expiresAt.toISOString(),
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/auth/resets", async (req, res) => {
  try {
    const { utorid, ...extraFields } = req.body;

    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!utorid) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const user = await prisma.user.findUnique({
      where: { utorid },
    });

    if (!user) {
      return res.status(404).json({ error: "Not Found" });
    }

    const lastRequest = resetRateLimiter.get(utorid);
    const now = Date.now();

    if (lastRequest && now - lastRequest < 60000) {
      return res.status(429).json({ error: "Too Many Requests" });
    }

    resetRateLimiter.set(utorid, now);
    for (const [id, timestamp] of resetRateLimiter.entries()) {
      if (now - timestamp > 60000) {
        resetRateLimiter.delete(id);
      }
    }

    const resetToken = uuidv4();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1);

    if (user) {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          resetToken,
          expiresAt,
        },
      });
    }

    res.status(202).json({
      expiresAt: expiresAt.toISOString(),
      resetToken,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/auth/resets/:resetToken", async (req, res) => {
  try {
    const { resetToken } = req.params;
    const { utorid, password, ...extraFields } = req.body;

    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!utorid || !password) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const user = await prisma.user.findUnique({
      where: { resetToken },
    });

    if (!user) {
      return res.status(404).json({ error: "Not Found" });
    }

    if (user.utorid !== utorid) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!user.expiresAt || new Date() > user.expiresAt) {
      return res.status(410).json({ error: "Gone" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash,
        resetToken: null,
        expiresAt: null,
        lastLogin: new Date(),
      },
    });

    res.status(200).json({ message: "OK" });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/users", roleCheckMiddleware("cashier"), async (req, res) => {
  try {
    const { utorid, name, email, ...extraFields } = req.body;

    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!utorid || !name || !email) {
      return res.status(400).json({ error: "Bad Request" });
    }
    if (
      !validateUtorid(utorid) ||
      !validateName(name) ||
      !validateEmail(email)
    ) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const existingUser = await prisma.user.findUnique({
      where: { utorid },
    });

    if (existingUser) {
      return res.status(409).json({ error: "Conflict" });
    }
    const existingEmail = await prisma.user.findUnique({
      where: { email },
    });

    if (existingEmail) {
      return res.status(409).json({ error: "Conflict" });
    }

    const resetToken = uuidv4();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    const user = await prisma.user.create({
      data: {
        utorid,
        name,
        email,
        resetToken,
        expiresAt,
        verified: false,
      },
    });

    res.status(201).json({
      id: user.id,
      utorid: user.utorid,
      name: user.name,
      email: user.email,
      verified: user.verified,
      expiresAt: user.expiresAt.toISOString(),
      resetToken: user.resetToken,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/users", roleCheckMiddleware("manager"), async (req, res) => {
  try {
    const {
      name,
      role,
      verified,
      activated,
      page = "1",
      limit = "10",
    } = req.query;

    const pageNumber = parseInt(page, 10);
    const limitNumber = parseInt(limit, 10);

    if (
      isNaN(pageNumber) ||
      pageNumber < 1 ||
      isNaN(limitNumber) ||
      limitNumber < 1
    ) {
      return res.status(400).json({ error: "Bad Request" });
    }
    const filters = {};

    if (name) {
      filters.OR = [
        { utorid: { contains: name } },
        { name: { contains: name } },
      ];
    }

    if (role) {
      filters.role = role;
    }

    if (verified !== undefined) {
      filters.verified = verified === "true";
    }

    if (activated === "true") {
      filters.lastLogin = { not: null };
    } else if (activated === "false") {
      filters.lastLogin = null;
    }

    const count = await prisma.user.count({ where: filters });

    const skip = (pageNumber - 1) * limitNumber;
    const results = await prisma.user.findMany({
      where: filters,
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        birthday: true,
        role: true,
        points: true,
        createdAt: true,
        lastLogin: true,
        verified: true,
        avatarUrl: true,
      },
      skip,
      take: limitNumber,
    });

    res.status(200).json({
      count,
      results,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/users/:userId", roleCheckMiddleware("cashier"), async (req, res) => {
  try {
    const userId = parseInt(req.params.userId, 10);

    if (isNaN(userId)) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const userSelect = {
      id: true,
      utorid: true,
      name: true,
      points: true,
      verified: true,
    };

    if (req.user.role === "manager" || req.user.role === "superuser") {
      userSelect.email = true;
      userSelect.birthday = true;
      userSelect.role = true;
      userSelect.createdAt = true;
      userSelect.lastLogin = true;
      userSelect.avatarUrl = true;
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: userSelect,
    });

    if (!user) {
      return res.status(404).json({ error: "Not Found" });
    }

    const now = new Date();

    const usedPromotions = await prisma.userPromotion.findMany({
      where: { userId },
      select: { promotionId: true },
    });

    const usedPromotionIds = usedPromotions.map(
      (usedPromotion) => usedPromotion.promotionId
    );

    const promotions = await prisma.promotion.findMany({
      where: {
        type: "onetime",
        startTime: { lte: now },
        endTime: { gte: now },
        id: { notIn: usedPromotionIds },
      },
      select: {
        id: true,
        name: true,
        minSpending: true,
        rate: true,
        points: true,
      },
    });

    res.status(200).json({
      ...user,
      promotions,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.patch(
  "/users/:userId",
  roleCheckMiddleware("manager"),
  async (req, res) => {
    try {
      const userId = parseInt(req.params.userId, 10);

      if (isNaN(userId)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const { email, verified, suspicious, role, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (
        email === undefined &&
        verified === undefined &&
        suspicious === undefined &&
        role === undefined
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (email !== undefined && email !== null && !validateEmail(email)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (
        verified !== undefined &&
        verified !== null &&
        (typeof verified !== "boolean" || verified !== true)
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (
        suspicious !== undefined &&
        suspicious !== null &&
        typeof suspicious !== "boolean"
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (
        role !== undefined &&
        role !== null &&
        role !== "regular" &&
        role !== "cashier" &&
        role !== "manager" &&
        role !== "superuser"
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (req.user.role === "manager" && role !== undefined && role !== null) {
        if (role !== "regular" && role !== "cashier") {
          return res.status(403).json({ error: "Forbidden" });
        }
      }

      const existingUser = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, utorid: true, name: true, suspicious: true },
      });

      if (!existingUser) {
        return res.status(404).json({ error: "Not Found" });
      }
      if (role === "cashier") {
        const isSus =
          suspicious !== undefined && suspicious !== null
            ? suspicious
            : existingUser.suspicious;
        if (isSus) {
          return res.status(400).json({ error: "Bad Request" });
        }
      }

      const response = {
        id: existingUser.id,
        utorid: existingUser.utorid,
        name: existingUser.name,
      };

      const updateData = {};
      if (email !== undefined && email !== null) {
        updateData.email = email;
        response.email = email;
      }
      if (verified !== undefined && verified !== null) {
        updateData.verified = verified;
        response.verified = verified;
      }
      if (suspicious !== undefined && suspicious !== null) {
        updateData.suspicious = suspicious;
        response.suspicious = suspicious;
      }
      if (role !== undefined && role !== null) {
        updateData.role = role;
        response.role = role;
      }

      await prisma.user.update({
        where: { id: userId },
        data: updateData,
      });
      res.status(200).json(response);
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

server.on("error", (err) => {
  console.error(`cannot start server: ${err.message}`);
  process.exit(1);
});
