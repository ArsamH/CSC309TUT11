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
const multer = require("multer");

const prisma = new PrismaClient();
const app = express();

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    const uniqueName = Date.now() + "-" + file.originalname;
    cb(null, uniqueName);
  },
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Only image files are allowed!"), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
});

app.use(express.json());
app.use("/uploads", express.static("uploads"));

const jwtMiddleware = jwt({
  secret: process.env.JWT_SECRET,
  algorithms: ["HS256"],
  credentialsRequired: false,
});

app.use(jwtMiddleware);

app.use((err, req, res, next) => {
  if (err.name === "UnauthorizedError") {
    req.auth = null;
    return next();
  }
  next();
});

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

const validateBirthday = (birthday) => {
  if (typeof birthday !== "string") {
    return false;
  }
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRegex.test(birthday)) {
    return false;
  }
  const date = new Date(birthday);
  return date instanceof Date && !isNaN(date);
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
        activated: true,
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
      filters.lastLogin = { equals: null };
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

app.get("/users/me", roleCheckMiddleware("regular"), async (req, res) => {
  try {
    const userId = req.auth.userId;

    const user = await prisma.user.findUnique({
      where: { id: userId },
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
      birthday: user.birthday
        ? user.birthday.toISOString().split("T")[0]
        : null,
      promotions,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.patch(
  "/users/me",
  roleCheckMiddleware("regular"),
  upload.single("avatar"),
  async (req, res) => {
    try {
      const userId = req.auth.userId;
      const { name, email, birthday, avatar, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (
        name === undefined &&
        email === undefined &&
        birthday === undefined &&
        !req.file
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (name !== undefined && !validateName(name)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (email !== undefined && !validateEmail(email)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (birthday !== undefined && !validateBirthday(birthday)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const updateData = {};
      if (name !== undefined) {
        updateData.name = name;
      }
      if (email !== undefined) {
        updateData.email = email;
      }
      if (birthday !== undefined) {
        updateData.birthday = new Date(birthday);
      }
      if (req.file) {
        updateData.avatarUrl = `/uploads/${req.file.filename}`;
      }

      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: updateData,
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
      });

      res.status(200).json({
        ...updatedUser,
        birthday: updatedUser.birthday
          ? updatedUser.birthday.toISOString().split("T")[0]
          : null,
      });
    } catch (error) {
      if (error instanceof multer.MulterError) {
        return res.status(400).json({ error: "Bad Request" });
      }

      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.patch(
  "/users/me/password",
  roleCheckMiddleware("regular"),
  async (req, res) => {
    try {
      const userId = req.auth.userId;
      const { old, new: newPassword, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (!old || !newPassword) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (!validatePassword(newPassword)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { passwordHash: true },
      });
      if (!user || !user.passwordHash) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const passwordMatch = await bcrypt.compare(old, user.passwordHash);
      if (!passwordMatch) {
        return res.status(403).json({ error: "Forbidden" });
      }

      const newPasswordHash = await bcrypt.hash(newPassword, 10);
      await prisma.user.update({
        where: { id: userId },
        data: { passwordHash: newPasswordHash },
      });

      res.status(200).json({ message: "OK" });
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post(
  "/users/me/transactions",
  roleCheckMiddleware("regular"),
  async (req, res) => {
    try {
      const { type, amount, remark, ...extraFields } = req.body;
      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (type !== "redemption") {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (amount === undefined || !Number.isInteger(amount) || amount <= 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const user = await prisma.user.findUnique({
        where: { id: req.auth.userId },
        select: {
          id: true,
          utorid: true,
          points: true,
          verified: true,
        },
      });

      if (!user) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      if (!user.verified) {
        return res.status(403).json({ error: "Forbidden" });
      }

      if (user.points < amount) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const transaction = await prisma.transaction.create({
        data: {
          type: "redemption",
          amount: amount,
          redeemed: null,
          remark: remark || "",
          suspicious: false,
          userId: user.id,
          createdById: user.id,
        },
      });

      res.status(201).json({
        id: transaction.id,
        utorid: user.utorid,
        type: "redemption",
        processedBy: null,
        amount: transaction.amount,
        remark: transaction.remark,
        createdBy: user.utorid,
      });
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);
app.get(
  "/users/me/transactions",
  roleCheckMiddleware("regular"),
  async (req, res) => {
    try {
      const {
        type,
        relatedId,
        promotionId,
        amount,
        operator,
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
      if (relatedId !== undefined && type === undefined) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (
        (amount !== undefined && operator === undefined) ||
        (amount === undefined && operator !== undefined)
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (operator !== undefined && operator !== "gte" && operator !== "lte") {
        return res.status(400).json({ error: "Bad Request" });
      }

      const filters = {
        userId: req.auth.userId,
      };

      if (type) {
        filters.type = type;
      }

      if (relatedId !== undefined) {
        const relatedIdNum = parseInt(relatedId, 10);
        if (isNaN(relatedIdNum)) {
          return res.status(400).json({ error: "Bad Request" });
        }
        filters.relatedId = relatedIdNum;
      }
      if (amount !== undefined) {
        const amountNum = parseInt(amount, 10);
        if (isNaN(amountNum)) {
          return res.status(400).json({ error: "Bad Request" });
        }
        if (operator === "gte") {
          filters.amount = { gte: amountNum };
        } else if (operator === "lte") {
          filters.amount = { lte: amountNum };
        }
      }

      let possibleTransactionIds = null;
      if (promotionId !== undefined) {
        const promotionIdNum = parseInt(promotionId, 10);
        if (isNaN(promotionIdNum)) {
          return res.status(400).json({ error: "Bad Request" });
        }

        const transactionPromotions =
          await prisma.transactionPromotion.findMany({
            where: { promotionId: promotionIdNum },
            select: { transactionId: true },
          });

        possibleTransactionIds = transactionPromotions.map(
          (tp) => tp.transactionId
        );

        if (possibleTransactionIds.length === 0) {
          return res.status(200).json({ count: 0, results: [] });
        }

        filters.id = { in: possibleTransactionIds };
      }

      const count = await prisma.transaction.count({ where: filters });

      const skip = (pageNumber - 1) * limitNumber;
      const transactions = await prisma.transaction.findMany({
        where: filters,
        include: {
          createdBy: {
            select: { utorid: true },
          },
          promotions: {
            select: { promotionId: true },
          },
        },
        skip,
        take: limitNumber,
      });

      const results = transactions.map((t) => {
        const result = {
          id: t.id,
          type: t.type,
          amount: t.amount,
          promotionIds: t.promotions.map((p) => p.promotionId),
          remark: t.remark || "",
          createdBy: t.createdBy.utorid,
        };

        if (t.spent !== null) {
          result.spent = t.spent;
        }
        if (t.relatedId !== null) {
          result.relatedId = t.relatedId;
        }

        return result;
      });

      res.status(200).json({
        count,
        results,
      });
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

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

app.post(
  "/users/:userId/transactions",
  roleCheckMiddleware("regular"),
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { type, amount, remark, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (type !== "transfer") {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (amount === undefined || !Number.isInteger(amount) || amount <= 0) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const recipientId = parseInt(userId, 10);
      if (isNaN(recipientId)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const sender = await prisma.user.findUnique({
        where: { id: req.auth.userId },
        select: {
          id: true,
          utorid: true,
          points: true,
          verified: true,
        },
      });

      if (!sender) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      if (!sender.verified) {
        return res.status(403).json({ error: "Forbidden" });
      }

      const recipient = await prisma.user.findUnique({
        where: { id: recipientId },
        select: {
          id: true,
          utorid: true,
          points: true,
        },
      });

      if (!recipient) {
        return res.status(404).json({ error: "Not Found" });
      }

      if (sender.id === recipient.id) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (sender.points < amount) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const senderTransaction = await prisma.transaction.create({
        data: {
          type: "transfer",
          amount: -amount,
          relatedId: recipient.id,
          remark: remark || "",
          suspicious: false,
          userId: sender.id,
          createdById: sender.id,
        },
      });
      await prisma.transaction.create({
        data: {
          type: "transfer",
          amount: amount,
          relatedId: sender.id,
          remark: remark || "",
          suspicious: false,
          userId: recipient.id,
          createdById: sender.id,
        },
      });

      await prisma.user.update({
        where: { id: sender.id },
        data: { points: { increment: -amount } },
      });
      await prisma.user.update({
        where: { id: recipient.id },
        data: { points: { increment: amount } },
      });

      res.status(201).json({
        id: senderTransaction.id,
        sender: sender.utorid,
        recipient: recipient.utorid,
        type: "transfer",
        sent: amount,
        remark: senderTransaction.remark,
        createdBy: sender.utorid,
      });
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post("/transactions", roleCheckMiddleware("cashier"), async (req, res) => {
  try {
    const {
      utorid,
      type,
      spent,
      amount,
      relatedId,
      promotionIds,
      remark,
      ...extraFields
    } = req.body;

    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (!utorid || !type) {
      return res.status(400).json({ error: "Bad Request" });
    }
    const customer = await prisma.user.findUnique({
      where: { utorid },
    });

    if (!customer) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const currentUser = await prisma.user.findUnique({
      where: { id: req.auth.userId },
      select: { utorid: true, role: true, suspicious: true },
    });

    if (!currentUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    if (type === "purchase") {
      if (
        currentUser.role !== "cashier" &&
        currentUser.role !== "manager" &&
        currentUser.role !== "superuser"
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }

      if (
        spent === undefined ||
        spent === null ||
        typeof spent !== "number" ||
        spent <= 0
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      let promotions = [];
      if (promotionIds) {
        const now = new Date();
        promotions = await prisma.promotion.findMany({
          where: {
            id: { in: promotionIds },
            startTime: { lte: now },
            endTime: { gte: now },
          },
        });

        if (promotions.length !== promotionIds.length) {
          return res.status(400).json({ error: "Bad Request" });
        }

        for (const promotion of promotions) {
          if (promotion.minSpending && spent < promotion.minSpending) {
            return res.status(400).json({ error: "Bad Request" });
          }
          if (promotion.type === "onetime") {
            const alreadyUsed = await prisma.userPromotion.findUnique({
              where: {
                userId_promotionId: {
                  userId: customer.id,
                  promotionId: promotion.id,
                },
              },
            });

            if (alreadyUsed) {
              return res.status(400).json({ error: "Bad Request" });
            }
          }
        }
      }
      let earned = Math.round(spent / 0.25);
      for (const promotion of promotions) {
        if (promotion.rate) {
          earned += Math.round((spent / 0.25) * promotion.rate);
        }
        if (promotion.points) {
          earned += promotion.points;
        }
      }
      const transaction = await prisma.transaction.create({
        data: {
          type: "purchase",
          amount: earned,
          spent: spent,
          remark: remark || "",
          suspicious: currentUser.suspicious,
          userId: customer.id,
          createdById: req.auth.userId,
        },
      });
      if (promotionIds && promotionIds.length > 0) {
        for (const promotionId of promotionIds) {
          await prisma.transactionPromotion.create({
            data: {
              transactionId: transaction.id,
              promotionId: promotionId,
            },
          });
          const promo = promotions.find((p) => p.id === promotionId);
          if (promo && promo.type === "onetime") {
            await prisma.userPromotion.create({
              data: {
                userId: customer.id,
                promotionId: promotionId,
              },
            });
          }
        }
      }
      if (!currentUser.suspicious) {
        await prisma.user.update({
          where: { id: customer.id },
          data: { points: { increment: earned } },
        });
      }

      return res.status(201).json({
        id: transaction.id,
        utorid: utorid,
        type: "purchase",
        spent: spent,
        earned: currentUser.suspicious ? 0 : earned,
        remark: transaction.remark,
        promotionIds: promotionIds || [],
        createdBy: currentUser.utorid,
      });
    }

    if (type === "adjustment") {
      if (currentUser.role !== "manager" && currentUser.role !== "superuser") {
        return res.status(403).json({ error: "Forbidden" });
      }
      if (amount === undefined || amount === null) {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (typeof amount !== "number") {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (relatedId === undefined || relatedId === null) {
        return res.status(404).json({ error: "Not Found" });
      }

      if (typeof relatedId !== "number") {
        return res.status(400).json({ error: "Bad Request" });
      }
      const relatedTransaction = await prisma.transaction.findUnique({
        where: { id: relatedId },
      });

      if (!relatedTransaction) {
        return res.status(404).json({ error: "Not Found" });
      }

      const transaction = await prisma.transaction.create({
        data: {
          type: "adjustment",
          amount: amount,
          relatedId: relatedId,
          remark: remark || "",
          suspicious: false,
          userId: customer.id,
          createdById: req.auth.userId,
        },
      });
      await prisma.user.update({
        where: { id: customer.id },
        data: { points: { increment: amount } },
      });

      return res.status(201).json({
        id: transaction.id,
        utorid: utorid,
        amount: amount,
        type: "adjustment",
        relatedId: relatedId,
        remark: transaction.remark,
        promotionIds: promotionIds || [],
        createdBy: currentUser.utorid,
      });
    }
    return res.status(400).json({ error: "Bad Request" });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/transactions", roleCheckMiddleware("manager"), async (req, res) => {
  try {
    const {
      name,
      createdBy,
      suspicious,
      promotionId,
      type,
      relatedId,
      amount,
      operator,
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
    if (relatedId !== undefined && type === undefined) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (
      (amount !== undefined && operator === undefined) ||
      (amount === undefined && operator !== undefined)
    ) {
      return res.status(400).json({ error: "Bad Request" });
    }
    if (operator !== undefined && operator !== "gte" && operator !== "lte") {
      return res.status(400).json({ error: "Bad Request" });
    }

    const filters = {};

    if (name) {
      filters.user = {
        OR: [{ utorid: name }, { name: name }],
      };
    }

    if (createdBy) {
      filters.createdBy = {
        utorid: createdBy,
      };
    }

    if (suspicious !== undefined) {
      filters.suspicious = suspicious === "true";
    }
    if (type) {
      filters.type = type;
    }

    if (relatedId !== undefined) {
      const relatedIdNum = parseInt(relatedId, 10);
      if (isNaN(relatedIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      filters.relatedId = relatedIdNum;
    }
    if (amount !== undefined) {
      const amountNum = parseInt(amount, 10);
      if (isNaN(amountNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (operator === "gte") {
        filters.amount = { gte: amountNum };
      } else if (operator === "lte") {
        filters.amount = { lte: amountNum };
      }
    }

    let possibleTransactionIds = null;
    if (promotionId !== undefined) {
      const promotionIdNum = parseInt(promotionId, 10);
      if (isNaN(promotionIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const transactionPromotions = await prisma.transactionPromotion.findMany({
        where: { promotionId: promotionIdNum },
        select: { transactionId: true },
      });

      possibleTransactionIds = transactionPromotions.map(
        (tp) => tp.transactionId
      );

      if (possibleTransactionIds.length === 0) {
        return res.status(200).json({ count: 0, results: [] });
      }

      filters.id = { in: possibleTransactionIds };
    }

    const count = await prisma.transaction.count({ where: filters });

    const skip = (pageNumber - 1) * limitNumber;
    const transactions = await prisma.transaction.findMany({
      where: filters,
      include: {
        user: {
          select: { utorid: true },
        },
        createdBy: {
          select: { utorid: true },
        },
        promotions: {
          select: { promotionId: true },
        },
      },
      skip,
      take: limitNumber,
    });
    const results = transactions.map((t) => {
      const result = {
        id: t.id,
        utorid: t.user.utorid,
        amount: t.amount,
        type: t.type,
        promotionIds: t.promotions.map((p) => p.promotionId),
        suspicious: t.suspicious,
        remark: t.remark || "",
        createdBy: t.createdBy.utorid,
      };

      if (t.spent !== null) {
        result.spent = t.spent;
      }
      if (t.relatedId !== null) {
        result.relatedId = t.relatedId;
      }
      if (t.redeemed !== null) {
        result.redeemed = t.redeemed;
      }

      return result;
    });

    res.status(200).json({
      count,
      results,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get(
  "/transactions/:transactionId",
  roleCheckMiddleware("manager"),
  async (req, res) => {
    try {
      const { transactionId } = req.params;
      const transId = parseInt(transactionId, 10);
      if (isNaN(transId)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const transaction = await prisma.transaction.findUnique({
        where: { id: transId },
        include: {
          user: {
            select: { utorid: true },
          },
          createdBy: {
            select: { utorid: true },
          },
          promotions: {
            select: { promotionId: true },
          },
        },
      });

      if (!transaction) {
        return res.status(404).json({ error: "Not Found" });
      }
      const result = {
        id: transaction.id,
        utorid: transaction.user.utorid,
        type: transaction.type,
        amount: transaction.amount,
        promotionIds: transaction.promotions.map((p) => p.promotionId),
        suspicious: transaction.suspicious,
        remark: transaction.remark || "",
        createdBy: transaction.createdBy.utorid,
      };
      if (transaction.spent !== null) {
        result.spent = transaction.spent;
      }
      if (transaction.relatedId !== null) {
        result.relatedId = transaction.relatedId;
      }
      res.status(200).json(result);
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.patch(
  "/transactions/:transactionId/suspicious",
  roleCheckMiddleware("manager"),
  async (req, res) => {
    try {
      const { transactionId } = req.params;
      const { suspicious, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const transId = parseInt(transactionId, 10);
      if (isNaN(transId)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (typeof suspicious !== "boolean" || suspicious === undefined) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const transaction = await prisma.transaction.findUnique({
        where: { id: transId },
        include: {
          user: {
            select: { utorid: true, points: true },
          },
          createdBy: {
            select: { utorid: true },
          },
          promotions: {
            select: { promotionId: true },
          },
        },
      });

      if (!transaction) {
        return res.status(404).json({ error: "Not Found" });
      }
      if (transaction.suspicious !== suspicious) {
        let pointsAdded = 0;

        if (suspicious) {
          pointsAdded -= transaction.amount;
        } else {
          pointsAdded += transaction.amount;
        }

        await prisma.transaction.update({
          where: { id: transId },
          data: { suspicious },
        });

        await prisma.user.update({
          where: { id: transaction.userId },
          data: {
            points: {
              increment: pointsAdded,
            },
          },
        });
      }
      const updatedTransaction = await prisma.transaction.findUnique({
        where: { id: transId },
        include: {
          user: {
            select: { utorid: true },
          },
          createdBy: {
            select: { utorid: true },
          },
          promotions: {
            select: { promotionId: true },
          },
        },
      });

      const result = {
        id: updatedTransaction.id,
        utorid: updatedTransaction.user.utorid,
        type: updatedTransaction.type,
        amount: updatedTransaction.amount,
        promotionIds: updatedTransaction.promotions.map((p) => p.promotionId),
        suspicious: updatedTransaction.suspicious,
        remark: updatedTransaction.remark || "",
        createdBy: updatedTransaction.createdBy.utorid,
      };
      if (updatedTransaction.spent !== null) {
        result.spent = updatedTransaction.spent;
      }

      res.status(200).json(result);
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.patch(
  "/transactions/:transactionId/processed",
  roleCheckMiddleware("cashier"),
  async (req, res) => {
    try {
      const { transactionId } = req.params;
      const { processed, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const transId = parseInt(transactionId, 10);
      if (isNaN(transId)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (processed !== true) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const transaction = await prisma.transaction.findUnique({
        where: { id: transId },
        include: {
          user: {
            select: { id: true, utorid: true, points: true },
          },
          createdBy: {
            select: { utorid: true },
          },
        },
      });

      if (!transaction) {
        return res.status(404).json({ error: "Not Found" });
      }

      if (transaction.type !== "redemption" || transaction.redeemed !== null) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const userPoints = await prisma.user.findUnique({
        where: { id: transaction.user.id },
        select: { points: true },
      });

      if (!userPoints || userPoints.points < transaction.amount) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const redeemer = await prisma.user.findUnique({
        where: { id: req.auth.userId },
        select: { utorid: true },
      });

      if (!redeemer) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      await prisma.transaction.update({
        where: { id: transId },
        data: { redeemed: transaction.amount, relatedId: req.auth.userId },
      });
      await prisma.user.update({
        where: { id: transaction.user.id },
        data: {
          points: {
            increment: -transaction.amount,
          },
        },
      });

      res.status(200).json({
        id: transaction.id,
        utorid: transaction.user.utorid,
        type: "redemption",
        processedBy: redeemer.utorid,
        redeemed: transaction.amount,
        remark: transaction.remark || "",
        createdBy: transaction.createdBy.utorid,
      });
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.get("/events", roleCheckMiddleware("regular"), async (req, res) => {
  try {
    const {
      name,
      location,
      started,
      ended,
      showFull,
      published,
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

    if (started !== undefined && ended !== undefined) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const currentUser = await prisma.user.findUnique({
      where: { id: req.auth.userId },
      select: { role: true },
    });

    if (!currentUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const filters = {};
    const now = new Date();
    if (!(currentUser.role === "manager" || currentUser.role === "superuser")) {
      filters.published = true;
    } else {
      if (published !== undefined) {
        filters.published = published === "true";
      }
    }
    if (name) {
      filters.name = name;
    }
    if (location) {
      filters.location = location;
    }

    if (started !== undefined) {
      if (started === "true") {
        filters.startTime = { lte: now };
      } else {
        filters.startTime = { gt: now };
      }
    }
    if (ended !== undefined) {
      if (ended === "true") {
        filters.endTime = { lte: now };
      } else {
        filters.endTime = { gt: now };
      }
    }
    const events = await prisma.event.findMany({
      where: filters,
      include: {
        guests: true,
      },
    });
    const shouldShowFull = showFull === "true";
    let filteredEvents = events;

    if (!shouldShowFull) {
      filteredEvents = events.filter((event) => {
        if (event.capacity === null) {
          return true;
        }
        return event.guests.length < event.capacity;
      });
    }

    const count = filteredEvents.length;
    const skip = (pageNumber - 1) * limitNumber;
    const paginatedEvents = filteredEvents.slice(skip, skip + limitNumber);
    const results = paginatedEvents.map((event) => {
      const result = {
        id: event.id,
        name: event.name,
        location: event.location,
        startTime: event.startTime.toISOString(),
        endTime: event.endTime.toISOString(),
        capacity: event.capacity,
        numGuests: event.guests.length,
      };
      if (currentUser.role === "manager" || currentUser.role === "superuser") {
        result.pointsRemain = event.points - event.pointsAwarded;
        result.pointsAwarded = event.pointsAwarded;
        result.published = event.published;
      }

      return result;
    });

    res.status(200).json({
      count,
      results,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get(
  "/events/:eventId",
  roleCheckMiddleware("regular"),
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const eventIdNum = parseInt(eventId, 10);

      if (isNaN(eventIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const event = await prisma.event.findUnique({
        where: { id: eventIdNum },
        include: {
          organizers: {
            include: {
              user: {
                select: {
                  id: true,
                  utorid: true,
                  name: true,
                },
              },
            },
          },
          guests: {
            include: {
              user: {
                select: {
                  id: true,
                  utorid: true,
                  name: true,
                },
              },
            },
          },
        },
      });

      if (!event) {
        return res.status(404).json({ error: "Not Found" });
      }

      const currentUser = await prisma.user.findUnique({
        where: { id: req.auth.userId },
        select: { id: true, role: true },
      });

      if (!currentUser) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      const isOrganizer = event.organizers.some(
        (organizer) => organizer.userId === currentUser.id
      );
      if (
        !(currentUser.role === "manager" || currentUser.role === "superuser") &&
        !isOrganizer &&
        !event.published
      ) {
        return res.status(404).json({ error: "Not Found" });
      }
      const organizers = event.organizers.map((organizer) => ({
        id: organizer.user.id,
        utorid: organizer.user.utorid,
        name: organizer.user.name,
      }));
      if (
        currentUser.role === "manager" ||
        currentUser.role === "superuser" ||
        isOrganizer
      ) {
        const guests = event.guests.map((guest) => ({
          id: guest.user.id,
          utorid: guest.user.utorid,
          name: guest.user.name,
          points: guest.points,
        }));

        res.status(200).json({
          id: event.id,
          name: event.name,
          description: event.description,
          location: event.location,
          startTime: event.startTime.toISOString(),
          endTime: event.endTime.toISOString(),
          capacity: event.capacity,
          pointsRemain: event.points - event.pointsAwarded,
          pointsAwarded: event.pointsAwarded,
          published: event.published,
          organizers,
          guests,
        });
      } else {
        res.status(200).json({
          id: event.id,
          name: event.name,
          description: event.description,
          location: event.location,
          startTime: event.startTime.toISOString(),
          endTime: event.endTime.toISOString(),
          capacity: event.capacity,
          organizers,
          numGuests: event.guests.length,
        });
      }
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.patch(
  "/events/:eventId",
  roleCheckMiddleware("regular"),
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const {
        name,
        description,
        location,
        startTime,
        endTime,
        capacity,
        points,
        published,
        ...extraFields
      } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const eventIdNum = parseInt(eventId, 10);
      if (isNaN(eventIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (
        name === undefined &&
        description === undefined &&
        location === undefined &&
        startTime === undefined &&
        endTime === undefined &&
        capacity === undefined &&
        points === undefined &&
        published === undefined
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const event = await prisma.event.findUnique({
        where: { id: eventIdNum },
        include: {
          organizers: true,
          guests: true,
        },
      });

      if (!event) {
        return res.status(404).json({ error: "Not Found" });
      }

      const currentUser = await prisma.user.findUnique({
        where: { id: req.auth.userId },
        select: { id: true, role: true },
      });

      if (!currentUser) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      const isOrganizer = event.organizers.some(
        (organizer) => organizer.userId === currentUser.id
      );

      if (
        !(currentUser.role === "manager" || currentUser.role === "superuser") &&
        !isOrganizer
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }

      if (
        (points !== undefined || published !== undefined) &&
        !(currentUser.role === "manager" || currentUser.role === "superuser")
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }

      const now = new Date();
      const updateData = {};
      const response = {
        id: event.id,
        name: event.name,
        location: event.location,
      };

      if (name !== undefined) {
        if (event.startTime < now) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.name = name;
        response.name = name;
      }
      if (description !== undefined) {
        updateData.description = description;
        response.description = description;
      }
      if (location !== undefined) {
        if (event.startTime < now) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.location = location;
        response.location = location;
      }
      if (startTime !== undefined) {
        const newStartTime = new Date(startTime);
        if (
          isNaN(newStartTime.getTime()) ||
          newStartTime < now ||
          event.startTime < now
        ) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.startTime = newStartTime;
        response.startTime = newStartTime.toISOString();
      }

      if (endTime !== undefined) {
        const newEndTime = new Date(endTime);
        if (
          isNaN(newEndTime.getTime()) ||
          newEndTime < now ||
          event.endTime < now
        ) {
          return res.status(400).json({ error: "Bad Request" });
        }
        const actualStartTime = updateData.startTime || event.startTime;
        if (newEndTime <= actualStartTime) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.endTime = newEndTime;
        response.endTime = newEndTime.toISOString();
      }
      if (capacity !== undefined) {
        if (event.startTime < now || capacity < event.guests.length) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.capacity = capacity;
        response.capacity = capacity;
      }
      if (
        points !== undefined &&
        (currentUser.role === "manager" || currentUser.role === "superuser")
      ) {
        if (
          !Number.isInteger(points) ||
          points <= 0 ||
          points < event.pointsAwarded
        ) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.points = points;
        response.points = points;
      }
      if (
        published !== undefined &&
        (currentUser.role === "manager" || currentUser.role === "superuser")
      ) {
        if (published !== true) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.published = published;
        response.published = published;
      }

      await prisma.event.update({
        where: { id: eventIdNum },
        data: updateData,
      });

      res.status(200).json(response);
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post("/events", roleCheckMiddleware("manager"), async (req, res) => {
  try {
    const {
      name,
      description,
      location,
      startTime,
      endTime,
      capacity,
      points,
      ...extraFields
    } = req.body;

    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }
    if (
      !name ||
      !description ||
      !location ||
      !startTime ||
      !endTime ||
      points === undefined ||
      points <= 0 ||
      (capacity !== undefined && capacity !== null && capacity <= 0)
    ) {
      return res.status(400).json({ error: "Bad Request" });
    }
    const startDate = new Date(startTime);
    const endDate = new Date(endTime);

    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const now = new Date();
    if (startDate <= now || endDate < now || endDate <= startDate) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const event = await prisma.event.create({
      data: {
        name,
        description,
        location,
        startTime: startDate,
        endTime: endDate,
        capacity: capacity === undefined ? null : capacity,
        points,
        pointsAwarded: 0,
        published: false,
      },
      include: {
        organizers: {
          include: {
            user: {
              select: { utorid: true },
            },
          },
        },
        guests: {
          include: {
            user: {
              select: { utorid: true },
            },
          },
        },
      },
    });

    res.status(201).json({
      id: event.id,
      name: event.name,
      description: event.description,
      location: event.location,
      startTime: event.startTime.toISOString(),
      endTime: event.endTime.toISOString(),
      capacity: event.capacity,
      pointsRemain: event.points - event.pointsAwarded,
      pointsAwarded: event.pointsAwarded,
      published: event.published,
      organizers: event.organizers.map((o) => o.user.utorid),
      guests: event.guests.map((g) => g.user.utorid),
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete(
  "/events/:eventId",
  roleCheckMiddleware("manager"),
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const eventIdNum = parseInt(eventId, 10);

      if (isNaN(eventIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const event = await prisma.event.findUnique({
        where: { id: eventIdNum },
      });

      if (!event) {
        return res.status(404).json({ error: "Not Found" });
      }

      if (event.published) {
        return res.status(400).json({ error: "Bad Request" });
      }

      await prisma.event.delete({
        where: { id: eventIdNum },
      });

      res.status(204).send();
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post(
  "/events/:eventId/organizers",
  roleCheckMiddleware("manager"),
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const { utorid, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (!utorid) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const eventIdNum = parseInt(eventId, 10);
      if (isNaN(eventIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const event = await prisma.event.findUnique({
        where: { id: eventIdNum },
      });

      if (!event) {
        return res.status(404).json({ error: "Not Found" });
      }

      const now = new Date();
      if (event.endTime < now) {
        return res.status(410).json({ error: "Gone" });
      }

      const user = await prisma.user.findUnique({
        where: { utorid },
      });

      if (!user) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const isGuest = await prisma.eventGuest.findUnique({
        where: {
          userId_eventId: {
            userId: user.id,
            eventId: eventIdNum,
          },
        },
      });

      if (isGuest) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const existingOrganizer = await prisma.eventOrganizer.findUnique({
        where: {
          userId_eventId: {
            userId: user.id,
            eventId: eventIdNum,
          },
        },
      });
      if (!existingOrganizer) {
        await prisma.eventOrganizer.create({
          data: {
            userId: user.id,
            eventId: eventIdNum,
          },
        });
      }

      const updatedEvent = await prisma.event.findUnique({
        where: { id: eventIdNum },
        include: {
          organizers: {
            include: {
              user: {
                select: {
                  id: true,
                  utorid: true,
                  name: true,
                },
              },
            },
          },
        },
      });

      const organizers = updatedEvent.organizers.map((organizer) => ({
        id: organizer.user.id,
        utorid: organizer.user.utorid,
        name: organizer.user.name,
      }));

      const response = {
        id: updatedEvent.id,
        name: updatedEvent.name,
        location: updatedEvent.location,
        organizers,
      };

      res.status(201).json(response);
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.delete(
  "/events/:eventId/organizers/:userId",
  roleCheckMiddleware("manager"),
  async (req, res) => {
    try {
      const { eventId, userId } = req.params;
      const eventIdNum = parseInt(eventId, 10);
      const userIdNum = parseInt(userId, 10);

      if (isNaN(eventIdNum) || isNaN(userIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const event = await prisma.event.findUnique({
        where: { id: eventIdNum },
      });

      if (!event) {
        return res.status(404).json({ error: "Not Found" });
      }

      const user = await prisma.user.findUnique({
        where: { id: userIdNum },
      });

      if (!user) {
        return res.status(404).json({ error: "Not Found" });
      }

      const organizer = await prisma.eventOrganizer.findUnique({
        where: {
          userId_eventId: {
            userId: userIdNum,
            eventId: eventIdNum,
          },
        },
      });

      if (organizer) {
        await prisma.eventOrganizer.delete({
          where: {
            userId_eventId: {
              userId: userIdNum,
              eventId: eventIdNum,
            },
          },
        });
      }

      res.status(204).send();
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post(
  "/events/:eventId/guests",
  roleCheckMiddleware("regular"),
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const { utorid, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (!utorid) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const eventIdNum = parseInt(eventId, 10);
      if (isNaN(eventIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const event = await prisma.event.findUnique({
        where: { id: eventIdNum },
        include: {
          organizers: true,
          guests: true,
        },
      });

      if (!event) {
        return res.status(404).json({ error: "Not Found" });
      }

      const currentUser = await prisma.user.findUnique({
        where: { id: req.auth.userId },
        select: { id: true, role: true },
      });

      if (!currentUser) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      const isOrganizer = event.organizers.some(
        (organizer) => organizer.userId === currentUser.id
      );

      if (
        !(currentUser.role === "manager" || currentUser.role === "superuser") &&
        !isOrganizer
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }
      if (
        !(currentUser.role === "manager" || currentUser.role === "superuser") &&
        !event.published
      ) {
        return res.status(404).json({ error: "Not Found" });
      }

      const now = new Date();
      if (event.endTime < now) {
        return res.status(410).json({ error: "Gone" });
      }
      if (event.capacity !== null && event.guests.length >= event.capacity) {
        return res.status(410).json({ error: "Gone" });
      }

      const guestPerson = await prisma.user.findUnique({
        where: { utorid },
      });

      if (!guestPerson) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const isGuestOrganizer = event.organizers.some(
        (organizer) => organizer.userId === guestPerson.id
      );

      if (isGuestOrganizer) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const existingGuest = await prisma.eventGuest.findUnique({
        where: {
          userId_eventId: {
            userId: guestPerson.id,
            eventId: eventIdNum,
          },
        },
      });

      if (!existingGuest) {
        await prisma.eventGuest.create({
          data: {
            userId: guestPerson.id,
            eventId: eventIdNum,
            points: 0,
          },
        });
      }
      const updatedEvent = await prisma.event.findUnique({
        where: { id: eventIdNum },
        include: {
          guests: true,
        },
      });

      const response = {
        id: updatedEvent.id,
        name: updatedEvent.name,
        location: updatedEvent.location,
        guestAdded: {
          id: guestPerson.id,
          utorid: guestPerson.utorid,
          name: guestPerson.name,
        },
        numGuests: updatedEvent.guests.length,
      };

      res.status(201).json(response);
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.delete(
  "/events/:eventId/guests/me",
  roleCheckMiddleware("regular"),
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const eventIdNum = parseInt(eventId, 10);
      if (isNaN(eventIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const event = await prisma.event.findUnique({
        where: { id: eventIdNum },
      });

      if (!event) {
        return res.status(404).json({ error: "Not Found" });
      }

      const now = new Date();
      if (event.endTime < now) {
        return res.status(410).json({ error: "Gone" });
      }
      const guest = await prisma.eventGuest.findUnique({
        where: {
          userId_eventId: {
            userId: req.auth.userId,
            eventId: eventIdNum,
          },
        },
      });

      if (!guest) {
        return res.status(404).json({ error: "Not Found" });
      }

      await prisma.eventGuest.delete({
        where: {
          userId_eventId: {
            userId: req.auth.userId,
            eventId: eventIdNum,
          },
        },
      });

      res.status(204).send();
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post(
  "/events/:eventId/transactions",
  roleCheckMiddleware("regular"),
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const { type, utorid, amount, remark, ...extraFields } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (type !== "event") {
        return res.status(400).json({ error: "Bad Request" });
      }

      if (amount === undefined || isNaN(amount) || amount <= 0) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const eventIdNum = parseInt(eventId, 10);
      if (isNaN(eventIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const event = await prisma.event.findUnique({
        where: { id: eventIdNum },
        include: {
          organizers: true,
          guests: {
            include: {
              user: true,
            },
          },
        },
      });

      if (!event) {
        return res.status(404).json({ error: "Not Found" });
      }
      const currentUser = await prisma.user.findUnique({
        where: { id: req.auth.userId },
        select: { id: true, utorid: true, role: true },
      });

      if (!currentUser) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      const isOrganizer = event.organizers.some(
        (organizer) => organizer.userId === currentUser.id
      );

      if (
        !(currentUser.role === "manager" || currentUser.role === "superuser") &&
        !isOrganizer
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }

      if (utorid !== undefined) {
        const guest = event.guests.find(
          (guest) => guest.user.utorid === utorid
        );

        if (!guest) {
          return res.status(400).json({ error: "Bad Request" });
        }
        const leftoverpoints = event.points - event.pointsAwarded;
        if (leftoverpoints < amount) {
          return res.status(400).json({ error: "Bad Request" });
        }

        const transaction = await prisma.transaction.create({
          data: {
            type: "event",
            amount: amount,
            relatedId: eventIdNum,
            remark: remark || "",
            suspicious: false,
            userId: guest.userId,
            createdById: currentUser.id,
          },
        });

        await prisma.user.update({
          where: { id: guest.userId },
          data: { points: { increment: amount } },
        });

        await prisma.eventGuest.update({
          where: {
            userId_eventId: {
              userId: guest.userId,
              eventId: eventIdNum,
            },
          },
          data: { points: { increment: amount } },
        });

        await prisma.event.update({
          where: { id: eventIdNum },
          data: { pointsAwarded: { increment: amount } },
        });

        const response = {
          id: transaction.id,
          recipient: guest.user.utorid,
          awarded: amount,
          type: "event",
          relatedId: eventIdNum,
          remark: transaction.remark,
          createdBy: currentUser.utorid,
        };

        res.status(201).json(response);
      } else {
        if (event.guests.length === 0) {
          return res.status(400).json({ error: "Bad Request" });
        }

        const finalAmount = amount * event.guests.length;
        const leftoverpoints = event.points - event.pointsAwarded;
        if (leftoverpoints < finalAmount) {
          return res.status(400).json({ error: "Bad Request" });
        }

        const transactions = [];

        for (const guest of event.guests) {
          const transaction = await prisma.transaction.create({
            data: {
              type: "event",
              amount: amount,
              relatedId: eventIdNum,
              remark: remark || "",
              suspicious: false,
              userId: guest.userId,
              createdById: currentUser.id,
            },
          });

          await prisma.user.update({
            where: { id: guest.userId },
            data: { points: { increment: amount } },
          });

          await prisma.eventGuest.update({
            where: {
              userId_eventId: {
                userId: guest.userId,
                eventId: eventIdNum,
              },
            },
            data: { points: { increment: amount } },
          });

          const response = {
            id: transaction.id,
            recipient: guest.user.utorid,
            awarded: amount,
            type: "event",
            relatedId: eventIdNum,
            remark: transaction.remark,
            createdBy: currentUser.utorid,
          };

          transactions.push(response);
        }

        await prisma.event.update({
          where: { id: eventIdNum },
          data: { pointsAwarded: { increment: amount } },
        });

        res.status(201).json(transactions);
      }
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post("/promotions", roleCheckMiddleware("manager"), async (req, res) => {
  try {
    const {
      name,
      description,
      type,
      startTime,
      endTime,
      minSpending,
      rate,
      points,
      ...extraFields
    } = req.body;

    console.log(req.body);
    if (Object.keys(extraFields).length > 0) {
      return res.status(400).json({ error: "Bad Request" });
    }
    if (type !== "automatic" && type !== "onetime") {
      return res.status(400).json({ error: "Bad Request" });
    }

    const startDate = new Date(startTime);
    const endDate = new Date(endTime);
    const now = new Date();

    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return res.status(400).json({ error: "Bad Request" });
    }

    if (startDate < now) {
      return res.status(400).json({ error: "Bad Request" });
    }
    if (endDate <= startDate) {
      return res.status(400).json({ error: "Bad Request" });
    }

    const promotionDataBuilder = {
      name,
      description,
      type,
      startTime: startDate,
      endTime: endDate,
    };

    if (minSpending !== undefined) {
      if (isNaN(minSpending) || minSpending <= 0) {
        return res.status(400).json({ error: "Bad Request" });
      }
      promotionDataBuilder.minSpending = minSpending;
    }

    if (rate !== undefined) {
      if (isNaN(rate) || rate <= 0) {
        return res.status(400).json({ error: "Bad Request" });
      }
      promotionDataBuilder.rate = rate;
    }

    if (points !== undefined) {
      if (isNaN(points) || points <= 0) {
        return res.status(400).json({ error: "Bad Request" });
      }
      promotionDataBuilder.points = points;
    }

    const promotion = await prisma.promotion.create({
      data: promotionDataBuilder,
    });

    const response = {
      id: promotion.id,
      name: promotion.name,
      description: promotion.description,
      type: promotion.type,
      startTime: promotion.startTime.toISOString(),
      endTime: promotion.endTime.toISOString(),
      minSpending: promotion.minSpending,
      rate: promotion.rate,
      points: promotion.points,
    };

    res.status(201).json(response);
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/promotions", roleCheckMiddleware("regular"), async (req, res) => {
  try {
    const { name, type, started, ended, page = "1", limit = "10" } = req.query;

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

    if (started !== undefined && ended !== undefined) {
      return res.status(400).json({ error: "Bad Request" });
    }
    const currentUser = await prisma.user.findUnique({
      where: { id: req.auth.userId },
      select: { id: true, role: true },
    });

    if (!currentUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const filters = {};
    const now = new Date();

    if (name) {
      filters.name = name;
    }
    if (type) {
      if (type !== "automatic" && type !== "onetime") {
        return res.status(400).json({ error: "Bad Request" });
      }
      filters.type = type;
    }

    if (currentUser.role === "manager" || currentUser.role === "superuser") {
      if (started !== undefined) {
        if (started === "true") {
          filters.startTime = { lte: now };
        } else {
          filters.startTime = { gt: now };
        }
      }

      if (ended !== undefined) {
        if (ended === "true") {
          filters.endTime = { lte: now };
        } else {
          filters.endTime = { gt: now };
        }
      }
    } else {
      filters.startTime = { lte: now };
      filters.endTime = { gt: now };
    }
    const allPromotions = await prisma.promotion.findMany({
      where: filters,
    });

    let filteredPromotions = allPromotions;

    if (!(currentUser.role === "manager" || currentUser.role === "superuser")) {
      const usedPromotions = await prisma.userPromotion.findMany({
        where: { userId: currentUser.id },
        select: { promotionId: true },
      });
      const usedPromotionIds = usedPromotions.map(
        (promotion) => promotion.promotionId
      );
      filteredPromotions = allPromotions.filter((promotion) => {
        if (
          promotion.type === "onetime" &&
          usedPromotionIds.includes(promotion.id)
        ) {
          return false;
        }
        return true;
      });
    }

    const count = filteredPromotions.length;

    const skip = (pageNumber - 1) * limitNumber;
    const paginatedPromotionValues = filteredPromotions.slice(
      skip,
      skip + limitNumber
    );

    const results = paginatedPromotionValues.map((promotion) => {
      const promotionResponse = {
        id: promotion.id,
        name: promotion.name,
        type: promotion.type,
      };

      if (currentUser.role === "manager" || currentUser.role === "superuser") {
        promotionResponse.startTime = promotion.startTime.toISOString();
      }

      promotionResponse.endTime = promotion.endTime.toISOString();
      promotionResponse.minSpending = promotion.minSpending;
      promotionResponse.rate = promotion.rate;
      promotionResponse.points = promotion.points;

      return promotionResponse;
    });

    res.status(200).json({
      count,
      results,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get(
  "/promotions/:promotionId",
  roleCheckMiddleware("regular"),
  async (req, res) => {
    try {
      const { promotionId } = req.params;
      const promotionIdNum = parseInt(promotionId, 10);

      if (isNaN(promotionIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const promotion = await prisma.promotion.findUnique({
        where: { id: promotionIdNum },
      });

      if (!promotion) {
        return res.status(404).json({ error: "Not Found" });
      }

      const now = new Date();
      if (promotion.startTime > now || promotion.endTime <= now) {
        return res.status(404).json({ error: "Not Found" });
      }

      const response = {
        id: promotion.id,
        name: promotion.name,
        description: promotion.description,
        type: promotion.type,
        endTime: promotion.endTime.toISOString(),
        minSpending: promotion.minSpending,
        rate: promotion.rate,
        points: promotion.points,
      };

      res.status(200).json(response);
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.patch(
  "/promotions/:promotionId",
  roleCheckMiddleware("manager"),
  async (req, res) => {
    try {
      const { promotionId } = req.params;
      const {
        name,
        description,
        type,
        startTime,
        endTime,
        minSpending,
        rate,
        points,
        ...extraFields
      } = req.body;

      if (Object.keys(extraFields).length > 0) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const promotionIdNum = parseInt(promotionId, 10);
      if (isNaN(promotionIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      if (
        name === undefined &&
        description === undefined &&
        type === undefined &&
        startTime === undefined &&
        endTime === undefined &&
        minSpending === undefined &&
        rate === undefined &&
        points === undefined
      ) {
        return res.status(400).json({ error: "Bad Request" });
      }

      const promotion = await prisma.promotion.findUnique({
        where: { id: promotionIdNum },
      });

      if (!promotion) {
        return res.status(404).json({ error: "Not Found" });
      }

      const now = new Date();
      const updateData = {};

      const response = {
        id: promotion.id,
        name: promotion.name,
        type: promotion.type,
      };

      if (startTime !== undefined) {
        const newStartTime = new Date(startTime);
        if (isNaN(newStartTime.getTime())) {
          return res.status(400).json({ error: "Bad Request" });
        }
        if (newStartTime < now) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.startTime = newStartTime;
        response.startTime = newStartTime.toISOString();
      }

      if (endTime !== undefined) {
        const newEndTime = new Date(endTime);
        if (isNaN(newEndTime.getTime())) {
          return res.status(400).json({ error: "Bad Request" });
        }
        if (newEndTime < now) {
          return res.status(400).json({ error: "Bad Request" });
        }
        const actualStartTime = updateData.startTime || promotion.startTime;
        if (newEndTime <= actualStartTime) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.endTime = newEndTime;
        response.endTime = newEndTime.toISOString();
      }

      if (name !== undefined) {
        if (promotion.startTime < now) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.name = name;
        response.name = name;
      }

      if (description !== undefined) {
        if (promotion.startTime < now) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.description = description;
        response.description = description;
      }
      if (type !== undefined) {
        if (type !== "automatic" && type !== "onetime") {
          return res.status(400).json({ error: "Bad Request" });
        }
        if (promotion.startTime < now) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.type = type;
        response.type = type;
      }

      if (minSpending !== undefined) {
        if (promotion.startTime < now) {
          return res.status(400).json({ error: "Bad Request" });
        }
        if (isNaN(minSpending) || minSpending <= 0) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.minSpending = minSpending;
        response.minSpending = minSpending;
      }

      if (rate !== undefined) {
        if (promotion.startTime < now) {
          return res.status(400).json({ error: "Bad Request" });
        }
        if (isNaN(rate) || rate <= 0) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.rate = rate;
        response.rate = rate;
      }

      if (points !== undefined) {
        if (promotion.startTime < now) {
          return res.status(400).json({ error: "Bad Request" });
        }
        if (isNaN(points) || points <= 0) {
          return res.status(400).json({ error: "Bad Request" });
        }
        updateData.points = points;
        response.points = points;
      }

      await prisma.promotion.update({
        where: { id: promotionIdNum },
        data: updateData,
      });

      res.status(200).json(response);
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.delete(
  "/promotions/:promotionId",
  roleCheckMiddleware("manager"),
  async (req, res) => {
    try {
      const { promotionId } = req.params;
      const promotionIdNum = parseInt(promotionId, 10);

      if (isNaN(promotionIdNum)) {
        return res.status(400).json({ error: "Bad Request" });
      }
      const promotion = await prisma.promotion.findUnique({
        where: { id: promotionIdNum },
      });

      if (!promotion) {
        return res.status(404).json({ error: "Not Found" });
      }

      const now = new Date();
      if (promotion.startTime <= now) {
        return res.status(403).json({ error: "Forbidden" });
      }

      await prisma.promotion.delete({
        where: { id: promotionIdNum },
      });

      res.status(204).send();
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
