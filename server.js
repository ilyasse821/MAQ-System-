"use strict";

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const mongoose = require("mongoose");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const path = require("node:path");

// ---------- الإعدادات ----------
require("dotenv/config");

const REQUIRED = ["DISCORD_BOT_TOKEN", "MONGODB_URI", "SESSION_SECRET"];
for (const key of REQUIRED) {
  if (!process.env[key]) {
    console.error(`❌ متغير البيئة المطلوب مفقود: ${key}`);
    process.exit(1);
  }
}

const CONFIG = {
  botToken: process.env.DISCORD_BOT_TOKEN,
  mongoUri: process.env.MONGODB_URI,
  ownerIds: (process.env.BOT_OWNER_IDS || "").split(",").map((s) => s.trim()).filter(Boolean),
  sessionSecret: process.env.SESSION_SECRET,
  // كود PIN الابتدائي — يُستخدم فقط أول مرة لا يوجد فيها PIN مخزَّن في القاعدة،
  // بعدها يُدار بالكامل من صفحة "تغيير PIN" داخل الداشبورد.
  initialPin: process.env.DASHBOARD_PIN || null,
  port: Number(process.env.PORT || 3000),
  isProd: process.env.NODE_ENV === "production"
};


// ---------- نماذج قاعدة البيانات ----------
// هذه النماذج يجب أن تبقى مطابقة تماماً (نفس اسم الـ model، نفس بنية

const GuildConfigSchema = new mongoose.Schema(
  {
    guildId: { type: String, required: true, unique: true, index: true },
    logChannels: {
      moderation: String,
      messages: String,
      voice: String,
      joins: String,
      server: String,
      tickets: String,
      automod: String,
      commands: String,
      errors: String
    },
    staffRoles: {
      trusted: { type: [String], default: [] },
      staff: { type: [String], default: [] },
      moderator: { type: [String], default: [] },
      admin: { type: [String], default: [] }
    },
    automod: {
      enabled: { type: Boolean, default: true },
      antiSpam: {
        enabled: { type: Boolean, default: true },
        maxMessages: { type: Number, default: 6 },
        perSeconds: { type: Number, default: 7 },
        action: { type: String, enum: ["warn", "mute", "kick"], default: "mute" }
      },
      antiInvite: { enabled: { type: Boolean, default: true }, allowlist: { type: [String], default: [] } },
      antiLink: { enabled: { type: Boolean, default: false }, allowlist: { type: [String], default: [] } },
      antiMentionSpam: { enabled: { type: Boolean, default: true }, maxMentions: { type: Number, default: 6 } },
      antiRaid: {
        enabled: { type: Boolean, default: true },
        joinThreshold: { type: Number, default: 10 },
        perSeconds: { type: Number, default: 30 },
        minAccountAgeMinutes: { type: Number, default: 30 },
        action: { type: String, enum: ["kick", "ban", "lockdown_only"], default: "lockdown_only" }
      },
      antiMassAction: { enabled: { type: Boolean, default: true }, maxActionsPerMinute: { type: Number, default: 5 } },
      ignoredChannels: { type: [String], default: [] },
      ignoredRoles: { type: [String], default: [] }
    },
    tickets: {
      enabled: { type: Boolean, default: true },
      categoryChannelId: String,
      supportRoleIds: { type: [String], default: [] },
      maxOpenPerUser: { type: Number, default: 1 },
      categories: { type: [{ key: String, label: String, emoji: String }], default: [] }
    },
    moderationEscalation: {
      warnsBeforeMute: { type: Number, default: 3 },
      warnsBeforeKick: { type: Number, default: 5 },
      warnsBeforeBan: { type: Number, default: 7 }
    },
    lockdown: {
      active: { type: Boolean, default: false },
      activatedBy: String,
      activatedAt: Date
    }
  },
  { timestamps: true }
);
const GuildConfig = mongoose.model("GuildConfig", GuildConfigSchema);

const ModerationCaseSchema = new mongoose.Schema(
  {
    guildId: { type: String, required: true, index: true },
    caseId: Number,
    type: String,
    targetId: String,
    targetTag: String,
    moderatorId: String,
    moderatorTag: String,
    reason: String,
    active: { type: Boolean, default: true },
    duration: Number,
    expiresAt: Date
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);
const ModerationCase = mongoose.model("ModerationCase", ModerationCaseSchema);

const TicketSchema = new mongoose.Schema(
  {
    guildId: { type: String, required: true, index: true },
    ticketNumber: Number,
    channelId: String,
    category: String,
    ownerId: String,
    ownerTag: String,
    claimedBy: String,
    status: { type: String, enum: ["open", "claimed", "closed"], default: "open" },
    closedBy: String,
    closedReason: String,
    closedAt: Date
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);
const Ticket = mongoose.model("Ticket", TicketSchema);

const AuditEntrySchema = new mongoose.Schema(
  {
    guildId: { type: String, required: true, index: true },
    category: { type: String, required: true, index: true },
    action: String,
    executorId: String,
    executorTag: String,
    targetId: String,
    targetTag: String,
    channelId: String,
    channelName: String,
    reason: String,
    before: mongoose.Schema.Types.Mixed,
    after: mongoose.Schema.Types.Mixed,
    metadata: mongoose.Schema.Types.Mixed
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);
const AuditEntry = mongoose.model("AuditEntry", AuditEntrySchema);

// ---- كود PIN لدخول الداشبورد (مستقل تماماً عن بيانات البوت) ----
const DashboardAuthSchema = new mongoose.Schema(
  {
    key: { type: String, default: "singleton", unique: true },
    pinHash: { type: String, required: true },
    failedAttempts: { type: Number, default: 0 },
    lockedUntil: Date,
    updatedAt: { type: Date, default: Date.now }
  },
  { timestamps: false }
);
const DashboardAuth = mongoose.model("DashboardAuth", DashboardAuthSchema);



// ---------- خدمة PIN ----------

const MAX_ATTEMPTS = 5;
const LOCK_MINUTES = 15;

// يُنشئ سجل PIN الأول من DASHBOARD_PIN في .env إذا لم يوجد أي سجل بعد.
async function ensurePinSeeded() {
  const existing = await DashboardAuth.findOne({ key: "singleton" });
  if (existing) return existing;

  if (!CONFIG.initialPin) {
    throw new Error(
      "لا يوجد كود PIN مخزَّن بعد، ويجب ضبط DASHBOARD_PIN في .env عند أول تشغيل فقط (يُستخدم مرة واحدة للبذر، بعدها غيّره من صفحة تغيير PIN)."
    );
  }
  if (!/^\d{4,8}$/.test(CONFIG.initialPin)) {
    throw new Error("DASHBOARD_PIN يجب أن يكون أرقاماً فقط، بين 4 و8 خانات.");
  }

  const pinHash = await bcrypt.hash(CONFIG.initialPin, 12);
  return DashboardAuth.create({ key: "singleton", pinHash });
}

// يتحقق من كود PIN المُدخَل. يعيد { ok, locked, remainingAttempts }.
async function verifyPin(inputPin) {
  const auth = await ensurePinSeeded();

  if (auth.lockedUntil && auth.lockedUntil > new Date()) {
    const minutesLeft = Math.ceil((auth.lockedUntil - new Date()) / 60000);
    return { ok: false, locked: true, minutesLeft };
  }

  const match = await bcrypt.compare(String(inputPin), auth.pinHash);

  if (!match) {
    auth.failedAttempts += 1;
    if (auth.failedAttempts >= MAX_ATTEMPTS) {
      auth.lockedUntil = new Date(Date.now() + LOCK_MINUTES * 60000);
      auth.failedAttempts = 0;
    }
    await auth.save();
    return { ok: false, locked: false, remainingAttempts: Math.max(0, MAX_ATTEMPTS - auth.failedAttempts) };
  }

  auth.failedAttempts = 0;
  auth.lockedUntil = undefined;
  await auth.save();
  return { ok: true };
}

async function changePin(currentPin, newPin) {
  if (!/^\d{4,8}$/.test(newPin)) {
    return { ok: false, error: "الكود الجديد يجب أن يكون أرقاماً فقط، بين 4 و8 خانات." };
  }

  const check = await verifyPin(currentPin);
  if (!check.ok) {
    return { ok: false, error: check.locked ? `الحساب مقفل مؤقتاً، حاول بعد ${check.minutesLeft} دقيقة.` : "الكود الحالي غير صحيح." };
  }

  const pinHash = await bcrypt.hash(newPin, 12);
  await DashboardAuth.findOneAndUpdate({ key: "singleton" }, { pinHash, updatedAt: new Date() });
  return { ok: true };
}



// ---------- خدمة Discord API (بتوكن البوت) ----------

const DISCORD_API = "https://discord.com/api/v10";

async function botRequest(path) {
  const { data } = await axios.get(`${DISCORD_API}${path}`, {
    headers: { Authorization: `Bot ${CONFIG.botToken}` }
  });
  return data;
}

// كل السيرفرات التي يوجد فيها البوت — تُستخدم لملء قائمة اختيار السيرفر في الداشبورد.
async function fetchBotGuilds() {
  return botRequest("/users/@me/guilds");
}

async function fetchGuildChannels(guildId) {
  const channels = await botRequest(`/guilds/${guildId}/channels`);
  return channels.filter((c) => c.type === 0 || c.type === 4).sort((a, b) => a.position - b.position);
}

async function fetchGuildRoles(guildId) {
  const roles = await botRequest(`/guilds/${guildId}/roles`);
  return roles.filter((r) => r.name !== "@everyone").sort((a, b) => b.position - a.position);
}

async function fetchGuildInfo(guildId) {
  return botRequest(`/guilds/${guildId}?with_counts=true`);
}



// ---------- الحراسة (Auth Middleware) ----------

function ensureAuthenticated(req, res, next) {
  if (req.session?.authenticated) return next();
  req.session.returnTo = req.originalUrl;
  return res.redirect("/auth/login");
}

// يتحقق أن البوت فعلاً موجود في السيرفر المطلوب (يمنع الوصول لمعرف سيرفر عشوائي).
async function ensureGuildAccess(req, res, next) {
  try {
    const { guildId } = req.params;
    const guilds = await fetchBotGuilds();
    const found = guilds.some((g) => g.id === guildId);
    if (!found) {
      return res.status(403).render("views", { page: "error", title: "الوصول مرفوض", message: "البوت غير موجود في هذا السيرفر." });
    }
    next();
  } catch (err) {
    next(err);
  }
}



// ---------- تطبيق Express ----------
const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      "font-src": ["'self'", "https://fonts.gstatic.com"]
    }
  }
}));
app.use(express.urlencoded({ extended: true }));
app.get("/style.css", (req, res) => res.sendFile(path.join(__dirname, "style.css")));
app.use(rateLimit({ windowMs: 60_000, max: 120 }));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 8 });

async function getConfig(guildId) {
  return GuildConfig.findOneAndUpdate({ guildId }, { $setOnInsert: { guildId } }, { upsert: true, new: true });
}

async function start() {
  await mongoose.connect(CONFIG.mongoUri);
  console.log("✅ الداشبورد متصل بقاعدة البيانات");

  app.use(session({
    secret: CONFIG.sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: CONFIG.mongoUri, collectionName: "dashboardSessions" }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7, secure: CONFIG.isProd, httpOnly: true, sameSite: "lax" }
  }));

  app.get("/", (req, res) => res.redirect(req.session.authenticated ? "/dashboard" : "/auth/login"));

  app.get("/auth/login", (req, res) => {
    if (req.session.authenticated) return res.redirect("/dashboard");
    res.render("views", { page: "login", title: "تسجيل الدخول", error: null });
  });

  app.post("/auth/login", loginLimiter, async (req, res, next) => {
    try {
      const result = await verifyPin(req.body.pin);
      if (!result.ok) {
        const error = result.locked
          ? `تم قفل الدخول مؤقتاً. حاول بعد ${result.minutesLeft} دقيقة.`
          : `كود PIN غير صحيح. المحاولات المتبقية: ${result.remainingAttempts}.`;
        return res.status(401).render("views", { page: "login", title: "تسجيل الدخول", error });
      }
      req.session.authenticated = true;
      const returnTo = req.session.returnTo || "/dashboard";
      delete req.session.returnTo;
      res.redirect(returnTo);
    } catch (err) { next(err); }
  });

  app.post("/auth/logout", (req, res) => req.session.destroy(() => res.redirect("/auth/login")));

  app.get("/auth/change-pin", (req, res) => {
    if (!req.session.authenticated) return res.redirect("/auth/login");
    res.render("views", { page: "change-pin", title: "تغيير PIN", error: null, success: null });
  });

  app.post("/auth/change-pin", async (req, res, next) => {
    try {
      if (!req.session.authenticated) return res.redirect("/auth/login");
      const { currentPin, newPin, confirmPin } = req.body;
      if (newPin !== confirmPin) {
        return res.status(400).render("views", { page: "change-pin", title: "تغيير PIN", error: "الكود الجديد وتأكيده غير متطابقين.", success: null });
      }
      const result = await changePin(currentPin, newPin);
      if (!result.ok) return res.status(400).render("views", { page: "change-pin", title: "تغيير PIN", error: result.error, success: null });
      res.render("views", { page: "change-pin", title: "تغيير PIN", error: null, success: "✅ تم تغيير كود PIN بنجاح." });
    } catch (err) { next(err); }
  });

  app.get("/dashboard", ensureAuthenticated, async (req, res, next) => {
    try {
      const guilds = await fetchBotGuilds();
      res.render("views", { page: "guilds", title: "السيرفرات", guilds });
    } catch (err) { next(err); }
  });

  app.use("/dashboard/:guildId", ensureAuthenticated, ensureGuildAccess, async (req, res, next) => {
    try {
      res.locals.guildId = req.params.guildId;
      const [guildInfo, config] = await Promise.all([
        fetchGuildInfo(req.params.guildId).catch(() => null),
        getConfig(req.params.guildId)
      ]);
      res.locals.guildInfo = guildInfo;
      res.locals.guildConfig = config;
      res.locals.lockdownActive = Boolean(config.lockdown && config.lockdown.active);
      next();
    } catch (err) { next(err); }
  });

  app.get("/dashboard/:guildId", async (req, res, next) => {
    try {
      const { guildId } = req.params;
      const config = res.locals.guildConfig;
      const [openTickets, totalCases, recentEntries, todayCases] = await Promise.all([
        Ticket.countDocuments({ guildId, status: { $ne: "closed" } }),
        ModerationCase.countDocuments({ guildId }),
        AuditEntry.find({ guildId }).sort({ createdAt: -1 }).limit(8).lean(),
        ModerationCase.countDocuments({ guildId, createdAt: { $gte: new Date(Date.now() - 86400000) } })
      ]);
      res.render("views", { page: "overview", title: "نظرة عامة", guildId, guildInfo: res.locals.guildInfo, lockdownActive: res.locals.lockdownActive, config, stats: { openTickets, totalCases, todayCases }, recentEntries });
    } catch (err) { next(err); }
  });

  app.get("/dashboard/:guildId/logs-config", async (req, res, next) => {
    try {
      const { guildId } = req.params;
      const channels = await fetchGuildChannels(guildId);
      res.render("views", { page: "logs-config", title: "تشانلات اللوق", guildId, guildInfo: res.locals.guildInfo, lockdownActive: res.locals.lockdownActive, config: res.locals.guildConfig, channels, saved: req.query.saved });
    } catch (err) { next(err); }
  });

  app.get("/dashboard/:guildId/roles", async (req, res, next) => {
    try {
      const { guildId } = req.params;
      const roles = await fetchGuildRoles(guildId);
      res.render("views", { page: "roles", title: "الرتب والصلاحيات", guildId, guildInfo: res.locals.guildInfo, lockdownActive: res.locals.lockdownActive, config: res.locals.guildConfig, roles, saved: req.query.saved });
    } catch (err) { next(err); }
  });

  app.get("/dashboard/:guildId/automod", async (req, res, next) => {
    res.render("views", { page: "automod", title: "الحماية التلقائية", guildId: req.params.guildId, guildInfo: res.locals.guildInfo, lockdownActive: res.locals.lockdownActive, config: res.locals.guildConfig, saved: req.query.saved });
  });

  app.get("/dashboard/:guildId/tickets", async (req, res, next) => {
    try {
      const { guildId } = req.params;
      const status = req.query.status || "all";
      const filter = { guildId };
      if (status !== "all") filter.status = status;
      const tickets = await Ticket.find(filter).sort({ createdAt: -1 }).limit(100).lean();
      res.render("views", { page: "tickets", title: "التذاكر", guildId, guildInfo: res.locals.guildInfo, lockdownActive: res.locals.lockdownActive, tickets, status });
    } catch (err) { next(err); }
  });

  app.get("/dashboard/:guildId/cases", async (req, res, next) => {
    try {
      const { guildId } = req.params;
      const type = req.query.type || "all";
      const filter = { guildId };
      if (type !== "all") filter.type = type;
      const cases = await ModerationCase.find(filter).sort({ createdAt: -1 }).limit(100).lean();
      res.render("views", { page: "cases", title: "الإجراءات الإدارية", guildId, guildInfo: res.locals.guildInfo, lockdownActive: res.locals.lockdownActive, cases, type });
    } catch (err) { next(err); }
  });

  app.get("/dashboard/:guildId/audit-log", async (req, res, next) => {
    try {
      const { guildId } = req.params;
      const category = req.query.category || "all";
      const page = Math.max(1, parseInt(req.query.page) || 1);
      const pageSize = 30;
      const filter = { guildId };
      if (category !== "all") filter.category = category;
      const [entries, total] = await Promise.all([
        AuditEntry.find(filter).sort({ createdAt: -1 }).skip((page - 1) * pageSize).limit(pageSize).lean(),
        AuditEntry.countDocuments(filter)
      ]);
      res.render("views", { page: "audit-log", title: "سجل اللوقات", guildId, guildInfo: res.locals.guildInfo, lockdownActive: res.locals.lockdownActive, entries, category, page, totalPages: Math.max(1, Math.ceil(total / pageSize)) });
    } catch (err) { next(err); }
  });

  const LOG_CHANNEL_KEYS = ["moderation","messages","voice","joins","server","tickets","automod","commands","errors"];

  app.post("/api/guilds/:guildId/logs-config", ensureAuthenticated, ensureGuildAccess, async (req, res, next) => {
    try {
      const set = {};
      for (const key of LOG_CHANNEL_KEYS) set[`logChannels.${key}`] = req.body[key] || undefined;
      await GuildConfig.findOneAndUpdate({ guildId: req.params.guildId }, { $set: set }, { upsert: true });
      res.redirect(`/dashboard/${req.params.guildId}/logs-config?saved=1`);
    } catch (err) { next(err); }
  });

  app.post("/api/guilds/:guildId/roles", ensureAuthenticated, ensureGuildAccess, async (req, res, next) => {
    try {
      const toArray = (v) => (Array.isArray(v) ? v : v ? [v] : []);
      const set = {
        "staffRoles.trusted": toArray(req.body.trusted),
        "staffRoles.staff": toArray(req.body.staff),
        "staffRoles.moderator": toArray(req.body.moderator),
        "staffRoles.admin": toArray(req.body.admin)
      };
      await GuildConfig.findOneAndUpdate({ guildId: req.params.guildId }, { $set: set }, { upsert: true });
      res.redirect(`/dashboard/${req.params.guildId}/roles?saved=1`);
    } catch (err) { next(err); }
  });

  app.post("/api/guilds/:guildId/automod", ensureAuthenticated, ensureGuildAccess, async (req, res, next) => {
    try {
      const b = req.body;
      const set = {
        "automod.enabled": b.enabled === "on",
        "automod.antiSpam.enabled": b.antiSpamEnabled === "on",
        "automod.antiSpam.maxMessages": Number(b.maxMessages) || 6,
        "automod.antiSpam.perSeconds": Number(b.perSeconds) || 7,
        "automod.antiInvite.enabled": b.antiInviteEnabled === "on",
        "automod.antiLink.enabled": b.antiLinkEnabled === "on",
        "automod.antiMentionSpam.enabled": b.antiMentionEnabled === "on",
        "automod.antiMentionSpam.maxMentions": Number(b.maxMentions) || 6,
        "automod.antiRaid.enabled": b.antiRaidEnabled === "on",
        "automod.antiRaid.joinThreshold": Number(b.joinThreshold) || 10,
        "automod.antiRaid.perSeconds": Number(b.raidPerSeconds) || 30,
        "automod.antiRaid.action": b.raidAction || "lockdown_only",
        "moderationEscalation.warnsBeforeMute": Number(b.warnsBeforeMute) || 3,
        "moderationEscalation.warnsBeforeKick": Number(b.warnsBeforeKick) || 5,
        "moderationEscalation.warnsBeforeBan": Number(b.warnsBeforeBan) || 7
      };
      await GuildConfig.findOneAndUpdate({ guildId: req.params.guildId }, { $set: set }, { upsert: true });
      res.redirect(`/dashboard/${req.params.guildId}/automod?saved=1`);
    } catch (err) { next(err); }
  });

  app.post("/api/guilds/:guildId/lockdown/:state", ensureAuthenticated, ensureGuildAccess, async (req, res, next) => {
    try {
      const { guildId, state } = req.params;
      const lock = state === "on";
      const channels = await axios.get(`https://discord.com/api/v10/guilds/${guildId}/channels`, { headers: { Authorization: `Bot ${CONFIG.botToken}` } }).then(r => r.data);
      await Promise.all(channels.filter(c => c.type === 0).map(c =>
        axios.put(`https://discord.com/api/v10/channels/${c.id}/permissions/${guildId}`,
          { type: 0, deny: lock ? "2048" : "0", allow: "0" },
          { headers: { Authorization: `Bot ${CONFIG.botToken}` } }
        ).catch(() => null)
      ));
      await GuildConfig.findOneAndUpdate({ guildId },
        lock ? { $set: { "lockdown.active": true, "lockdown.activatedBy": "dashboard", "lockdown.activatedAt": new Date() } } : { $set: { "lockdown.active": false } },
        { upsert: true });
      res.redirect(`/dashboard/${guildId}?lockdown=${state}`);
    } catch (err) { next(err); }
  });

  app.use((req, res) => {
    res.status(404).render("views", { page: "error", title: "الصفحة غير موجودة", message: "الرابط الذي فتحته غير موجود." });
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).render("views", { page: "error", title: "خطأ في الخادم", message: "حدث خطأ غير متوقع. حاول لاحقاً." });
  });

  app.listen(CONFIG.port, () => console.log(`✅ الداشبورد يعمل على http://localhost:${CONFIG.port}`));
}

start().catch((err) => { console.error("❌ فشل تشغيل الداشبورد:", err); process.exit(1); });
