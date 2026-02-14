import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import Stripe from "stripe";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";

dotenv.config();

const app = express();

// --------- Stripe ----------
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// --------- Middlewares ----------
app.use(express.json());

// --------- CORS (local + production safe) ----------
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  process.env.CLIENT_URL, // live client url (firebase)
].filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // allow Postman / server-to-server
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error("CORS blocked for: " + origin));
    },
    credentials: true,
  })
);

// --------- Mongo ----------
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ogvd1me.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// collections will be initialized after connect
let db;
let usersCollection;
let requestsCollection;
let fundingCollection;

// ---------- Auth Helpers ----------
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized" });
  }
  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Unauthorized" });
    req.decoded = decoded;
    next();
  });
};

const getDbUserByEmail = async (email) => {
  if (!email) return null;
  return await usersCollection.findOne({ email });
};

const verifyActiveUser = async (req, res, next) => {
  const email = req.decoded?.email;
  const user = await getDbUserByEmail(email);

  if (!user) return res.status(403).send({ message: "Forbidden" });
  if (user.status === "blocked") return res.status(403).send({ message: "User blocked" });

  req.dbUser = user;
  next();
};

const verifyRole = (role) => async (req, res, next) => {
  const email = req.decoded?.email;
  const user = await getDbUserByEmail(email);

  if (!user) return res.status(403).send({ message: "Forbidden" });
  if (user.status === "blocked") return res.status(403).send({ message: "User blocked" });
  if (user.role !== role) return res.status(403).send({ message: "Forbidden" });

  req.dbUser = user;
  next();
};

// admin OR volunteer
const verifyAdminOrVolunteer = async (req, res, next) => {
  const email = req.decoded?.email;
  const user = await getDbUserByEmail(email);

  if (!user) return res.status(403).send({ message: "Forbidden" });
  if (user.status === "blocked") return res.status(403).send({ message: "User blocked" });

  if (!["admin", "volunteer"].includes(user.role)) {
    return res.status(403).send({ message: "Forbidden" });
  }

  req.dbUser = user;
  next();
};

// donor only
const verifyDonor = async (req, res, next) => {
  const email = req.decoded?.email;
  const user = await getDbUserByEmail(email);

  if (!user) return res.status(403).send({ message: "Forbidden" });
  if (user.status === "blocked") return res.status(403).send({ message: "User blocked" });
  if (user.role !== "donor") return res.status(403).send({ message: "Only donor allowed" });

  req.dbUser = user;
  next();
};

// request details access control
const canAccessRequestDetails = (reqUser, requestDoc) => {
  if (!reqUser || !requestDoc) return false;
  if (reqUser.role === "admin" || reqUser.role === "volunteer") return true;
  if (requestDoc.requesterEmail === reqUser.email) return true;
  if (requestDoc.donorEmail && requestDoc.donorEmail === reqUser.email) return true;
  return false;
};

async function run() {
  try {
    await client.connect();
    db = client.db("bloodDonationDB");
    usersCollection = db.collection("users");
    requestsCollection = db.collection("donationRequests");
    fundingCollection = db.collection("fundings");

    console.log("✅ Mongo connected");

    // Health
    app.get("/", (req, res) => res.send("Blood Donation Server Running ✅"));

    // ---------- JWT ----------
    app.post("/jwt", async (req, res) => {
      const { email } = req.body;
      if (!email) return res.status(400).send({ message: "email required" });

      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(401).send({ message: "User not found in DB" });
      if (user.status === "blocked") return res.status(403).send({ message: "User blocked" });

      const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "7d" });
      res.send({ token });
    });

    // ---------- Users ----------
    app.put("/users", async (req, res) => {
      const user = req.body;
      if (!user?.email) return res.status(400).send({ message: "email required" });

      const doc = {
        name: user.name || "",
        email: user.email,
        avatar: user.avatar || "",
        bloodGroup: user.bloodGroup || "",
        district: user.district || "",
        upazila: user.upazila || "",
        role: user.role || "donor",
        status: user.status || "active",
        updatedAt: new Date(),
      };

      const result = await usersCollection.updateOne(
        { email: user.email },
        { $set: doc, $setOnInsert: { createdAt: new Date() } },
        { upsert: true }
      );

      res.send(result);
    });

    app.get("/users", verifyJWT, verifyRole("admin"), async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    app.get("/users/me", verifyJWT, verifyActiveUser, async (req, res) => {
      res.send(req.dbUser);
    });

    // donor search (public)
    app.get("/donors/search", async (req, res) => {
      const { bloodGroup, district, upazila } = req.query;

      const query = { role: "donor", status: "active" };
      if (bloodGroup) query.bloodGroup = bloodGroup;
      if (district) query.district = district;
      if (upazila) query.upazila = upazila;

      const donors = await usersCollection
        .find(query, {
          projection: { name: 1, email: 1, avatar: 1, bloodGroup: 1, district: 1, upazila: 1 },
        })
        .sort({ createdAt: -1 })
        .toArray();

      res.send(donors);
    });

    // ---------- Admin Users ----------
    app.get("/admin/users", verifyJWT, verifyRole("admin"), async (req, res) => {
      const status = req.query.status; // active/blocked
      const query = status ? { status } : {};
      const users = await usersCollection.find(query).sort({ createdAt: -1 }).toArray();
      res.send(users);
    });

    app.patch("/admin/users/:id", verifyJWT, verifyRole("admin"), async (req, res) => {
      const id = req.params.id;
      const { role, status } = req.body;

      const updateDoc = {};
      if (role) updateDoc.role = role;
      if (status) updateDoc.status = status;

      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { ...updateDoc, updatedAt: new Date() } }
      );
      res.send(result);
    });

    // ---------- Donation Requests ----------
    // create (active user only; blocked denied)
    app.post("/donation-requests", verifyJWT, verifyActiveUser, async (req, res) => {
      const email = req.decoded.email;
      const body = req.body;

      const doc = {
        requesterName: body.requesterName || "",
        requesterEmail: email,
        recipientName: body.recipientName || "",
        recipientDistrict: body.recipientDistrict || "",
        recipientUpazila: body.recipientUpazila || "",
        hospitalName: body.hospitalName || "",
        fullAddress: body.fullAddress || "",
        bloodGroup: body.bloodGroup || "",
        donationDate: body.donationDate || "",
        donationTime: body.donationTime || "",
        requestMessage: body.requestMessage || "",
        status: "pending",
        donorName: "",
        donorEmail: "",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await requestsCollection.insertOne(doc);
      res.send(result);
    });

    // my requests
    app.get("/donation-requests/my", verifyJWT, verifyActiveUser, async (req, res) => {
      const email = req.decoded.email;
      const status = req.query.status;
      const query = { requesterEmail: email };
      if (status) query.status = status;

      const data = await requestsCollection.find(query).sort({ createdAt: -1 }).toArray();
      res.send(data);
    });

    // public pending list
    app.get("/donation-requests/pending", async (req, res) => {
      const data = await requestsCollection.find({ status: "pending" }).sort({ createdAt: -1 }).toArray();
      res.send(data);
    });

    // details (private) with access control
    app.get("/donation-requests/:id", verifyJWT, verifyActiveUser, async (req, res) => {
      const id = req.params.id;
      const data = await requestsCollection.findOne({ _id: new ObjectId(id) });
      if (!data) return res.status(404).send({ message: "Not found" });

      const ok = canAccessRequestDetails(req.dbUser, data);
      if (!ok) return res.status(403).send({ message: "Forbidden" });

      res.send(data);
    });

    // update (only owner, pending only; admin can update always)
    app.patch("/donation-requests/:id", verifyJWT, verifyActiveUser, async (req, res) => {
      const id = req.params.id;
      const email = req.decoded.email;
      const body = req.body;

      const existing = await requestsCollection.findOne({ _id: new ObjectId(id) });
      if (!existing) return res.status(404).send({ message: "Not found" });

      const user = req.dbUser;
      const isAdmin = user?.role === "admin";

      if (!isAdmin && existing.requesterEmail !== email) {
        return res.status(403).send({ message: "Forbidden" });
      }

      if (existing.status !== "pending" && !isAdmin) {
        return res.status(400).send({ message: "Only pending can be edited" });
      }

      const updateDoc = {
        recipientName: body.recipientName ?? existing.recipientName,
        recipientDistrict: body.recipientDistrict ?? existing.recipientDistrict,
        recipientUpazila: body.recipientUpazila ?? existing.recipientUpazila,
        hospitalName: body.hospitalName ?? existing.hospitalName,
        fullAddress: body.fullAddress ?? existing.fullAddress,
        bloodGroup: body.bloodGroup ?? existing.bloodGroup,
        donationDate: body.donationDate ?? existing.donationDate,
        donationTime: body.donationTime ?? existing.donationTime,
        requestMessage: body.requestMessage ?? existing.requestMessage,
        updatedAt: new Date(),
      };

      const result = await requestsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updateDoc }
      );
      res.send(result);
    });

    // delete (only owner; admin can delete)
    app.delete("/donation-requests/:id", verifyJWT, verifyActiveUser, async (req, res) => {
      const id = req.params.id;
      const email = req.decoded.email;

      const existing = await requestsCollection.findOne({ _id: new ObjectId(id) });
      if (!existing) return res.status(404).send({ message: "Not found" });

      const user = req.dbUser;
      const isAdmin = user?.role === "admin";

      if (!isAdmin && existing.requesterEmail !== email) {
        return res.status(403).send({ message: "Forbidden" });
      }

      const result = await requestsCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // confirm donate (DONOR ONLY) pending -> inprogress
    app.patch("/donation-requests/:id/confirm", verifyJWT, verifyDonor, async (req, res) => {
      const id = req.params.id;
      const email = req.decoded.email;
      const { donorName } = req.body;

      const existing = await requestsCollection.findOne({ _id: new ObjectId(id) });
      if (!existing) return res.status(404).send({ message: "Not found" });
      if (existing.status !== "pending") return res.status(400).send({ message: "Only pending can be confirmed" });

      const result = await requestsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status: "inprogress",
            donorName: donorName || req.dbUser?.name || "",
            donorEmail: email,
            updatedAt: new Date(),
          },
        }
      );
      res.send(result);
    });

    // alias donate endpoint (clean)
    app.patch("/donation-requests/:id/donate", verifyJWT, verifyDonor, async (req, res) => {
      const id = req.params.id;
      const email = req.decoded.email;
      const { donorName } = req.body;

      const existing = await requestsCollection.findOne({ _id: new ObjectId(id) });
      if (!existing) return res.status(404).send({ message: "Not found" });
      if (existing.status !== "pending") return res.status(400).send({ message: "Only pending can be confirmed" });

      const result = await requestsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status: "inprogress",
            donorName: donorName || req.dbUser?.name || "",
            donorEmail: email,
            updatedAt: new Date(),
          },
        }
      );
      res.send(result);
    });

    // status update:
    // admin/volunteer can update any status
    // donor(owner) can update status for own request
    app.patch("/donation-requests/:id/status", verifyJWT, verifyActiveUser, async (req, res) => {
      const id = req.params.id;
      const email = req.decoded.email;
      const { status } = req.body;

      const existing = await requestsCollection.findOne({ _id: new ObjectId(id) });
      if (!existing) return res.status(404).send({ message: "Not found" });

      const user = req.dbUser;
      const isAdmin = user?.role === "admin";
      const isVolunteer = user?.role === "volunteer";

      if (isVolunteer || isAdmin) {
        const result = await requestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status, updatedAt: new Date() } }
        );
        return res.send(result);
      }

      if (existing.requesterEmail !== email) {
        return res.status(403).send({ message: "Forbidden" });
      }

      const result = await requestsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status, updatedAt: new Date() } }
      );
      res.send(result);
    });

    // admin/volunteer requests list
    app.get("/admin-or-volunteer/requests", verifyJWT, verifyAdminOrVolunteer, async (req, res) => {
      const status = req.query.status;
      const query = status ? { status } : {};
      const data = await requestsCollection.find(query).sort({ createdAt: -1 }).toArray();
      res.send(data);
    });

    // ---------- Dashboard Stats ----------
    app.get("/admin-or-volunteer/stats", verifyJWT, verifyAdminOrVolunteer, async (req, res) => {
      const totalDonors = await usersCollection.countDocuments({ role: "donor" });
      const totalRequests = await requestsCollection.countDocuments();

      const fundingAgg = await fundingCollection
        .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
        .toArray();

      const totalFunding = fundingAgg?.[0]?.total || 0;

      res.send({ totalDonors, totalFunding, totalRequests });
    });

    // =================================================================
    // ======================= FUNDING (STRIPE) =========================
    // =================================================================

    // Funding list (protected)
    app.get("/fundings", verifyJWT, verifyActiveUser, async (req, res) => {
      const userRole = req.dbUser?.role;
      const email = req.decoded.email;

      if (userRole === "admin" || userRole === "volunteer") {
        const data = await fundingCollection.find().sort({ createdAt: -1 }).toArray();
        return res.send(data);
      }

      const data = await fundingCollection.find({ email }).sort({ createdAt: -1 }).toArray();
      res.send(data);
    });

    // Create Stripe Checkout Session
    app.post("/create-checkout-session", verifyJWT, verifyActiveUser, async (req, res) => {
      try {
        const { amount, name, email } = req.body;

        const n = Number(amount);
        if (!n || n < 10) return res.status(400).send({ message: "Minimum amount is 10" });

        // Stripe expects cents for usd
        const unitAmount = Math.round(n * 100);

        const session = await stripe.checkout.sessions.create({
          mode: "payment",
          payment_method_types: ["card"],
          line_items: [
            {
              quantity: 1,
              price_data: {
                currency: "usd",
                unit_amount: unitAmount,
                product_data: { name: "Blood Donation Platform Funding" },
              },
            },
          ],
          metadata: {
            email: email || req.decoded.email,
            name: name || "",
          },
          success_url: `${process.env.CLIENT_URL}/funding?success=1&session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.CLIENT_URL}/funding?canceled=1`,
        });

        res.send({ url: session.url });
      } catch (e) {
        console.error("Stripe error:", e?.message);
        res.status(500).send({ message: "Stripe session create failed" });
      }
    });

    // Confirm payment & save funding to DB
    app.post("/fundings/confirm", verifyJWT, verifyActiveUser, async (req, res) => {
      try {
        const { sessionId } = req.body;
        if (!sessionId) return res.status(400).send({ message: "sessionId required" });

        const exists = await fundingCollection.findOne({ sessionId });
        if (exists) return res.send({ ok: true, message: "Already saved" });

        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status !== "paid") {
          return res.status(400).send({ message: "Payment not completed" });
        }

        const amountTotal = (session.amount_total || 0) / 100;
        const currency = session.currency || "usd";
        const meta = session.metadata || {};

        const doc = {
          sessionId,
          amount: amountTotal,
          currency,
          name: meta.name || req.dbUser?.name || "",
          email: meta.email || req.decoded.email,
          createdAt: new Date(),
        };

        const result = await fundingCollection.insertOne(doc);
        res.send(result);
      } catch (e) {
        console.error("Stripe confirm error:", e?.message);
        res.status(500).send({ message: "Funding confirm failed" });
      }
    });

    console.log("✅ API ready (including Stripe Funding)");
  } finally {
    // keep running
  }
}

run().catch(console.dir);

app.listen(process.env.PORT || 5000, () => {
  console.log("Server running on port", process.env.PORT || 5000);
});
