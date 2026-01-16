const WebSocket = require('ws');
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // সিরিয়াল জেনারেট করার জন্য

// ==========================================
// কনফিগারেশন (CONFIGURATION)
// ==========================================
// আপনার দেওয়া মঙ্গোডিবি কানেকশন স্ট্রিং
const MONGODB_URI = "mongodb+srv://sarwarjahanshohid_db_user:CPlQyNRqiD2CyRNc@cluster0.t1fleow.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const JWT_SECRET = process.env.JWT_SECRET || "secure_secret_key_500_devices";
const PORT = process.env.PORT || 3000;

// অফলাইন চেক কনফিগারেশন
const OFFLINE_CHECK_INTERVAL = 10 * 60 * 1000; // ১০ মিনিট
const OFFLINE_THRESHOLD = 10 * 60 * 1000;      // ১০ মিনিট (এর বেশি সময় সিগন্যাল না পেলে অফলাইন)

mongoose.connect(MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected Successfully"))
  .catch(err => console.error("❌ DB Error:", err));

// ==========================================
// স্কিমা (SCHEMAS)
// ==========================================

// ১. ইউজার স্কিমা
const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    isBlocked: { type: Boolean, default: false },
    devices: [{ type: String }] // ম্যাক এড্রেসের তালিকা
});

// ২. ডিভাইস স্কিমা
const DeviceSchema = new mongoose.Schema({
    macAddress: { type: String, unique: true, required: true },
    serialNumber: { type: String, required: true }, // অটো জেনারেট হবে
    ownerEmail: { type: String, default: null },
    isLocked: { type: Boolean, default: false }, // অ্যাডমিন লক
    status: { type: String, default: 'OFFLINE' },
    lastSeen: { type: Date, default: Date.now }
});

// ৩. মোটর লগ স্কিমা (অ্যাক্টিভিটি লগ)
const MotorLogSchema = new mongoose.Schema({
    macAddress: { type: String, required: true, index: true },
    startTime: Date,
    endTime: Date,
    duration: String,     // যেমন: "10m 5s"
    bdDate: String,       // বাংলাদেশ তারিখ
    bdTime: String,       // বাংলাদেশ সময় (শুরু)
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Device = mongoose.model('Device', DeviceSchema);
const MotorLog = mongoose.model('MotorLog', MotorLogSchema);

// ==========================================
// এক্সপ্রেস অ্যাপ (API Routes)
// ==========================================
const app = express();
app.use(cors());
app.use(express.json());

// --- হেল্পার: বাংলাদেশ সময় ---
function getBDTime() {
    const now = new Date();
    const options = { timeZone: 'Asia/Dhaka', hour12: true };
    return {
        date: now.toLocaleDateString('en-GB', { timeZone: 'Asia/Dhaka' }),
        time: now.toLocaleTimeString('en-US', options)
    };
}

// --- হেল্পার: সিরিয়াল নম্বর জেনারেটর ---
function generateSerialNumber() {
    // উদাহরণ: SN-A1B2C3D4
    return `SN-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

// --- অফলাইন চেকার ফাংশন (প্রতি ১০ মিনিট পর পর) ---
async function checkOfflineDevices() {
    try {
        const threshold = new Date(Date.now() - OFFLINE_THRESHOLD);
        
        // যেই ডিভাইসগুলো অনলাইনে আছে কিন্তু ১০ মিনিটের বেশি সময় আপডেট দেয়নি
        const result = await Device.updateMany(
            { status: 'ONLINE', lastSeen: { $lt: threshold } },
            { $set: { status: 'OFFLINE' } }
        );

        if (result.modifiedCount > 0) {
            console.log(`[Offline Monitor] ${result.modifiedCount} devices marked OFFLINE.`);
        }
    } catch (error) {
        console.error('[Offline Monitor Error]', error);
    }
}

// ১০ মিনিট পর পর অফলাইন চেক রান হবে
setInterval(checkOfflineDevices, OFFLINE_CHECK_INTERVAL);

// --- অথ মিডলওয়্যার ---
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ msg: "No token" });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) { res.status(401).json({ msg: "Invalid Token" }); }
};

// --- রাউটস (ROUTES) ---

// সাইনআপ
app.post('/api/auth/signup', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();
        res.json({ msg: "User registered" });
    } catch (e) { res.status(400).json({ msg: "Email exists" }); }
});

// লগইন
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: "User not found" });
    if (user.isBlocked) return res.status(403).json({ msg: "Account Blocked" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid Credentials" });

    const token = jwt.sign({ id: user._id, role: user.role, email: user.email }, JWT_SECRET);
    res.json({ token, user: { name: user.name, email: user.email, role: user.role, devices: user.devices } });
});

// ডিভাইস অ্যাড (ইউজার)
app.post('/api/device/add', authenticate, async (req, res) => {
    const { macAddress, serialNumber } = req.body;
    
    // ডিভাইসটি ডেটাবেসে আছে কিনা চেক করা
    let device = await Device.findOne({ macAddress });

    // যদি ডিভাইস না থাকে এবং ইউজার ম্যানুয়ালি অ্যাড করতে চায়,
    // তবে সিকিউরিটির জন্য সিরিয়াল নম্বর ম্যাচ করতে হবে (যদি আগে অটো জেনারেট হয়ে থাকে)
    if (!device) {
         return res.status(404).json({ msg: "Device not found. Connect device to internet first." });
    }

    // সিরিয়াল নম্বর ভেরিফিকেশন
    if (device.serialNumber !== serialNumber) {
        return res.status(400).json({ msg: "Invalid Serial Number" });
    }

    // মালিকানা চেক
    if (device.ownerEmail && device.ownerEmail !== req.user.email) {
        return res.status(400).json({ msg: "Device already claimed by another user" });
    }

    device.ownerEmail = req.user.email;
    await device.save();

    await User.findByIdAndUpdate(req.user.id, { $addToSet: { devices: macAddress } });
    res.json({ msg: "Device Added Successfully", macAddress });
});

// অ্যাডমিন: সকল ইউজার
app.get('/api/admin/users', authenticate, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ msg: "Access Denied" });
    const users = await User.find({}, '-password');
    res.json(users);
});

// অ্যাডমিন: ব্লক/আনব্লক
app.post('/api/admin/toggle-block', authenticate, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ msg: "Access Denied" });
    const { userId, blockStatus } = req.body;
    await User.findByIdAndUpdate(userId, { isBlocked: blockStatus });
    res.json({ msg: "Updated" });
});

// অ্যাডমিন: ডিভাইস লক
app.post('/api/admin/lock-device', authenticate, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ msg: "Access Denied" });
    const { macAddress, lockStatus } = req.body;
    await Device.findOneAndUpdate({ macAddress }, { isLocked: lockStatus });
    
    // লক হলে ফোর্স ডিসকানেক্ট
    if (lockStatus) {
        const ws = connectedDevices.get(macAddress);
        if (ws) {
            ws.send(JSON.stringify({ command: "LOCKED_BY_ADMIN" }));
            ws.close();
        }
    }
    res.json({ msg: "Device Lock Status Updated" });
});

// ==========================================
// ওয়েব সকেট সার্ভার (IoT লজিক)
// ==========================================
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ম্যাপস
const connectedDevices = new Map(); // MAC -> WS
const activeMotorSessions = new Map(); // MAC -> StartTime (Date)

wss.on('connection', (ws) => {
    
    ws.on('message', async (msg) => {
        try {
            const data = JSON.parse(msg);

            // ১. ডিভাইস আইডেন্টিটি (ESP32)
            if (data.type === 'identify_device') {
                const mac = data.macAddress;
                
                // ডেটাবেসে ডিভাইস খুঁজুন বা অটো তৈরি করুন
                let deviceDB = await Device.findOne({ macAddress: mac });
                
                if (!deviceDB) {
                    // নতুন ডিভাইস: অটো সিরিয়াল নম্বর জেনারেট হবে
                    const newSerial = generateSerialNumber();
                    deviceDB = new Device({
                        macAddress: mac,
                        serialNumber: newSerial,
                        status: 'ONLINE',
                        lastSeen: new Date()
                    });
                    await deviceDB.save();
                    console.log(`✨ New Device Created: ${mac} (SN: ${newSerial})`);
                } else {
                    // পুরনো ডিভাইস: স্ট্যাটাস আপডেট
                    if (deviceDB.isLocked) {
                        ws.send(JSON.stringify({ command: "LOCKED_BY_ADMIN" }));
                        return ws.close();
                    }
                    deviceDB.status = 'ONLINE';
                    deviceDB.lastSeen = new Date();
                    await deviceDB.save();
                }
                
                connectedDevices.set(mac, ws);
                console.log(`🔌 Device Connected: ${mac}`);
            }

            // ২. স্ট্যাটাস আপডেট (ESP32 থেকে)
            else if (data.type === 'statusUpdate') {
                const p = data.payload;
                const mac = p.macAddress;

                // লাস্ট সিন আপডেট করা (যাতে অফলাইন ফিল্টারে ধরা না পড়ে)
                await Device.updateOne({ macAddress: mac }, { lastSeen: new Date(), status: 'ONLINE' });

                // --- মোটর লজিক ---
                if (p.motorStatus === "ON") {
                    if (!activeMotorSessions.has(mac)) {
                        activeMotorSessions.set(mac, new Date());
                        console.log(`[${mac}] Motor ON`);
                    }
                } 
                else if (p.motorStatus === "OFF") {
                    const startTime = activeMotorSessions.get(mac);
                    if (startTime) {
                        const endTime = new Date();
                        const durationMs = endTime - startTime;
                        
                        // সময় ক্যালকুলেশন
                        const mins = Math.floor(durationMs / 60000);
                        const secs = Math.floor((durationMs % 60000) / 1000);
                        const durationStr = `${mins}m ${secs}s`;
                        
                        // বাংলাদেশ সময়
                        const bdInfo = getBDTime();

                        const newLog = new MotorLog({
                            macAddress: mac,
                            startTime, endTime,
                            duration: durationStr,
                            bdDate: bdInfo.date,
                            bdTime: bdInfo.time
                        });
                        await newLog.save();
                        console.log(`[${mac}] Log Saved: ${durationStr}`);
                        
                        activeMotorSessions.delete(mac);
                    }
                }

                // ইউজারদের কাছে ব্রডকাস্ট করা হবে
                broadcastToWebClients(data);
            }

            // ৩. ইউজার কমান্ড
            else if (data.type === 'command') {
                const targetMac = data.targetMac;
                const dev = await Device.findOne({ macAddress: targetMac });
                
                if (dev && dev.isLocked) return; // লক থাকলে ইগনোর
                
                const targetWs = connectedDevices.get(targetMac);
                if (targetWs && targetWs.readyState === WebSocket.OPEN) {
                    targetWs.send(JSON.stringify({ command: data.command, value: data.value }));
                }
            }
            
            // ৪. লগ ফেচ করা (ড্যাশবোর্ড থেকে)
            else if (data.command === 'GET_LOGS') {
                const mac = data.macAddress;
                const logs = await MotorLog.find({ macAddress: mac }).sort({ createdAt: -1 }).limit(50);
                ws.send(JSON.stringify({ type: 'logListUpdate', payload: logs }));
            }

        } catch (e) { console.error(e); }
    });

    ws.on('close', () => {
        // কানেকশন ক্লিনআপ লজিক প্রয়োজন হলে এখানে যোগ করা যাবে
    });
});

function broadcastToWebClients(msg) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(msg));
        }
    });
}

server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));