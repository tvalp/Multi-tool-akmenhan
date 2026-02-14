const express = require("express");
const base32 = require("hi-base32");
const CryptoJS = require("crypto-js");
const axios = require("axios");
const xml2js = require("xml2js");
const session = require("express-session");
const whois = require("whois-json");
const crypto = require("crypto");

const app = express();
const PORT = 3000;

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: "superSecretKey",
    resave: false,
    saveUninitialized: true
}));

/* =======================
   HOME
======================= */
app.get("/", (req, res) => {
    res.render("index", {
        result: null,
        analysis: null,
        aesResult: null,
        hashResult: null,
        scanResult: null,
        history: req.session.history || []
    });
});

/* =======================
   ENCODER
======================= */
app.post("/convert", (req, res) => {
    const { input, type } = req.body;
    let result;

    try {
        switch (type) {
            case "base64-encode":
                result = Buffer.from(input).toString("base64");
                break;
            case "base64-decode":
                result = Buffer.from(input, "base64").toString("utf-8");
                break;
            case "base32-encode":
                result = base32.encode(input);
                break;
            case "base32-decode":
                result = base32.decode(input);
                break;
            case "hex":
                result = Buffer.from(input).toString("hex");
                break;
            case "binary":
                result = Buffer.from(input)
                    .toString("binary")
                    .split("")
                    .map(c => c.charCodeAt(0).toString(2).padStart(8, "0"))
                    .join(" ");
                break;
            case "sha256":
                result = CryptoJS.SHA256(input).toString();
                break;
            case "md5":
                result = CryptoJS.MD5(input).toString();
                break;
        }
    } catch {
        result = "Dönüştürme hatası";
    }

    if (!req.session.history) req.session.history = [];
    req.session.history.unshift({ type, input });
    req.session.history = req.session.history.slice(0, 5);

    res.render("index", {
        result,
        analysis: null,
        aesResult: null,
        hashResult: null,
        scanResult: null,
        history: req.session.history
    });
});

/* =======================
   AES
======================= */
app.post("/aes", (req, res) => {
    const { input, key, mode } = req.body;
    let aesResult;

    try {
        if (mode === "encrypt") {
            aesResult = CryptoJS.AES.encrypt(input, key).toString();
        } else {
            const bytes = CryptoJS.AES.decrypt(input, key);
            aesResult = bytes.toString(CryptoJS.enc.Utf8);
        }
    } catch {
        aesResult = "AES işlem hatası";
    }

    res.render("index", {
        result: null,
        analysis: null,
        aesResult,
        hashResult: null,
        scanResult: null,
        history: req.session.history || []
    });
});

/* =======================
   SHA256 HASH TOOL
======================= */
app.post("/hash", (req, res) => {
    const { password } = req.body;

    let hashResult;
    try {
        hashResult = crypto.createHash("sha256")
            .update(password)
            .digest("hex");
    } catch {
        hashResult = "Hash oluşturulamadı";
    }

    res.render("index", {
        result: null,
        analysis: null,
        aesResult: null,
        hashResult,
        scanResult: null,
        history: req.session.history || []
    });
});

/* =======================
   URL SCANNER
======================= */
app.post("/scan", async (req, res) => {
    const { url } = req.body;

    try {
        const parsed = new URL(url);
        const base = parsed.origin;

        const scanResult = {
            subdomains: [
                "api." + parsed.hostname,
                "admin." + parsed.hostname,
                "dev." + parsed.hostname
            ],
            endpoints: [
                base + "/login",
                base + "/admin",
                base + "/api",
                base + "/dashboard"
            ]
        };

        res.render("index", {
            result: null,
            analysis: null,
            aesResult: null,
            hashResult: null,
            scanResult,
            history: req.session.history || []
        });

    } catch {
        res.render("index", {
            result: null,
            analysis: null,
            aesResult: null,
            hashResult: null,
            scanResult: { error: "URL taranamadı" },
            history: req.session.history || []
        });
    }
});

/* =======================
   WEBSITE ANALYZER
======================= */
app.post("/analyze", async (req, res) => {
    const { url } = req.body;

    try {
        const parsed = new URL(url);
        const base = parsed.origin;

        const response = await axios.get(url);
        const headers = response.headers;

        const securityHeaders = {
            csp: headers["content-security-policy"],
            hsts: headers["strict-transport-security"],
            xframe: headers["x-frame-options"],
            xcontent: headers["x-content-type-options"]
        };

        let score = 0;
        let recommendations = [];

        Object.keys(securityHeaders).forEach(key => {
            if (securityHeaders[key]) {
                score += 25;
            } else {
                recommendations.push(`${key} header eksik`);
            }
        });

        /* ROBOTS */
        let robotsData = [];
        try {
            const robots = await axios.get(base + "/robots.txt");
            robotsData = robots.data
                .split("\n")
                .filter(line => line.toLowerCase().startsWith("disallow"));
        } catch {}

        /* SITEMAP */
        let sitemapUrls = [];
        try {
            const sitemap = await axios.get(base + "/sitemap.xml");
            const parsedXml = await xml2js.parseStringPromise(sitemap.data);
            sitemapUrls = parsedXml.urlset.url.map(u => u.loc[0]);
        } catch {}

        /* WHOIS */
        let whoisData = {};
        try {
            whoisData = await whois(parsed.hostname);
        } catch {}

        res.render("index", {
            result: null,
            aesResult: null,
            hashResult: null,
            scanResult: null,
            history: req.session.history || [],
            analysis: {
                protocol: parsed.protocol,
                hostname: parsed.hostname,
                status: response.status,
                securityHeaders,
                robotsData,
                sitemapUrls,
                whois: {
                    registrar: whoisData.registrar || "N/A",
                    creationDate: whoisData.creationDate || "N/A"
                },
                score,
                recommendations
            }
        });

    } catch {
        res.render("index", {
            result: null,
            aesResult: null,
            hashResult: null,
            scanResult: null,
            history: req.session.history || [],
            analysis: { error: "URL analiz edilemedi" }
        });
    }
});

app.listen(PORT, () => {
    console.log(`Server çalışıyor: http://localhost:${PORT}`);
});
