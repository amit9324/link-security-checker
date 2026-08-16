const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Serve the website
app.use(express.static(path.join(__dirname, "public")));

// Homepage
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// URL security checker
app.post("/api/check", (req, res) => {

    const input = req.body.url;

    if (!input) {
        return res.status(400).json({
            error: "Please enter a URL."
        });
    }

    let url;

    try {
        url = new URL(input);
    } catch (error) {
        return res.status(400).json({
            error: "Invalid URL. Please enter a valid URL."
        });
    }

    let score = 0;
    const findings = [];

    // HTTPS check
    if (url.protocol === "https:") {
        findings.push({
            level: "good",
            text: "HTTPS is enabled."
        });
    } else {
        score += 20;

        findings.push({
            level: "warning",
            text: "The URL does not use HTTPS."
        });
    }

    // IP address check
    const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(url.hostname)) {
        score += 20;

        findings.push({
            level: "warning",
            text: "The URL uses an IP address instead of a domain."
        });
    } else {
        findings.push({
            level: "good",
            text: "A normal domain name is being used."
        });
    }

    // URL length
    if (input.length > 150) {
        score += 10;

        findings.push({
            level: "warning",
            text: "The URL is unusually long."
        });
    }

    // @ symbol
    if (input.includes("@")) {
        score += 15;

        findings.push({
            level: "warning",
            text: "The URL contains an @ symbol."
        });
    }

    // Suspicious keywords
    const keywords = [
        "login",
        "verify",
        "verification",
        "password",
        "account",
        "update",
        "free",
        "bonus",
        "gift",
        "claim"
    ];

    const lowerUrl = input.toLowerCase();

    const foundKeywords = keywords.filter(keyword =>
        lowerUrl.includes(keyword)
    );

    if (foundKeywords.length > 0) {
        score += Math.min(foundKeywords.length * 5, 15);

        findings.push({
            level: "warning",
            text: "Suspicious keyword detected: " +
                foundKeywords.join(", ")
        });
    }

    // Punycode
    if (url.hostname.includes("xn--")) {
        score += 15;

        findings.push({
            level: "warning",
            text: "The domain contains Punycode."
        });
    }

    score = Math.min(score, 100);

    let risk;

    if (score <= 20) {
        risk = "LOW RISK";
    } else if (score <= 50) {
        risk = "SUSPICIOUS";
    } else {
        risk = "HIGH RISK";
    }

    res.json({
        valid: true,
        url: url.href,
        hostname: url.hostname,
        score: score,
        risk: risk,
        findings: findings,
        note: "This is a heuristic check and does not guarantee that a website is safe."
    });
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Link Security Checker running on port ${PORT}`);
});