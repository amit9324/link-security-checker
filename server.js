const express = require("express");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

// --------------------------------------------------
// Middleware
// --------------------------------------------------

app.use(express.json({ limit: "10kb" }));

// Serve frontend
app.use(express.static(path.join(__dirname, "public")));

// --------------------------------------------------
// Homepage
// --------------------------------------------------

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --------------------------------------------------
// Helper Functions
// --------------------------------------------------

function addFinding(findings, level, points, text) {
    findings.push({
        level,
        points,
        text
    });
}

function isIPv4(hostname) {
    const ipv4Pattern =
        /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

    return ipv4Pattern.test(hostname);
}

function isIPv6(hostname) {
    return hostname.includes(":");
}

function countOccurrences(text, character) {
    return text.split(character).length - 1;
}

// --------------------------------------------------
// Suspicious keywords
// --------------------------------------------------

const suspiciousKeywords = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "validate",
    "validation",
    "password",
    "passwd",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "wallet",
    "bank",
    "banking",
    "payment",
    "invoice",
    "billing",
    "recover",
    "recovery",
    "unlock",
    "suspended",
    "urgent",
    "free",
    "bonus",
    "gift",
    "reward",
    "claim",
    "crypto",
    "bitcoin",
    "airdrop"
];

// --------------------------------------------------
// Suspicious TLDs
// --------------------------------------------------

const suspiciousTLDs = [
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "click",
    "work",
    "support",
    "zip",
    "mov",
    "country",
    "download"
];

// --------------------------------------------------
// Known suspicious domains
//
// Add confirmed malicious domains here.
// Do NOT put ordinary websites here.
// --------------------------------------------------

const knownSuspiciousDomains = [
    // Example:
    // "example-phishing-domain.com"
];

// --------------------------------------------------
// Main URL Security API
// --------------------------------------------------

app.post("/api/check", (req, res) => {

    const input = String(req.body.url || "").trim();

    // --------------------------------------------------
    // Validate input
    // --------------------------------------------------

    if (!input) {
        return res.status(400).json({
            error: "Please enter a URL."
        });
    }

    if (input.length > 2048) {
        return res.status(400).json({
            error: "URL is too long."
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

    // Only HTTP/HTTPS URLs are allowed
    if (url.protocol !== "http:" && url.protocol !== "https:") {
        return res.status(400).json({
            error: "Only HTTP and HTTPS URLs are supported."
        });
    }

    // --------------------------------------------------
    // Variables
    // --------------------------------------------------

    let score = 0;

    const findings = [];

    const hostname = url.hostname.toLowerCase();
    const fullUrl = url.href.toLowerCase();

    const domainParts = hostname.split(".").filter(Boolean);

    // --------------------------------------------------
    // 1. HTTPS check
    // --------------------------------------------------

    if (url.protocol === "https:") {

        addFinding(
            findings,
            "good",
            0,
            "HTTPS is enabled."
        );

    } else {

        score += 15;

        addFinding(
            findings,
            "warning",
            15,
            "The URL does not use HTTPS."
        );
    }

    // --------------------------------------------------
    // 2. IP address check
    // --------------------------------------------------

    if (isIPv4(hostname) || isIPv6(hostname)) {

        score += 25;

        addFinding(
            findings,
            "danger",
            25,
            "The URL uses an IP address instead of a normal domain name."
        );

    } else {

        addFinding(
            findings,
            "good",
            0,
            "A domain name is being used."
        );
    }

    // --------------------------------------------------
    // 3. @ symbol
    // --------------------------------------------------

    if (input.includes("@")) {

        score += 25;

        addFinding(
            findings,
            "danger",
            25,
            "The URL contains an @ symbol, which can be used to disguise the real destination."
        );
    }

    // --------------------------------------------------
    // 4. Punycode
    // --------------------------------------------------

    if (hostname.includes("xn--")) {

        score += 20;

        addFinding(
            findings,
            "warning",
            20,
            "The domain contains Punycode, which can sometimes be used in look-alike domains."
        );
    }

    // --------------------------------------------------
    // 5. URL length
    // --------------------------------------------------

    if (input.length > 200) {

        score += 10;

        addFinding(
            findings,
            "warning",
            10,
            "The URL is unusually long."
        );
    }

    // --------------------------------------------------
    // 6. Very long hostname
    // --------------------------------------------------

    if (hostname.length > 80) {

        score += 10;

        addFinding(
            findings,
            "warning",
            10,
            "The domain name is unusually long."
        );
    }

    // --------------------------------------------------
    // 7. Excessive subdomains
    // --------------------------------------------------

    if (domainParts.length >= 5) {

        score += 15;

        addFinding(
            findings,
            "warning",
            15,
            "The URL contains an unusually large number of subdomains."
        );

    } else if (domainParts.length === 4) {

        score += 5;

        addFinding(
            findings,
            "info",
            5,
            "The URL contains several subdomains."
        );
    }

    // --------------------------------------------------
    // 8. Suspicious keywords
    // --------------------------------------------------

    const foundKeywords = suspiciousKeywords.filter(keyword =>
        fullUrl.includes(keyword)
    );

    if (foundKeywords.length > 0) {

        const keywordPoints =
            Math.min(foundKeywords.length * 5, 20);

        score += keywordPoints;

        addFinding(
            findings,
            "warning",
            keywordPoints,
            "Suspicious security-related or reward-related keywords detected: " +
            foundKeywords.join(", ")
        );
    }

    // --------------------------------------------------
    // 9. Suspicious TLD
    // --------------------------------------------------

    const tld = domainParts.length > 1
        ? domainParts[domainParts.length - 1]
        : "";

    if (suspiciousTLDs.includes(tld)) {

        score += 10;

        addFinding(
            findings,
            "warning",
            10,
            `The domain uses the .${tld} top-level domain, which can be abused for malicious websites.`
        );
    }

    // --------------------------------------------------
    // 10. Too many hyphens
    // --------------------------------------------------

    const hyphenCount = countOccurrences(hostname, "-");

    if (hyphenCount >= 4) {

        score += 10;

        addFinding(
            findings,
            "warning",
            10,
            "The domain contains an unusually high number of hyphens."
        );
    }

    // --------------------------------------------------
    // 11. Too many numbers
    // --------------------------------------------------

    const numberMatches = hostname.match(/\d/g) || [];
    const numberCount = numberMatches.length;

    if (numberCount >= 5) {

        score += 10;

        addFinding(
            findings,
            "warning",
            10,
            "The domain contains an unusually high number of numbers."
        );
    }

    // --------------------------------------------------
    // 12. Suspicious characters
    // --------------------------------------------------

    if (/[<>{}\\|^`$begin:math:display$$end:math:display$]/.test(input)) {

        score += 15;

        addFinding(
            findings,
            "danger",
            15,
            "The URL contains unusual characters."
        );
    }

    // --------------------------------------------------
    // 13. Encoded URL characters
    // --------------------------------------------------

    const encodedCount = (input.match(/%[0-9a-f]{2}/gi) || []).length;

    if (encodedCount >= 5) {

        score += 10;

        addFinding(
            findings,
            "warning",
            10,
            "The URL contains many encoded characters."
        );
    }

    // --------------------------------------------------
    // 14. Repeated separators
    // --------------------------------------------------

    if (
        input.includes("..") ||
        input.includes("//") ||
        input.includes("--")
    ) {

        score += 5;

        addFinding(
            findings,
            "info",
            5,
            "The URL contains repeated separators."
        );
    }

    // --------------------------------------------------
    // 15. Suspicious port
    // --------------------------------------------------

    const suspiciousPorts = [
        "21",
        "22",
        "23",
        "25",
        "445",
        "3389",
        "8080",
        "8888"
    ];

    if (
        url.port &&
        suspiciousPorts.includes(url.port)
    ) {

        score += 10;

        addFinding(
            findings,
            "warning",
            10,
            `The URL uses port ${url.port}, which is unusual for a normal public website.`
        );
    }

    // --------------------------------------------------
    // 16. Username in URL
    // --------------------------------------------------

    if (url.username) {

        score += 15;

        addFinding(
            findings,
            "warning",
            15,
            "The URL contains a username before the domain."
        );
    }

    // --------------------------------------------------
    // 17. Very deep URL path
    // --------------------------------------------------

    const pathParts = url.pathname
        .split("/")
        .filter(Boolean);

    if (pathParts.length >= 8) {

        score += 10;

        addFinding(
            findings,
            "warning",
            10,
            "The URL contains an unusually deep path."
        );
    }

    // --------------------------------------------------
    // 18. Suspicious query parameters
    // --------------------------------------------------

    const suspiciousParameters = [
        "redirect",
        "redirect_url",
        "return",
        "return_url",
        "next",
        "url",
        "continue",
        "destination"
    ];

    const foundParameters = [];

    for (const parameter of suspiciousParameters) {

        if (url.searchParams.has(parameter)) {
            foundParameters.push(parameter);
        }
    }

    if (foundParameters.length > 0) {

        score += 10;

        addFinding(
            findings,
            "warning",
            10,
            "The URL contains redirect-related parameters: " +
            foundParameters.join(", ")
        );
    }

    // --------------------------------------------------
    // 19. Domain resembles a login/payment target
    // --------------------------------------------------

    const sensitiveWords = [
        "paypal",
        "microsoft",
        "apple",
        "google",
        "facebook",
        "instagram",
        "amazon",
        "netflix",
        "whatsapp",
        "telegram",
        "bank"
    ];

    const foundSensitiveWords = sensitiveWords.filter(word =>
        hostname.includes(word)
    );

    if (foundSensitiveWords.length > 0) {

        // Only add a warning when the word appears in
        // a suspicious-looking hostname.
        if (
            hostname.includes("-") ||
            hostname.split(".").length >= 3 ||
            hostname.includes("login") ||
            hostname.includes("verify") ||
            hostname.includes("secure")
        ) {

            score += 20;

            addFinding(
                findings,
                "danger",
                20,
                "The domain contains a brand/service name combined with suspicious URL patterns: " +
                foundSensitiveWords.join(", ")
            );
        }
    }

    // --------------------------------------------------
    // 20. Known suspicious domain
    // --------------------------------------------------

    if (knownSuspiciousDomains.includes(hostname)) {

        score += 80;

        addFinding(
            findings,
            "danger",
            80,
            "This domain is present in the application's known suspicious-domain list."
        );
    }

    // --------------------------------------------------
    // Calculate final score
    // --------------------------------------------------

    score = Math.min(score, 100);

    // --------------------------------------------------
    // Determine risk
    // --------------------------------------------------

    let risk;
    let riskLevel;

    if (score <= 20) {

        risk = "LOW RISK";
        riskLevel = "low";

    } else if (score <= 50) {

        risk = "SUSPICIOUS";
        riskLevel = "medium";

    } else {

        risk = "HIGH RISK";
        riskLevel = "high";
    }

    // --------------------------------------------------
    // If dangerous findings exist, ensure high risk
    // --------------------------------------------------

    const dangerousFinding = findings.some(
        finding => finding.level === "danger"
    );

    if (dangerousFinding && score >= 50) {

        risk = "HIGH RISK";
        riskLevel = "high";
    }

    // --------------------------------------------------
    // Final response
    // --------------------------------------------------

    res.json({

        success: true,

        url: url.href,

        hostname: hostname,

        protocol: url.protocol,

        score: score,

        risk: risk,

        riskLevel: riskLevel,

        findings: findings,

        analysis: {
            usesHTTPS: url.protocol === "https:",
            isIPAddress:
                isIPv4(hostname) || isIPv6(hostname),
            usesPunycode:
                hostname.includes("xn--"),
            subdomainCount:
                Math.max(domainParts.length - 2, 0),
            domainLength:
                hostname.length,
            urlLength:
                input.length,
            keywordMatches:
                foundKeywords,
            suspiciousTLD:
                suspiciousTLDs.includes(tld),
            encodedCharacters:
                encodedCount
        },

        note:
            "This result is based on URL heuristics and does not guarantee that the website is safe or malicious. Do not enter passwords, payment information, or other sensitive information into a suspicious website."
    });
});

// --------------------------------------------------
// 404 handler
// --------------------------------------------------

app.use((req, res) => {

    res.status(404).json({
        error: "Endpoint not found."
    });
});

// --------------------------------------------------
// Error handler
// --------------------------------------------------

app.use((err, req, res, next) => {

    console.error(err);

    res.status(500).json({
        error: "Internal server error."
    });
});

// --------------------------------------------------
// Start server
// --------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {

    console.log(
        `Link Security Checker running on port ${PORT}`
    );

});
