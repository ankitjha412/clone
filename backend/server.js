const express = require("express");
const fs = require("fs");
const path = require("path");
const whois = require("whois");
const cors = require("cors");
const readline = require("readline");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const csvFilePath = path.join(__dirname, "urls.csv");
let storedDomains = new Set();

// ** Extracts the Main Domain from a URL **
const extractMainDomain = (inputUrl) => {
  try {
    console.log("🔍 Extracting domain from:", inputUrl);

    if (!inputUrl.startsWith("http://") && !inputUrl.startsWith("https://")) {
      inputUrl = "https://" + inputUrl;
    }

    const parsed = new URL(inputUrl);
    let hostname = parsed.hostname;

    if (hostname.startsWith("www.")) {
      hostname = hostname.substring(4);
    }

    console.log("✅ Extracted Domain:", hostname);
    return hostname;
  } catch (error) {
    console.error("❌ Invalid URL:", inputUrl, "Error:", error);
    return null;
  }
};

// ** Reads CSV & Extracts Domains **
const loadDomains = async () => {
  return new Promise((resolve, reject) => {
    const domains = new Set();
    const rl = readline.createInterface({
      input: fs.createReadStream(csvFilePath),
      crlfDelay: Infinity,
    });

    rl.on("line", (line) => {
      const parts = line.split(",");
      if (parts.length === 2 && parts[1] !== "original_url") {
        const domain = parts[1].trim().toLowerCase();
        domains.add(domain);
      }
    });

    rl.on("close", () => {
      console.log(`✅ Loaded ${domains.size} domains from CSV.`);
      resolve(domains);
    });

    rl.on("error", (error) => {
      console.error("❌ Error reading CSV file:", error);
      reject(error);
    });
  });
};

// ** WHOIS Lookup **
const getWhoisData = async (domain) => {
  return new Promise((resolve) => {
    try {
      whois.lookup(domain, { timeout: 5000 }, (err, data) => {
        if (err) {
          console.error(`❌ WHOIS lookup failed for ${domain}:`, err);
          resolve("WHOIS data unavailable due to server error.");
        } else {
          resolve(data || "No WHOIS data found.");
        }
      });
    } catch (error) {
      console.error(`❌ WHOIS error for ${domain}:`, error);
      resolve("WHOIS data unavailable.");
    }
  });
};

// ** Levenshtein Distance Algorithm (Measures Similarity) **
const levenshteinDistance = (a, b) => {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1));
      }
    }
  }

  return (1 - matrix[b.length][a.length] / Math.max(a.length, b.length)) * 100;
};

// ** API Endpoint to Check a Suspect URL **
app.post("/check-clone", async (req, res) => {
  try {
    console.log("📥 Incoming Request Body:", req.body);

    let { suspect_url } = req.body;
    if (!suspect_url) {
      console.log("❌ No URL received in the request.");
      return res.status(400).json({ error: "❌ URL is required." });
    }

    let suspect_domain = extractMainDomain(suspect_url);
    if (!suspect_domain) {
      console.log("❌ Invalid URL format:", suspect_url);
      return res.status(400).json({ error: "❌ Invalid URL format." });
    }

    let bestMatchDomain = null;
    let highestSimilarity = 0;

    if (storedDomains.has(suspect_domain)) {
      console.log(`✅ ${suspect_domain} is a verified domain. No clone detected.`);
      return res.json({
        suspect_url,
        extracted_domain: suspect_domain,
        best_match_domain: suspect_domain,
        matching_accuracy: "100%",
        isClone: false,
        whoisData: "WHOIS lookup skipped for verified domains.",
      });
    }

    // Check for similar-looking domains
    for (let storedDomain of storedDomains) {
      let similarity = levenshteinDistance(suspect_domain, storedDomain);
      if (similarity > highestSimilarity) {
        highestSimilarity = similarity;
        bestMatchDomain = storedDomain;
      }
    }

    const whoisData = await getWhoisData(suspect_domain);

    res.json({
      suspect_url,
      extracted_domain: suspect_domain,
      best_match_domain: bestMatchDomain,
      matching_accuracy: `${highestSimilarity.toFixed(2)}%`,
      isClone: highestSimilarity > 80,
      whoisData,
    });

  } catch (error) {
    console.error("❌ Error processing request:", error);
    res.status(500).json({ error: "❌ Internal Server Error" });
  }
});

// ** Load CSV Before Starting the Server **
(async () => {
  try {
    storedDomains = await loadDomains();
    console.log("🚀 Server starting...");
    app.listen(5000, () => console.log("✅ Server running on port 5000"));
  } catch (error) {
    console.error("❌ Failed to load CSV:", error);
  }
})();
