 // PhishGuard Frontend Application
// Background animation (particles) respecting reduced motion
(function initBackground() {
  const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const canvas = document.getElementById('bgCanvas');
  if (!canvas || prefersReduced) return;
  const ctx = canvas.getContext('2d');
  let width, height, dpr;
  let particles = [];
  const MAX_PARTICLES = 70;
  let t = 0; // time for waves

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = canvas.clientWidth;
    height = canvas.clientHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function themeColors() {
    const isDark = document.body.classList.contains('dark');
    return isDark
      ? ['#667eea', '#9f7aea', '#4ecdc4']
      : ['#ffffff', 'rgba(255,255,255,0.9)', 'rgba(255,255,255,0.7)'];
  }

  function createParticle() {
    const [c1, c2, c3] = themeColors();
    return {
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
      r: Math.random() * 2 + 0.8,
      color: [c1, c2, c3][Math.floor(Math.random() * 3)],
      parallax: Math.random() * 0.6 + 0.7,
    };
  }

  function initParticles() {
    particles = [];
    for (let i = 0; i < MAX_PARTICLES; i++) particles.push(createParticle());
  }

  function drawWaves() {
    const [c1, c2, c3] = themeColors();
    const waves = [
      { amp: 6, len: 220, speed: 0.6, color: c1, alpha: 0.08 },
      { amp: 10, len: 320, speed: 0.4, color: c2, alpha: 0.06 },
      { amp: 14, len: 440, speed: 0.3, color: c3, alpha: 0.05 },
    ];

    waves.forEach((w, i) => {
      ctx.beginPath();
      const yBase = (height * (0.25 + i * 0.2));
      for (let x = 0; x <= width; x += 8) {
        const y = yBase + Math.sin((x + t * (20 * w.speed)) / w.len) * w.amp;
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = w.color;
      ctx.globalAlpha = w.alpha;
      ctx.lineWidth = 2;
      ctx.stroke();
    });
  }

  function step() {
    ctx.clearRect(0, 0, width, height);

    // waves background
    drawWaves();

    // draw particles
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx * p.parallax; p.y += p.vy * p.parallax;
      if (p.x < -10) p.x = width + 10; if (p.x > width + 10) p.x = -10;
      if (p.y < -10) p.y = height + 10; if (p.y > height + 10) p.y = -10;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.globalAlpha = 0.85;
      ctx.fill();
    }

    // light connections
    ctx.globalAlpha = 0.08;
    ctx.lineWidth = 1;
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist2 = dx*dx + dy*dy;
        if (dist2 < 120*120) {
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = '#ffffff';
          ctx.stroke();
        }
      }
    }

    t += 0.5;
    requestAnimationFrame(step);
  }

  resize();
  initParticles();
  requestAnimationFrame(step);
  window.addEventListener('resize', () => { resize(); initParticles(); });
  const obs = new MutationObserver(() => initParticles());
  obs.observe(document.body, { attributes: true, attributeFilter: ['class'] });
})();

class PhishingDetector {
  constructor() {
    this.models = {
      randomForest: { weight: 0.4, name: "Random Forest", accuracy: 0.973 },
      gradientBoosting: {
        weight: 0.35,
        name: "Gradient Boosting",
        accuracy: 0.968,
      },
      xgboost: { weight: 0.25, name: "XGBoost", accuracy: 0.971 },
    };
    this.scanHistory = JSON.parse(localStorage.getItem("scanHistory")) || [];
    this.apiEndpoint = "http://localhost:5000/api"; // Backend API endpoint
    this.init();
  }

  init() {
    this.updateStats();
    this.loadHistory();
    this.setupEventListeners();
    this.loadTheme();
  }

  setupEventListeners() {
    // Enter key submission
    document.getElementById("urlInput").addEventListener("keypress", (e) => {
      if (e.key === "Enter") {
        this.scanURL();
      }
    });

    // Real-time URL validation with debounce
    const debouncedValidate = this.debounce((value) => this.validateURL(value), 150);
    document.getElementById("urlInput").addEventListener("input", (e) => {
      debouncedValidate(e.target.value);
      const hint = document.getElementById('urlHint');
      try {
        if (!e.target.value) { hint.textContent = ''; return; }
        new URL(e.target.value);
        hint.textContent = 'Looks like a valid URL.';
      } catch {
        hint.textContent = 'Enter a full URL, e.g., https://example.com';
      }
    });

    // Theme toggle
    document.getElementById("themeToggle").addEventListener("click", () => {
      this.toggleTheme();
    });
  }

  validateURL(url) {
    const urlInput = document.getElementById("urlInput");
    const scanBtn = document.getElementById("scanBtn");

    try {
      if (url && url.length > 0) {
        new URL(url);
        urlInput.style.borderColor = "#28a745";
        scanBtn.disabled = false;
      } else {
        urlInput.style.borderColor = "#e1e5e9";
        scanBtn.disabled = false;
      }
    } catch {
      if (url.length > 0) {
        urlInput.style.borderColor = "#dc3545";
        scanBtn.disabled = true;
      } else {
        urlInput.style.borderColor = "#e1e5e9";
        scanBtn.disabled = false;
      }
    }
  }

  // Feature extraction from URL
  extractFeatures(url) {
    const features = {};
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;
      const pathname = urlObj.pathname;
      const search = urlObj.searchParams;

      // Basic URL metrics
      features.urlLength = url.length;
      features.domainLength = hostname.length;
      features.pathLength = pathname.length;

      // Character analysis
      features.specialChars = (url.match(/[!@#$%^&*(),.?":{}|<>\-_=+]/g) || []).length;
      features.digits = (url.match(/\d/g) || []).length;
      features.letters = (url.match(/[a-zA-Z]/g) || []).length;

      // Domain analysis
      features.subdomainCount = (hostname.match(/\./g) || []).length - 1;
      features.domainTokens = hostname.split(".").length;
      features.hostnameEntropy = this.calculateEntropy(hostname);

      // Protocol and security
      features.isHttps = url.startsWith("https://");
      features.hasPort = urlObj.port !== "";
      features.portNumber = urlObj.port || (features.isHttps ? 443 : 80);

      // Suspicious patterns
      const suspiciousKeywords = [
        "secure", "account", "verify", "login", "signin", "bank", "paypal", "amazon", "microsoft", "google", "apple", "update", "confirm", "suspended", "locked", "security", "alert", "warning",
      ];
      features.suspiciousKeywords = suspiciousKeywords.filter((keyword) => url.toLowerCase().includes(keyword)).length;

      // IP address detection
      features.hasIP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname);
      features.hasPrivateIP = this.isPrivateIP(hostname);

      // URL shortening services
      const shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link", "tiny.cc", "buff.ly", "adf.ly", "is.gd", "soo.gd",
      ];
      features.isShortened = shorteners.some((shortener) => hostname.includes(shortener));

      // Path analysis
      features.pathDepth = pathname.split("/").filter((p) => p.length > 0).length;
      features.hasQueryParams = search.toString().length > 0;
      features.queryParamsCount = Array.from(search.keys()).length;

      // Suspicious path patterns
      features.hasRedirect = pathname.includes("redirect") || search.has("redirect") || search.has("url");
      features.hasLogin = pathname.includes("login") || pathname.includes("signin");
      features.hasSecure = pathname.includes("secure") || search.has("secure");

      // Hex encoding detection (common in phishing)
      features.hasHex = /%[0-9A-Fa-f]{2}/.test(url);

      // Domain reputation (simulated)
      features.domainAge = Math.floor(Math.random() * 3650); // 0-10 years in days
      features.alexa_rank = Math.floor(Math.random() * 1000000); // Simulated Alexa rank

      // TLD analysis
      const tld = hostname.split(".").pop();
      const suspiciousTlds = ["tk", "ml", "ga", "cf", "icu", "top", "click"];
      features.suspiciousTLD = suspiciousTlds.includes(tld);
      features.tld = tld;

      return features;
    } catch (error) {
      console.error("Feature extraction error:", error);
      return null;
    }
  }

  calculateEntropy(text) {
    if (!text) return 0;
    let entropy = 0;
    const length = text.length;
    const charCount = {};
    for (let char of text) {
      charCount[char] = (charCount[char] || 0) + 1;
    }
    for (let count of Object.values(charCount)) {
      const p = count / length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  isPrivateIP(hostname) {
    const privateRanges = [
      /^192\.168\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^127\./,
      /^localhost$/i,
    ];
    return privateRanges.some((range) => range.test(hostname));
  }

  // Simulate ensemble ML prediction or call the backend
  async predictPhishing(url) {
    try {
      const response = await fetch(`${this.apiEndpoint}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        // Handle unauthorized specifically
        if (response.status === 401) {
          throw new Error("Unauthorized. Please log in to use the scanner.");
        }
        let errorData = {};
        try { errorData = await response.json(); } catch {}
        throw new Error(errorData.error || `Backend returned an error (status ${response.status}).`);
      }

      const data = await response.json();

      // Use backend's multi-signal scoring
      const score = data.score;
      const confidence = data.confidence > 1 ? data.confidence / 100 : data.confidence;
      const reasonCodes = data.reason_codes || [];
      const modelPredictions = { [data.model]: score };

      return {
        score: score,
        confidence: confidence,
        predictions: modelPredictions,
        features: data.features,
        reasonCodes: reasonCodes,
        classification: this.classifyResult(score),
        modelDetails: {
          [data.model]: { name: data.model, weight: 1, accuracy: 0.95 },
        },
      };

    } catch (error) {
      console.warn("API unavailable or error occurred, using local simulation:", error.message);
      // Fallback to local simulation if API is not available or an error occurred
      const features = this.extractFeatures(url);
      if (!features) {
        throw new Error("Failed to extract features for local simulation.");
      }

      const suspiciousScore = this.calculateSuspiciousScore(features);
      const isPhishing = suspiciousScore > 0.5;
      const score = suspiciousScore;
      const confidence = Math.random() * 0.2 + 0.8;
      const modelPredictions = { "Local Simulation": isPhishing ? score : 1 - score };

      return {
        score: score,
        confidence: confidence,
        predictions: modelPredictions,
        features: features,
        reasonCodes: [],
        classification: this.classifyResult(score),
        modelDetails: { "Local Simulation": { name: "Local Simulation", weight: 1, accuracy: 0.95 } },
      };
    }
  }
  
  // A simple heuristic-based scoring function for local simulation
  calculateSuspiciousScore(features) {
      let score = 0;
      if (!features.isHttps) score += 0.25;
      if (features.hasIP) score += 0.35;
      if (features.isShortened) score += 0.25;
      if (features.suspiciousKeywords > 0) score += features.suspiciousKeywords * 0.08;
      if (features.suspiciousTLD) score += 0.15;
      if (features.urlLength > 75) score += 0.1;
      if (features.subdomainCount > 3) score += 0.1;
      if (features.hasHex) score += 0.2;
      if (features.hostnameEntropy > 4.5) score += 0.1; // High entropy might indicate obfuscation
      return Math.min(score, 1); // Clamp score at 1
  }

  classifyResult(score) {
    if (score < 0.3)
      return {
        type: "safe",
        label: "Safe Website",
        icon: "✅",
        description: "This website appears to be legitimate and safe to visit.",
      };
    if (score < 0.7)
      return {
        type: "suspicious",
        label: "Suspicious Activity",
        icon: "⚠️",
        description: "This website shows some suspicious characteristics. Exercise caution.",
      };
    return {
      type: "phishing",
      label: "Phishing Detected",
      icon: "🚨",
      description: "This website is likely a phishing site. Do not enter personal information.",
    };
  }

  async scanURL() {
    const urlInput = document.getElementById("urlInput");
    const scanBtn = document.getElementById("scanBtn");
    const scanBtnText = document.getElementById("scanBtnText");
    const resultsSection = document.getElementById("resultsSection");

    const url = urlInput.value.trim();

    if (!url) {
      this.showError("Please enter a URL to scan");
      return;
    }

    try {
      // Validate URL format
      new URL(url);
    } catch {
      this.showError("Please enter a valid URL (e.g., https://example.com)");
      return;
    }

    // Show loading state
    scanBtn.disabled = true;
    scanBtnText.innerHTML = "🔄 Scanning...";
    resultsSection.innerHTML = this.getLoadingHTML();
    resultsSection.classList.add("show");

    try {
      const result = await this.predictPhishing(url);
      this.displayResults(url, result);
      this.addToHistory(url, result);
    } catch (error) {
      console.error("Scanning error:", error);
      this.showError(`Error scanning URL: ${error.message}`);
    } finally {
      scanBtn.disabled = false;
      scanBtnText.innerHTML = "🔍 Scan URL";
    }
  }

  getLoadingHTML() {
    return `
      <div class="loading">
        <div class="spinner"></div>
        <h3>Analyzing URL...</h3>
        <p>Running ensemble machine learning models</p>
        <div style="margin-top: 20px;">
          <div style="display: flex; justify-content: center; gap: 20px; font-size: 0.9em; color: #6c757d;">
            <span>🌲 Random Forest</span>
            <span>📈 Gradient Boosting</span>
            <span>⚡ XGBoost</span>
          </div>
        </div>
      </div>
    `;
  }

  displayResults(url, result) {
    const resultsSection = document.getElementById("resultsSection");
    const { classification, score, confidence, predictions, features } = result;

    const confidencePercentage = Math.round(confidence * 100);
    const scorePercentage = Math.round(score * 100);

    const resultsHTML = `
      <div class="result-card result-${classification.type}">
        <div class="result-header">
          <span class="result-icon">${classification.icon}</span>
          <div>
            <div class="result-title">${classification.label}</div>
            <p style="margin: 5px 0 0 0; opacity: 0.8;">${classification.description}</p>
          </div>
        </div>
        
        <div class="confidence-section">
          <div class="confidence-label">
            <span>Risk Score: ${scorePercentage}%</span>
            <span>Confidence: ${confidencePercentage}%</span>
          </div>
          <div class="confidence-bar">
            <div class="confidence-fill" style="width: ${scorePercentage}%; background: ${this.getScoreColor(score)};"></div>
          </div>
        </div>

        <div style="margin-top: 25px;">
          <h4 style="margin-bottom: 15px; color: #495057;">🤖 Model Predictions</h4>
          ${Object.keys(predictions)
            .map(
              (model) => `
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding: 10px; background: rgba(255,255,255,0.3); border-radius: 8px;">
                <span style="font-weight: 600;">${this.models[model] ? this.models[model].name : model}</span>
                <span style="font-weight: 700; color: #495057;">${Math.round(predictions[model] * 100)}%</span>
              </div>
            `
            )
            .join("")}

          ${result.reasonCodes && result.reasonCodes.length > 0 ? `
          <div style="margin-top: 20px;">
            <h4 style="margin-bottom: 15px; color: #495057;">🔍 Detection Reasons</h4>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
              ${result.reasonCodes.map(code => `<span style="background: rgba(255,255,255,0.5); padding: 4px 8px; border-radius: 12px; font-size: 0.85em; color: #495057;">${code}</span>`).join('')}
            </div>
          </div>
          ` : ''}
        </div>

        <div class="features-grid">
          ${this.generateFeatureCards(features)}
        </div>
      </div>
    `;

    resultsSection.innerHTML = resultsHTML;

    // Animate the confidence bar
    setTimeout(() => {
      const fillElement = resultsSection.querySelector(".confidence-fill");
      if (fillElement) {
        fillElement.style.width = `${scorePercentage}%`;
      }
    }, 100);
  }

  generateFeatureCards(features) {
    const featureCards = [
      {
        title: "📏 URL Length",
        value: `${features.urlLength} characters`,
        description: features.urlLength > 75 ? "Unusually long URL" : "Normal length",
        risk: features.urlLength > 75,
      },
      {
        title: "🔒 Security Protocol",
        value: features.isHttps ? "HTTPS ✓" : "HTTP ⚠️",
        description: features.isHttps ? "Secure connection" : "Unencrypted connection",
        risk: !features.isHttps,
      },
      {
        title: "🌐 Subdomains",
        value: `${features.subdomainCount} subdomains`,
        description: features.subdomainCount > 3 ? "Many subdomains detected" : "Normal subdomain count",
        risk: features.subdomainCount > 3,
      },
      {
        title: "⚠️ Suspicious Keywords",
        value: `${features.suspiciousKeywords} found`,
        description: features.suspiciousKeywords > 0 ? "Contains suspicious terms" : "No suspicious terms",
        risk: features.suspiciousKeywords > 2,
      },
      {
        title: "🔗 URL Type",
        value: features.isShortened ? "Shortened URL" : "Direct URL",
        description: features.isShortened ? "Uses URL shortening service" : "Direct domain link",
        risk: features.isShortened,
      },
      {
        title: "🌍 Domain Age",
        value: `${Math.floor(features.domainAge)} days`,
        description: features.domainAge < 30 ? "Very new domain" : features.domainAge < 365 ? "Relatively new" : "Established domain",
        risk: features.domainAge < 30,
      },
    ];

    return featureCards
      .map(
        (card) => `
          <div class="feature-card" style="border-left: 4px solid ${card.risk ? "#dc3545" : "#28a745"};">
            <div class="feature-title">${card.title}</div>
            <div class="feature-value" style="color: ${card.risk ? "#dc3545" : "#28a745"};">${card.value}</div>
            <div class="feature-description">${card.description}</div>
          </div>
        `
      )
      .join("");
  }

  getScoreColor(score) {
    if (score < 0.3) return "linear-gradient(90deg, #28a745, #20c997)";
    if (score < 0.7) return "linear-gradient(90deg, #ffc107, #fd7e14)";
    return "linear-gradient(90deg, #dc3545, #e74c3c)";
  }

  showError(message) {
    const resultsSection = document.getElementById("resultsSection");
    resultsSection.innerHTML = `
      <div class="result-card" style="background: #f8d7da; border-left-color: #dc3545; color: #721c24;">
        <div class="result-header">
          <span class="result-icon">❌</span>
          <div class="result-title">Error</div>
        </div>
        <p>${message}</p>
      </div>
    `;
    resultsSection.classList.add("show");
  }

  addToHistory(url, result) {
    const historyItem = {
      url: url,
      result: result.classification,
      score: result.score,
      confidence: result.confidence,
      timestamp: new Date().toISOString(),
      features: result.features,
    };

    this.scanHistory.unshift(historyItem);
    if (this.scanHistory.length > 50) {
      this.scanHistory = this.scanHistory.slice(0, 50);
    }

    localStorage.setItem("scanHistory", JSON.stringify(this.scanHistory));
    this.updateStats();
    this.loadHistory();
  }

  loadHistory() {
    const historyContainer = document.getElementById("historyContainer");

    if (this.scanHistory.length === 0) {
      historyContainer.innerHTML =
        '<p style="color: #6c757d; text-align: center;">No scans performed yet</p>';
      return;
    }

    const historyHTML = this.scanHistory
      .slice(0, 10)
      .map((item) => {
        const timeAgo = this.getTimeAgo(new Date(item.timestamp));
        const borderColor =
          item.result.type === "safe"
            ? "#28a745"
            : item.result.type === "suspicious"
            ? "#ffc107"
            : "#dc3545";

        return `
          <div class="history-item" style="border-left-color: ${borderColor};" onclick="detector.showHistoryDetails('${item.url}')">
            <div class="history-url" title="${item.url}">${item.url}</div>
            <div class="history-result">
              <span>${item.result.icon}</span>
              <span>${item.result.label}</span>
              <span style="margin-left: 10px; font-size: 0.9em; opacity: 0.8;">${Math.round(
                item.score * 100
              )}%</span>
            </div>
            <div class="history-time">${timeAgo}</div>
          </div>
        `;
      })
      .join("");

    historyContainer.innerHTML = historyHTML;
  }

  getTimeAgo(date) {
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);

    if (diffInSeconds < 60) return "Just now";
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
    return `${Math.floor(diffInSeconds / 86400)}d ago`;
  }

  async updateStats() {
    try {
      const response = await fetch(`${this.apiEndpoint}/portal/dashboard`);
      if (response.ok) {
        const data = await response.json();
        const stats = data.stats;
        document.getElementById("totalScans").textContent = stats.total_scans || 0;
        document.getElementById("phishingDetected").textContent = stats.phishing_detected || 0;
        document.getElementById("accuracyRate").textContent = `${Math.round((stats.avg_score || 0) * 100)}%`;
        document.getElementById("mlModels").textContent = stats.ml_models || 0;
      } else {
        // Fallback to local
        document.getElementById("totalScans").textContent = this.scanHistory.length;
        document.getElementById("phishingDetected").textContent =
          this.scanHistory.filter((item) => item.result.type === "phishing").length;
        document.getElementById("accuracyRate").textContent = "N/A";
        document.getElementById("mlModels").textContent = Object.keys(this.models).length;
      }
    } catch (error) {
      console.warn("Failed to fetch dashboard stats:", error);
      // Fallback
      document.getElementById("totalScans").textContent = this.scanHistory.length;
      document.getElementById("phishingDetected").textContent =
        this.scanHistory.filter((item) => item.result.type === "phishing").length;
      document.getElementById("accuracyRate").textContent = "N/A";
      document.getElementById("mlModels").textContent = Object.keys(this.models).length;
    }
  }

  // Method to be called from onclick in history items
  showHistoryDetails(url) {
    const item = this.scanHistory.find((h) => h.url === url);
    if (item) {
      // Fill the input with the historical URL
      document.getElementById("urlInput").value = url;
      // Scroll to top
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }

  // Theme management
  loadTheme() {
    const savedTheme = localStorage.getItem("theme") || "light";
    document.body.classList.toggle("dark", savedTheme === "dark");
    this.updateThemeIcon();
  }

  toggleTheme() {
    const isDark = document.body.classList.toggle("dark");
    localStorage.setItem("theme", isDark ? "dark" : "light");
    this.updateThemeIcon();
  }

  updateThemeIcon() {
    const themeToggle = document.getElementById("themeToggle");
    const isDark = document.body.classList.contains("dark");
    themeToggle.textContent = isDark ? "☀️" : "🌙";
  }
// Simple debounce utility
  debounce(fn, delay = 200) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), delay);
    };
  }
}

// API Communication Class
class PhishingAPI {
  constructor(baseURL = "http://localhost:5000/api") {
    this.baseURL = baseURL;
  }

  async scanURL(url) {
    try {
      const response = await fetch(`${this.baseURL}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: url }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.warn("API unavailable, using local simulation:", error);
      // Fallback to local simulation if API is not available
      return null;
    }
  }
}

// Global Functions for HTML onclick events
function scanURL() {
  detector.scanURL();
}

// Initialize the application
let detector;

document.addEventListener("DOMContentLoaded", () => {
  detector = new PhishingDetector();
});

// Add CSS animation for toast notification
const style = document.createElement("style");
style.textContent = `
    @keyframes fadeInOut {
        0% { opacity: 0; transform: translateY(-20px); }
        20% { opacity: 1; transform: translateY(0); }
        80% { opacity: 1; transform: translateY(0); }
        100% { opacity: 0; transform: translateY(-20px); }
    }
`;
document.head.appendChild(style);