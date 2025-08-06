#  PhishGuard Frontend Application
class PhishingDetector {
    constructor() {
        this.models = {
            randomForest: { weight: 0.4, name: 'Random Forest', accuracy: 0.973 },
            gradientBoosting: { weight: 0.35, name: 'Gradient Boosting', accuracy: 0.968 },
            xgboost: { weight: 0.25, name: 'XGBoost', accuracy: 0.971 }
        };
        this.scanHistory = JSON.parse(localStorage.getItem('scanHistory')) || [];
        this.apiEndpoint = 'http://localhost:5000/api'; // Backend API endpoint;
        this.init();
    }

    init() {
        this.updateStats();
        this.loadHistory();
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Enter key submission
        document.getElementById('urlInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.scanURL();
            }
        });

        // Real-time URL validation
        document.getElementById('urlInput').addEventListener('input', (e) => {
            this.validateURL(e.target.value);
        });
    }

    validateURL(url) {
        const urlInput = document.getElementById('urlInput');
        const scanBtn = document.getElementById('scanBtn');
        
        try {
            if (url && url.length > 0) {
                new URL(url);
                urlInput.style.borderColor = '#28a745';
                scanBtn.disabled = false;
            } else {
                urlInput.style.borderColor = '#e1e5e9';
                scanBtn.disabled = false;
            }
        } catch {
            if (url.length > 0) {
                urlInput.style.borderColor = '#dc3545';
                scanBtn.disabled = true;
            } else {
                urlInput.style.borderColor = '#e1e5e9';
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
            features.domainTokens = hostname.split('.').length;
            
            // Protocol and security
            features.isHttps = url.startsWith('https://');
            features.hasPort = urlObj.port !== '';
            features.portNumber = urlObj.port || (features.isHttps ? 443 : 80);
            
            // Suspicious patterns
            const suspiciousKeywords = [
                'secure', 'account', 'verify', 'login', 'signin', 'bank', 'paypal', 
                'amazon', 'microsoft', 'google', 'apple', 'update', 'confirm',
                'suspended', 'locked', 'security', 'alert', 'warning'
            ];
            features.suspiciousKeywords = suspiciousKeywords.filter(keyword => 
                url.toLowerCase().includes(keyword)).length;
            
            // IP address detection
            features.hasIP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname);
            features.hasPrivateIP = this.isPrivateIP(hostname);
            
            // URL shortening services
            const shorteners = [
                'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link',
                'tiny.cc', 'buff.ly', 'adf.ly', 'is.gd', 'soo.gd'
            ];
            features.isShortened = shorteners.some(shortener => hostname.includes(shortener));
            
            // Path analysis
            features.pathDepth = pathname.split('/').filter(p => p.length > 0).length;
            features.hasQueryParams = search.toString().length > 0;
            features.queryParamsCount = Array.from(search.keys()).length;
            
            // Suspicious path patterns
            features.hasRedirect = pathname.includes('redirect') || search.has('redirect') || search.has('url');
            features.hasLogin = pathname.includes('login') || pathname.includes('signin');
            features.hasSecure = pathname.includes('secure') || search.has('secure');
            
            // Domain reputation (simulated)
            features.domainAge = Math.floor(Math.random() * 3650); // 0-10 years in days
            features.alexa_rank = Math.floor(Math.random() * 1000000); // Simulated Alexa rank
            
            // TLD analysis
            const tld = hostname.split('.').pop();
            const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'icu', 'top', 'click'];
            features.suspiciousTLD = suspiciousTlds.includes(tld);
            features.tld = tld;
            
            return features;
        } catch (error) {
            console.error('Feature extraction error:', error);
            return null;
        }
    }

    isPrivateIP(hostname) {
        const privateRanges = [
            /^192\.168\./,
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
            /^127\./,
            /^localhost$/i
        ];
        return privateRanges.some(range => range.test(hostname));
    }

    // Simulate ensemble ML prediction
    async predictPhishing(url) {
        const features = this.extractFeatures(url);
        if (!features) throw new Error('Invalid URL format');

        // Simulate API delay
        await new Promise(resolve => setTimeout(resolve, 1500 + Math.random() * 1000));
        
        const predictions = {};
        
        // Random Forest prediction
        let rfScore = 0.1 + Math.random() * 0.1; // Base randomness
        if (features.urlLength > 75) rfScore += 0.15;
        if (features.specialChars > 8) rfScore += 0.12;
        if (!features.isHttps) rfScore += 0.08;
        if (features.hasIP) rfScore += 0.25;
        if (features.isShortened) rfScore += 0.20;
        if (features.suspiciousKeywords > 2) rfScore += 0.18;
        if (features.domainAge < 30) rfScore += 0.12;
        if (features.suspiciousTLD) rfScore += 0.15;
        if (features.subdomainCount > 3) rfScore += 0.10;
        predictions.randomForest = Math.min(Math.max(rfScore, 0.05), 0.95);

        // Gradient Boosting prediction  
        let gbScore = 0.08 + Math.random() * 0.12;
        if (features.subdomainCount > 4) gbScore += 0.22;
        if (features.specialChars > 10) gbScore += 0.18;
        if (features.hasIP) gbScore += 0.30;
        if (features.suspiciousKeywords > 1) gbScore += 0.14;
        if (!features.isHttps) gbScore += 0.10;
        if (features.hasRedirect) gbScore += 0.16;
        if (features.pathDepth > 5) gbScore += 0.08;
        predictions.gradientBoosting = Math.min(Math.max(gbScore, 0.03), 0.97);

        // XGBoost prediction
        let xgScore = 0.06 + Math.random() * 0.14;
        if (features.urlLength > 100) xgScore += 0.25;
        if (features.isShortened) xgScore += 0.28;
        if (features.hasIP) xgScore += 0.35;
        if (features.domainAge < 7) xgScore += 0.20;
        if (features.queryParamsCount > 5) xgScore += 0.12;
        if (features.digits > features.letters * 0.3) xgScore += 0.15;
        predictions.xgboost = Math.min(Math.max(xgScore, 0.02), 0.98);

        // Ensemble prediction (weighted average)
        const ensembleScore = Object.keys(this.models).reduce((sum, model) => {
            return sum + (predictions[model] * this.models[model].weight);
        }, 0);

        return {
            score: ensembleScore,
            confidence: Math.abs(ensembleScore - 0.5) * 2, // Confidence based on distance from 0.5
            predictions: predictions,
            features: features,
            classification: this.classifyResult(ensembleScore),
            modelDetails: this.models
        };
    }

    classifyResult(score) {
        if (score < 0.3) return { 
            type: 'safe', 
            label: 'Safe Website', 
            icon: '✅',
            description: 'This website appears to be legitimate and safe to visit.'
        };
        if (score < 0.7) return { 
            type: 'suspicious', 
            label: 'Suspicious Activity', 
            icon: '⚠️',
            description: 'This website shows some suspicious characteristics. Exercise caution.'
        };
        return { 
            type: 'phishing', 
            label: 'Phishing Detected', 
            icon: '🚨',
            description: 'This website is likely a phishing site. Do not enter personal information.'
        };
    }

    async scanURL() {
        const urlInput = document.getElementById('urlInput');
        const scanBtn = document.getElementById('scanBtn');
        const scanBtnText = document.getElementById('scanBtnText');
        const resultsSection = document.getElementById('resultsSection');
        
        const url = urlInput.value.trim();
        
        if (!url) {
            this.showError('Please enter a URL to scan');
            return;
        }

        try {
            // Validate URL format
            new URL(url);
        } catch {
            this.showError('Please enter a valid URL (e.g., https://example.com)');
            return;
        }

        // Show loading state
        scanBtn.disabled = true;
        scanBtnText.innerHTML = '🔄 Scanning...';
        resultsSection.innerHTML = this.getLoadingHTML();
        resultsSection.classList.add('show');

        try {
            const result = await this.predictPhishing(url);
            this.displayResults(url, result);
            this.addToHistory(url, result);
        } catch (error) {
            console.error('Scanning error:', error);
            this.showError('Error scanning URL. Please try again.');
        } finally {
            scanBtn.disabled = false;
            scanBtnText.innerHTML = '🔍 Scan URL';
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
        const resultsSection = document.getElementById('resultsSection');
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
                    ${Object.keys(predictions).map(model => `
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding: 10px; background: rgba(255,255,255,0.3); border-radius: 8px;">
                            <span style="font-weight: 600;">${this.models[model].name}</span>
                            <span style="font-weight: 700; color: #495057;">${Math.round(predictions[model] * 100)}%</span>
                        </div>
                    `).join('')}
                </div>

                <div class="features-grid">
                    ${this.generateFeatureCards(features)}
                </div>
            </div>
        `;
        
        resultsSection.innerHTML = resultsHTML;
        
        // Animate the confidence bar
        setTimeout(() => {
            const fillElement = resultsSection.querySelector('.confidence-fill');
            if (fillElement) {
                fillElement.style.width = `${scorePercentage}%`;
            }
        }, 100);
    }

    generateFeatureCards(features) {
        const featureCards = [
            {
                title: '📏 URL Length',
                value: `${features.urlLength} characters`,
                description: features.urlLength > 75 ? 'Unusually long URL' : 'Normal length',
                risk: features.urlLength > 75
            },
            {
                title: '🔒 Security Protocol',
                value: features.isHttps ? 'HTTPS ✓' : 'HTTP ⚠️',
                description: features.isHttps ? 'Secure connection' : 'Unencrypted connection',
                risk: !features.isHttps
            },
            {
                title: '🌐 Subdomains',
                value: `${features.subdomainCount} subdomains`,
                description: features.subdomainCount > 3 ? 'Many subdomains detected' : 'Normal subdomain count',
                risk: features.subdomainCount > 3
            },
            {
                title: '⚠️ Suspicious Keywords',
                value: `${features.suspiciousKeywords} found`,
                description: features.suspiciousKeywords > 0 ? 'Contains suspicious terms' : 'No suspicious terms',
                risk: features.suspiciousKeywords > 2
            },
            {
                title: '🔗 URL Type',
                value: features.isShortened ? 'Shortened URL' : 'Direct URL',
                description: features.isShortened ? 'Uses URL shortening service' : 'Direct domain link',
                risk: features.isShortened
            },
            {
                title: '🌍 Domain Age',
                value: `${Math.floor(features.domainAge)} days`,
                description: features.domainAge < 30 ? 'Very new domain' : features.domainAge < 365 ? 'Relatively new' : 'Established domain',
                risk: features.domainAge < 30
            }
        ];

        return featureCards.map(card => `
            <div class="feature-card" style="border-left: 4px solid ${card.risk ? '#dc3545' : '#28a745'};">
                <div class="feature-title">${card.title}</div>
                <div class="feature-value" style="color: ${card.risk ? '#dc3545' : '#28a745'};">${card.value}</div>
                <div class="feature-description">${card.description}</div>
            </div>
        `).join('');
    }

    getScoreColor(score) {
        if (score < 0.3) return 'linear-gradient(90deg, #28a745, #20c997)';
        if (score < 0.7) return 'linear-gradient(90deg, #ffc107, #fd7e14)';
        return 'linear-gradient(90deg, #dc3545, #e74c3c)';
    }

    showError(message) {
        const resultsSection = document.getElementById('resultsSection');
        resultsSection.innerHTML = `
            <div class="result-card" style="background: #f8d7da; border-left-color: #dc3545; color: #721c24;">
                <div class="result-header">
                    <span class="result-icon">❌</span>
                    <div class="result-title">Error</div>
                </div>
                <p>${message}</p>
            </div>
        `;
        resultsSection.classList.add('show');
    }

    addToHistory(url, result) {
        const historyItem = {
            url: url,
            result: result.classification,
            score: result.score,
            confidence: result.confidence,
            timestamp: new Date().toISOString(),
            features: result.features
        };
        
        this.scanHistory.unshift(historyItem);
        if (this.scanHistory.length > 50) {
            this.scanHistory = this.scanHistory.slice(0, 50);
        }
        
        localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory));
        this.updateStats();
        this.loadHistory();
    }

    loadHistory() {
        const historyContainer = document.getElementById('historyContainer');
        
        if (this.scanHistory.length === 0) {
            historyContainer.innerHTML = '<p style="color: #6c757d; text-align: center;">No scans performed yet</p>';
            return;
        }

        const historyHTML = this.scanHistory.map(item => {
            const timeAgo = this.getTimeAgo(new Date(item.timestamp));
            const borderColor = item.result.type === 'safe' ? '#28a745' : 
                               item.result.type === 'suspicious' ? '#ffc107' : '#dc3545';
            
            return `
                <div class="history-item" style="border-left-color: ${borderColor};" onclick="this.showHistoryDetails('${item.url}')">
                    <div class="history-url" title="${item.url}">${item.url}</div>
                    <div class="history-result">
                        <span>${item.result.icon}</span>
                        <span>${item.result.label}</span>
                        <span style="margin-left: 10px; font-size: 0.9em; opacity: 0.8;">${Math.round(item.score * 100)}%</span>
                    </div>
                    <div class="history-time">${timeAgo}</div>
                </div>
            `;
        }).join('');

        historyContainer.innerHTML = historyHTML;
    }

    getTimeAgo(date) {
        const now = new Date();
        const diffInSeconds = Math.floor((now - date) / 1000);
        
        if (diffInSeconds < 60) return 'Just now';
        if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
        if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
        return `${Math.floor(diffInSeconds / 86400)}d ago`;
    }

    updateStats() {
        document.getElementById('totalScans').textContent = this.scanHistory.length;
        document.getElementById('phishingDetected').textContent = 
            this.scanHistory.filter(item => item.result.type === 'phishing').length;
    }

    // Method to be called from onclick in history items
    showHistoryDetails(url) {
        const item = this.scanHistory.find(h => h.url === url);
        if (item) {
            // Fill the input with the historical URL
            document.getElementById('urlInput').value = url;
            // Scroll to top
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    }
}

// API Communication Class
class PhishingAPI {
    constructor(baseURL = 'http://localhost:5000/api') {
        this.baseURL = baseURL;
    }

    async scanURL(url) {
        try {
            const response = await fetch(`${this.baseURL}/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.warn('API unavailable, using local simulation:', error);
            // Fallback to local simulation if API is not available
            return null;
        }
    }

    async getStats() {
        try {
            const response = await fetch(`${this.baseURL}/stats`);
            return await response.json();
        } catch (error) {
            console.warn('Stats API unavailable:', error);
            return null;
        }
    }
}

// Utility Functions
function formatURL(url) {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        return 'https://' + url;
    }
    return url;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show a brief success message
        const toast = document.createElement('div');
        toast.textContent = 'Copied to clipboard!';
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            z-index: 1000;
            animation: fadeInOut 2s ease-in-out;
        `;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 2000);
    });
}

// Global Functions for HTML onclick events
function scanURL() {
    detector.scanURL();
}

// Initialize the application
let detector;
let api;

document.addEventListener('DOMContentLoaded', () => {
    detector = new PhishingDetector();
    api = new PhishingAPI();
    
    // Add some sample data for demonstration
    if (detector.scanHistory.length === 0) {
        const sampleHistory = [
            {
                url: 'https://secure-paypal-verification.suspicious-domain.com/login',
                result: { type: 'phishing', label: 'Phishing Detected', icon: '🚨' },
                score: 0.89,
                confidence: 0.94,
                timestamp: new Date(Date.now() - 3600000).toISOString()
            },
            {
                url: 'https://google.com',
                result: { type: 'safe', label: 'Safe Website', icon: '✅' },
                score: 0.05,
                confidence: 0.98,
                timestamp: new Date(Date.now() - 7200000).toISOString()
            }
        ];
        
        detector.scanHistory = sampleHistory;
        localStorage.setItem('scanHistory', JSON.stringify(sampleHistory));
        detector.updateStats();
        detector.loadHistory();
    }
});

// Add CSS animation for toast notification
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeInOut {
        0% { opacity: 0; transform: translateY(-20px); }
        20% { opacity: 1; transform: translateY(0); }
        80% { opacity: 1; transform: translateY(0); }
        100% { opacity: 0; transform: translateY(-20px); }
    }
`;
document.head.appendChild(style);