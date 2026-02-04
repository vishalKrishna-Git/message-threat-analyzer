from flask import Flask, render_template, request, jsonify
import pytesseract
from PIL import Image, ImageOps, ImageEnhance, ImageFilter
import re
import io
import requests
from bs4 import BeautifulSoup
import pdfplumber
from pyzbar.pyzbar import decode
import json
import os
import gc

app = Flask(__name__)

# --- CONFIGURATION ---
# UNCOMMENT IF ON WINDOWS:
# pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# ==============================================================================
# 1. MASSIVE THREAT DATABASE (BLACKLIST - SCAMS)
# ==============================================================================

IMPERSONATION_TARGETS = {
    "netflix": "Netflix", "amazon": "Amazon", "prime video": "Amazon Prime", "disney": "Disney+",
    "hotstar": "Disney+ Hotstar", "spotify": "Spotify", "youtube": "YouTube",
    "facebook": "Meta/Facebook", "instagram": "Instagram", "whatsapp": "WhatsApp", 
    "snapchat": "Snapchat", "telegram": "Telegram", "linkedin": "LinkedIn", "twitter": "X (Twitter)",
    "paypal": "PayPal", "venmo": "Venmo", "cashapp": "CashApp", "western union": "Western Union",
    "binance": "Binance", "coinbase": "Coinbase", "trust wallet": "Trust Wallet", "metamask": "MetaMask",
    "sbi": "SBI Bank", "hdfc": "HDFC Bank", "icici": "ICICI Bank", "axis": "Axis Bank", "pnb": "Punjab National Bank",
    "kotak": "Kotak Mahindra", "bob": "Bank of Baroda", "canara": "Canara Bank", "indusind": "IndusInd Bank",
    "idfc": "IDFC First Bank", "yes bank": "Yes Bank", "union bank": "Union Bank of India",
    "paytm": "Paytm", "phonepe": "PhonePe", "gpay": "Google Pay", "bajaj finserv": "Bajaj Finance",
    "muthoot": "Muthoot Finance", "epfo": "EPFO", "lic": "LIC India", "cred": "CRED",
    "flipkart": "Flipkart", "meesho": "Meesho", "myntra": "Myntra", "ajio": "Ajio", "nykaa": "Nykaa",
    "zomato": "Zomato", "swiggy": "Swiggy", "blinkit": "Blinkit", "zepto": "Zepto", "bigbasket": "BigBasket",
    "jiomart": "JioMart", "dmart": "DMart", "ola": "Ola Cabs", "uber": "Uber", "rapido": "Rapido",
    "apple id": "Apple", "icloud": "Apple", "microsoft": "Microsoft", "google": "Google",
    "zoom": "Zoom", "dropbox": "Dropbox", "adobe": "Adobe", "norton": "Norton", "mcafee": "McAfee",
    "geek squad": "Geek Squad", "fedex": "FedEx", "dhl": "DHL", "usps": "USPS", "ups": "UPS", 
    "indiapost": "India Post", "bluedart": "BlueDart", "delhivery": "Delhivery",
    "jio": "Jio Telecom", "airtel": "Airtel", "vi": "Vodafone Idea", "bsnl": "BSNL",
    "uidai": "Aadhaar", "irctc": "Indian Railways", "incometax": "Income Tax Dept", 
    "parivahan": "Transport Ministry", "passport": "Passport Seva", "digilocker": "DigiLocker",
    "sebi": "SEBI", "rbi": "RBI", "police": "Police Dept", "cbi": "CBI", "customs": "Customs Dept"
}

SENSITIVE_WARNINGS = [
    "otp for", "otp is", "one time password", "verification code", "valid for", 
    "generated at", "do not share this code", "code is", "auth code", "login code",
    "secret code", "withdrawl code", "transaction password", "cvv", "pin number",
    "mpin", "upi pin"
]

URGENT_PANIC_SCAMS = [
    "within 24 hours", "within 24hr", "immediately", "urgent action", "avoid deactivation",
    "account will be close", "will be closed", "service stopped", "access restricted",
    "block your account", "suspend your account", "action required", "compliance pending",
    "kyc incomplete", "submit immediately", "last reminder", "final notice", "electricity disconnection",
    "pay right away", "overdue and unsettled", "power will be cut"
]

# --- NEW: FASTTAG & REWARDS DATASETS (Testing Requirement) ---
FASTTAG_SCAMS = [
    "fasttag blocked", "fastag suspended", "kyc pending for fasttag", "toll account", 
    "nhai alert", "wallet frozen", "update fasttag", "toll plaza"
]

REWARD_POINTS_SCAMS = [
    "reward points expiring", "redeem points", "convert to cash", "points lapsing", 
    "credit card bonus", "claim reward", "points value", "encash your points"
]

DIGITAL_ARREST_SCAMS = [
    "package seized", "drugs found", "illegal items", "customs officials", "narcotics bureau",
    "cbi investigation", "mumbai police", "delhi police", "cyber crime cell", "arrest warrant",
    "money laundering case", "adhaar misuse", "skype statement", "video call statement",
    "digital arrest", "stay online", "do not disconnect", "police verification pending",
    "court summon", "legal notice issued", "case registered against you", "crime branch"
]

POLICE_CHALLAN_SCAMS = [
    "challan pending", "parivahan", "court notice", "lok adalat", "traffic police", 
    "fine unpaid", "legal action", "virtual court", "epolice", "traffic violation",
    "vehicle seized", "pay fine immediately", "fir registered", "police case", "e-challan",
    "click to pay fine", "fine is overdue", "unsettled", "supplementary fees", 
    "enforcement procedures", "traffic fine", "steer clear"
]

INDIAN_JOB_SCAMS = [
    "part time job", "work from home", "like youtube videos", "telegram task", "prepaid task", 
    "daily salary", "hr manager", "hiring for amazon", "investment start", "crypto trading", 
    "mall review", "google map review", "hotel review", "daily income", "weekly payout",
    "no experience needed", "work from mobile", "data entry job", "filling job", "sms sending job",
    "online job fraud", "higher wages", "better employment", "false hope", "job promise",
    "rating task", "review task", "online branding", "recruitment manager"
]

INDIAN_BANKING_SCAMS = [
    "kyc pending", "update your pan", "account blocked", "netbanking blocked", 
    "adhar link", "pan card expired", "submit kyc", "dear customer your account", 
    "debit card blocked", "credit card points", "redeem points", "reward points expiring",
    "bank account suspended", "kyc verification", "sim verification", "paytm kyc",
    "credit limit increase", "lifetime free card", "cibil score check", "loan approved",
    "pf claim rejected", "uan activation", "epfo kyc", "pension stopped",
    "demat fraud", "depository fraud", "e-wallet fraud", "fraud call", "vishing", 
    "sim swap", "debit card fraud", "credit card fraud",
    "bank a/c will be close", "account will be closed", "complete your verification",
    "unauthorized use", "withdrawing funds", "card information", "purchase detected"
]

INDIAN_LOAN_APP_SCAMS = [
    "instant loan", "no cibil score", "loan approved", "disburse amount", "repay immediately",
    "access to gallery", "access to contacts", "contact list", "morphing pictures", "recovery agent",
    "legal action", "defaulter", "shame you", "send photos to relatives", "loan overdue",
    "pay extension fee", "quick cash", "paperless loan", "low interest rate"
]

AEPS_SCAMS = [
    "aeps withdrawal", "aadhaar payment", "biometric mismatch", "fingerprint clone",
    "money deducted without otp", "silicon thumb", "lock biometric", "aadhaar enabled payment",
    "csp center", "mini statement", "balance enquiry", "unauthorized aeps"
]

UPI_LOTTERY_SCAMS = [
    "cashback received", "phonepe reward", "gpay reward", "kbc winner", "kaun banega crorepati", 
    "lottery number", "jio lucky", "ipl winner", "scan to receive", "enter pin", 
    "refund processed", "money sent successfully", "scratch card", "better luck next time",
    "you won", "congratulations winner", "paytm cashback", "wallet refund", 
    "prime minister yojana", "pm scheme", "free laptop", "scholarship approved", "ration card update",
    "ayushman bharat upgrade", "e-shram card bonus",
    "congratulations", "you have been selected", "lucky draw", "claim your prize", 
    "spin the wheel", "jackpot winner", "winning notification"
]

INDIAN_DOC_SCAMS = [
    "aadhaar suspended", "biometric locked", "update aadhaar immediately", "aadhaar address update", 
    "download e-aadhaar", "aadhaar verification failed", "link mobile to aadhaar", "aadhaar kyc required",
    "document update required", "upload proof of identity", "aadhaar services suspended",
    "needs biometrics update", "needs document update", "avoid deactivation", "update to continue",
    "pan card inoperative", "pan inoperative", "link pan with aadhaar", "pan aadhaar link", 
    "penalty for pan", "pan verification failed", "pan card blocked", "income tax penalty",
    "pan invalid", "pan record missing",
    "voter id not verified", "digital voter id", "voter card blocked", "ration card cancelled", 
    "ration suspended", "add member to ration card", "ration subsidy stopped",
    "tax refund approved", "income tax refund", "itr processed", "click to claim refund", 
    "outstanding tax demand", "pay tax arrears", "gst registration cancelled", "gstin blocked",
    "passport dispatch halted", "police verification failed", "passport file on hold", 
    "visa appointment cancelled", "immigration error"
]

INDIAN_TECH_SCAMS = [
    "5g upgrade", "sim block", "esim activation", "port sim", "kyc sim", 
    "airtel verification", "jio verification", "vi verification", 
    "recharge successful", "plan expired", "validity expired", "upgrade to 5g",
    "sim swap", "esim request"
]

VIRUS_TROJAN_SCAMS = [
    "computer virus", "trojan horse", "worm detected", "malicious program", "backdoor entry",
    "replicate themselves", "damage your files", "alter data", "destructive program",
    "genuine application", "access your system", "steal confidential information",
    "ransomware", "encrypt files", "files encrypted", "demand ransom", "restore data", 
    "decrypt your files", "pay ransom", "bitcoin ransom", "lock your computer"
]

FAKE_APP_SCAMS = [
    "whatsapp gold", "whatsapp plus", "gold version", "upgrade to gold", "premium whatsapp",
    "whatsapp pink", "gb whatsapp", "download update", "new version available", 
    "update whatsapp now", "unlimited access", "free upgrade", "exclusive features",
    "install this app", "apk download", "install new version", "martinelli video"
]

CRYPTO_MINING_SCAMS = [
    "cryptojacking", "mining malware", "cloud mining scam", "generate cryptocurrency", 
    "stealing resources", "infected machines", "high power consumption", "mining pool",
    "wear and tear", "computing power"
]

HACKING_TERRORISM_SCAMS = [
    "threaten unity", "integrity of india", "sovereignty of india", "strike terror", 
    "denial of access", "penetrate system", "unauthorised access", "damage to computer",
    "disrupt supplies", "critical information infrastructure", "tampering with documents",
    "website defacement", "email hacking", "data breach", "wrongful loss", "delete information",
    "alter information", "diminish value", "exceeding authorised access"
]

IDENTITY_THEFT_SCAMS = [
    "identity theft", "impersonation act", "electronic signature theft", "password theft",
    "unique identification feature", "fraudulently making use", "dishonestly making use",
    "fake profile", "impersonating profile", "identity fraud"
]

SOCIAL_MEDIA_CRIMES = [
    "cheating by impersonation", "cyber bullying", "cyber stalking", "sexting", 
    "intimidating email", "impersonating email", "matrimonial fraud", "groom wanted", 
    "bride wanted", "profile hacking", "provocative speech", "incitement to offence", 
    "unlawful acts", "defamation"
]

INVESTMENT_SCAMS = [
    "stock tip", "guaranteed profit", "upper circuit", "ipo allotment", "institutional account",
    "foreign institutional investor", "fii trading", "block trade", "double your money",
    "whatsapp investment group", "telegram trading group", "sebi registered analyst",
    "profit sharing", "no loss strategy", "high return", "daily income trading",
    "pump and dump", "crypto giveaway", "guaranteed high returns"
]

SEXTORTION_SCAMS = [
    "video call recording", "nude video", "uploaded to youtube", "send to your contacts",
    "social reputation", "delete the video", "cyber police complaint", "pay to remove",
    "video viral", "recorded your screen", "sexually explicit", "lascivious", 
    "prurient interest", "deprave and corrupt", "section 67", "section 67a"
]

CRYPTO_SCAMS = [
    "airdrop claim", "connect wallet", "seed phrase", "validate wallet", "synchronize wallet",
    "gas fees", "fake usdt", "crypto mining pool", "hashrate", "mining withdrawal",
    "trust wallet support", "metamask support"
]

GLOBAL_DELIVERY_SCAMS = [
    "delivery attempt failed", "package pending", "shipping fee", "customs duty", 
    "incomplete address", "redelivery", "address confirmation", "package on hold",
    "unable to deliver", "return to sender", "track your package", "shipment issue"
]

GLOBAL_FINANCE_SCAMS = [
    "irs tax refund", "hmrc refund", "unusual sign-in activity", "verify your identity", 
    "apple id locked", "netflix payment failed", "paypal limited", "social security suspended",
    "unauthorized transaction", "payment declined", "card charged", "subscription expired",
    "renew subscription", "account limited", "secure your account", "invoice attached",
    "receipt for your order", "purchase confirmed", "cloud storage full", "icloud full",
    "view your bill", "invoice available", "bill is due", "payment overdue", 
    "ceo request", "wire transfer", "confidential project", "change vendor details",
    "business email compromise", "email takeover"
]

GLOBAL_RELATIONSHIP_SCAMS = [
    "romance", "military doctor", "send money for ticket", "diplomat", "consignment box", 
    "inheritance", "fund transfer", "next of kin", "trust fund", "widow", "orphan",
    "my darling", "my love", "soulmate", "send gift card", "steam card", "please help me"
]

GLOBAL_TECH_SUPPORT = [
    "microsoft support", "windows defender expired", "computer infected", "call this number", 
    "virus detected", "trojan alert", "firewall breach", "hacker detected", 
    "ip compromised", "system critical", "contact support immediately", "toll free"
]

SOCIAL_SCAMS = [
    "broke my phone", "temporary number", "new number", "lost my phone", "this is mom", 
    "this is dad", "accident", "hospital", "urgent surgery", "send money", "borrow money", 
    "pay you back", "send me $", "taxi fare", "uber", "gas money", "grindr", "tinder", 
    "meet up", "gift card", "steam card", "apple card", "google play card", 
    "help me", "emergency", "jail", "bail money", "lawyer fee", "stuck at airport",
    "voicemail received", "listen to voicemail", "video call missed",
    "my secretary", "assistant gave", "wrong number", "saved in my contacts", 
    "acquaintance", "fate", "destiny", "nice to meet you", "kindly and friendly", 
    "stored your number", "manager gave me", "assistant saved"
]

OTP_PHISHING_SCAMS = [
    "otp for purchase", "otp for transaction", "debited from your account", 
    "if not you", "call to cancel", "call support", "transaction detected", 
    "refund code", "stop transaction", "did you attempt", "unusual login", 
    "share this code", "verification code for amazon", "verification code for flipkart",
    "amount deducted", "request to pay", "approve request"
]

INDIAN_UTILITY_SCAMS = [
    "electricity power", "disconnect tonight", "bill not update", "electricity officer", 
    "contact officer", "light bill", "power cut", "meter disconnect", "bill unpaid",
    "previous month bill", "bses alert", "tata power", "adani electricity",
    "gas connection", "subsidy pending", "indane gas", "bharat gas"
]

PHISHING_KEYWORDS = [
    "dear beneficiary", "fund release", "winning notification", "inheritance", "next of kin",
    "confidential business", "abandoned shipment", "diplomatic delivery", "western union transfer",
    "atm card delivery", "lottery winner", "microsoft lottery", "coca cola lottery",
    "unclaimed funds", "payment file", "imf compensation", "un"
]

MALWARE_KEYWORDS = [
    "download attachment", "run this file", "install certificate", "update your driver",
    "pdf contains password", "enable editing", "view secured document", "download.exe",
    "invoice.pdf.exe", "statement.vbs", "photo.scr", "application.exe"
]

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl", "ngrok", "is.gd", ".xyz", "top", "club", "g00gle", "paypa1", 
    "amaz0n", "hotmail", "gmail", "outlook", "yahoo", "blogspot", "weebly", "wix", 
    "duckdns", "serveo", "pastebin", "ipfs", "glitch.me", "firebaseapp", 
    "nrsc.gov.in", "bhuvan-app", "lnk.ink", "link.ink", "short.url", "cutt.ly", "rb.gy"
]
BAD_URL_KEYWORDS = [
    "kyc", "bank-update", "secure-login", "account-verify", "bonus", "claim", "free", 
    "gift", "support", "help-desk", "service", "login", "signin", "wallet", "connect", 
    "validate", "confirm", "unlock", "update-pan", "adhaar-link", "rewards", "itr-refund"
]

MALWARE_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".msi", ".dmg", ".vbs", ".apk", ".jar"]

# ==============================================================================
# 2. WHITELIST DATABASES
# ==============================================================================

OFFICIAL_DOMAINS = [
    "microsoft.com", "apple.com", "google.com", "facebook.com", "instagram.com", 
    "whatsapp.com", "twitter.com", "linkedin.com", "youtube.com", "netflix.com",
    "amazon.in", "amazon.com", "telegram.org", "adobe.com", "dropbox.com", 
    "zoom.us", "salesforce.com", "atlassian.com", "slack.com",
    "uidai.gov.in", "myaadhaar.uidai.gov.in", "incometax.gov.in", "parivahan.gov.in", 
    "passportindia.gov.in", "epfindia.gov.in", "pmkisan.gov.in", "cybercrime.gov.in",
    "ncs.gov.in", "digilocker.gov.in", "nvsp.in", "eci.gov.in", "indianrail.gov.in", 
    "irctc.co.in", "echallan.parivahan.gov.in", "gst.gov.in", "rbi.org.in", "sebi.gov.in",
    "cowin.gov.in", "mohfw.gov.in", "niti.gov.in", "india.gov.in", "mygov.in", "epfindia.gov.in",
    "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "pnbindia.in", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in",
    "indusind.com", "idfcfirstbank.com", "rblbank.com", "yesbank.in", "bandhanbank.com",
    "citibank.co.in", "hsbc.co.in", "standardchartered.co.in", "amex.com", "federalbank.co.in",
    "paytm.com", "phonepe.com", "google.com/pay", "bhimupi.org.in", "npci.org.in",
    "paypal.com", "cred.club", "razorpay.com", "billdesk.com", "bharatpe.com",
    "freecharge.in", "mobikwik.com",
    "flipkart.com", "myntra.com", "ajio.com", "meesho.com", "nykaa.com", "tatacliq.com", 
    "jiomart.com", "zomato.com", "swiggy.com", "blinkit.com", "zeptonow.com", "bigbasket.com",
    "bluedart.com", "delhivery.com", "indiapost.gov.in", "dtdc.in", "fedex.com", "dhl.com",
    "snapdeal.com", "lenskart.com", "firstcry.com", "bookmyshow.com", "urbancompany.com",
    "olacabs.com", "uber.com", "rapido.bike", "makemytrip.com", "goibibo.com", "yatra.com",
    "indigo.in", "airindia.com", "spicejet.com", "akasaair.com", "redbus.in",
    "cleartrip.com", "booking.com", "agoda.com", "irctc.co.in",
    "jio.com", "airtel.in", "myvi.in", "bsnl.co.in", "actcorp.in", "hathway.com",
    "licindia.in", "policybazaar.com", "tatapower.com", "bsesdelhi.com", "adanielectricity.com"
]

SAFE_PATTERNS = {
    "BANKING_INFO": ["credited to", "deposited in", "statement generated", "balance is", "transaction successful", "thank you for banking", "received from", "sent to", "payment received", "auto-pay scheduled", "available limit", "spent", "outstanding due", "statement", "auto-pay"],
    "JOB_SAFE": ["application received", "interview scheduled", "position filled", "thank you for applying", "resume review", "job alert", "offer letter attached", "joining date"],
    "SOCIAL_SAFE": ["happy birthday", "congratulations on your", "get well soon", "good morning", "see you later", "call me when", "let's meet", "are you free", "happy anniversary", "merry christmas", "happy diwali", "happy new year", "best wishes", "hey, how are you", "can i call you", "lunch today"],
    "SHIPPING_SAFE": ["out for delivery", "delivered successfully", "handed over", "order placed", "invoice generated", "receipt for", "order confirmation", "arriving today"],
    "OTP_SAFE": ["valid for", "do not share", "verification code is", "is your otp", "requested for", "otp is"],
    "UTILITY_SAFE": ["bill generated", "due date", "paid", "usage alert", "payment received", "receipt", "bill payment", "recharge successful"]
}

RISK_EXPLANATIONS = {
    "FastTag": "🚗 **FastTag Fraud:** Scammers claim your FastTag is blocked/suspended to steal money. Only update KYC on official NETC/Bank portals.",
    "Rewards": "💳 **Reward Point Scam:** Banks NEVER ask you to click a link to 'redeem' points for cash. This is a trap to steal card details.",
    "Police/Legal": "🚨 **Why this is suspicious:** Real police officers or CBI officials will **never** video call you or interrogate you online. They will never demand money to 'clear your name' or ask for digital payments. This is likely a 'Digital Arrest' scam.",
    "Traffic Challan": "🚗 **Traffic Challan Fraud:** Scammers send fake 'e-challan' links (often ending in .apk or random domains). Real traffic fines are only paid on official government portals like `echallan.parivahan.gov.in`.",
    "Tech Support": "💻 **Tech Support Scam:** Legitimate companies like Microsoft or Google do not send unsolicited messages about viruses. Do not call the number or download any remote access software (like AnyDesk/TeamViewer).",
    "Govt Document": "❌ **Fake Document Alert:** Scammers use panic tactics ('Account Blocked', 'PAN Suspended') to trick you into clicking a link. Always verify your status on the official website, never via an SMS link.",
    "Banking": "🏦 **Banking Fraud:** Banks never ask for your password, PIN, or OTP over text or call. If the message demands 'immediate KYC' via a non-official link, it is a phishing attempt.",
    "Utility Bill": "💡 **Utility Scam:** Electricity boards do not disconnect power at night or ask you to call a personal mobile number. Use your official bill payment app to check for dues.",
    "UPI/Lottery": "💸 **Lottery Scam:** You cannot win a lottery you didn't enter. Scammers often ask you to 'scan a QR code' or 'enter your PIN' to receive money. **Never enter your PIN to receive money.**",
    "Job Offer": "💼 **Job Scam:** Legitimate companies do not pay you to 'like' YouTube videos or ask for a registration fee. High daily income promises for simple tasks are a hallmark of Ponzi schemes.",
    "Social": "🗣️ **Social Engineering:** Be wary of strangers claiming to be 'old friends' or wrong numbers trying to build a relationship. They may later ask for money or investment.",
    "Loan App": "💰 **Predatory Loan Apps:** Illegal loan apps often access your gallery and contacts to blackmail you. Do not pay them. Report the app to the cyber crime portal.",
    "AePS": "biometric **AePS Fraud:** Scammers can steal money using cloned fingerprints. Lock your Aadhaar biometrics in the mAadhaar app to stay safe.",
    "Phishing": "📧 **Phishing Attempt:** This message fits the pattern of a classic phishing scam (Inheritance/Lottery/Fund Release). Do not reply or share personal details.",
    "Identity": "🆔 **Identity Theft:** Someone may be trying to impersonate you or use your details illegally. Secure your accounts immediately.",
    "Terrorism": "⚠️ **Severe Threat:** This content contains keywords related to cyber terrorism or infrastructure attacks. Report this to authorities immediately.",
    "Extortion": "🚫 **Sextortion:** This is a blackmail attempt. Do not pay. The scammer will not delete the video even if you pay. Block them and report to Cyber Crime.",
    "Financial": "💳 **Financial Fraud:** Be cautious of fake tax refunds or unauthorized transaction alerts designed to panic you into revealing login credentials.",
    "Romance": "💔 **Romance Scam:** Scammers build trust over weeks to ask for money for 'flights', 'visas', or 'medical emergencies'. Never send money to someone you haven't met in person.",
    "Malware": "💾 **Dangerous File Detected:** The message contains an executable file extension (.exe, .scr) or a password-protected PDF. Do not download or open these files as they likely contain viruses or spyware.",
    "PasswordPDF": "🔐 **Password Locked / Corrupted PDF:** This file is protected with a password or is corrupted. Scammers often lock fake bank statements or legal notices to bypass security scanners. **Do not enter your personal password to open it.**"
}

# ==============================================================================
# 3. ACTIVE LINK INSPECTOR
# ==============================================================================
def inspect_link(url):
    risks = []
    score_add = 0
    if not url.startswith(('http://', 'https://')): url = 'http://' + url
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=1)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    try:
        # PERFORMANCE: Added timeout=2 to prevent hanging
        response = session.get(url, timeout=2, allow_redirects=True)
        
        # INPUT VALIDATION: Double check for APK headers
        content_type = response.headers.get('Content-Type', '').lower()
        if 'application/vnd.android.package-archive' in content_type:
            risks.append("⛔ **CRITICAL:** Link initiates an Android App (.apk) download.")
            score_add += 10

        if response.history:
            final_url = response.url
            risks.append(f"⚠️ **Redirection:** Link redirects to '{final_url}'")
            if ".apk" in final_url:
                 risks.append("⛔ **Malware Alert:** Redirected to an App download (.apk)")
                 score_add += 5
        if response.status_code != 200:
            risks.append(f"⚠️ **Suspicious:** Site returned Error {response.status_code} (Likely taken down).")
            score_add += 2 
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.title:
            title = soup.title.string.strip()[:50]
            risks.append(f"ℹ️ **Page Title:** '{title}'")
            if "index of" in title.lower() or "wordpress" in title.lower():
                risks.append("❌ **Unsafe:** Title indicates a cheap/hacked setup.")
                score_add += 2
    except requests.exceptions.Timeout:
        risks.append("⚠️ **Timeout:** Site is too slow or unresponsive (Suspicious).")
        score_add += 2
    except requests.exceptions.TooManyRedirects:
        risks.append("❌ **Loop:** Site redirects too many times (Trap).")
        score_add += 2
    except requests.exceptions.RequestException:
        risks.append("⚠️ **Connection Failed:** Could not verify link (Potential Risk).")
        score_add += 2
    finally:
        session.close()
    return risks, score_add

# 4. MAIN ANALYSIS ENGINE
def get_threat_analysis(text, source_type):
    score = 0
    flags = []
    advice_list = [] 
    detected_contexts = set() 
    
    text_lower = text.lower()
    is_safe_source = False
    detected_threat_type = None

    # --- A. WHITELIST CHECK ---
    for safe_domain in OFFICIAL_DOMAINS:
        if safe_domain in text_lower:
            is_safe_source = True
            flags.append(f"✅ **Verified Source:** Message contains official domain '{safe_domain}'.")
            score -= 100 
            break

    # --- B. LINK EXTRACTION ---
    link_pattern = r'(?:https?://|www\.)\S+'
    urls = re.findall(link_pattern, text)

    # --- C. IMPERSONATION DETECTION ---
    detected_impersonation = []
    for keyword, company in IMPERSONATION_TARGETS.items():
        if re.search(r'\b' + re.escape(keyword) + r'\b', text_lower):
            if company not in detected_impersonation:
                detected_impersonation.append(company)
                if not is_safe_source: score += 1 
    if detected_impersonation and not is_safe_source:
         flags.append(f"🏢 **Entity Detection:** Message mentions {', '.join(detected_impersonation)}.")
         flags.append(f"⚠️ **Warning:** Verify this is truly from their official app/number.")

    # --- D. SAFE CONTEXT CHECK ---
    for category, patterns in SAFE_PATTERNS.items():
        for phrase in patterns:
            if phrase in text_lower:
                score -= 3 
                flags.append(f"✅ **Likely Safe:** Context appears to be legitimate ({category}).")
                break

    # --- E. THREAT PATTERN MATCHING ---
    for phrase in SENSITIVE_WARNINGS:
        if phrase in text_lower:
            score += 1 
            flags.append(f"🔒 **Security Alert:** Message contains SENSITIVE CODE ('{phrase}'). **DO NOT SHARE** this with anyone.")
            break 
            
    for phrase in URGENT_PANIC_SCAMS:
        if phrase in text_lower:
            score += 3
            flags.append(f"⚠️ PANIC TRIGGER: Urgent action demanded ('{phrase}')")

    # --- ADDED: NEW CATEGORY CHECKS (FASTTAG & REWARDS) ---
    for phrase in FASTTAG_SCAMS:
        if phrase in text_lower:
            score += 5
            detected_threat_type = "FastTag"
            flags.append(f"⚠️ **FASTTAG SCAM:** Fake KYC/Block alert ('{phrase}')")
            if "FastTag" not in detected_contexts:
                advice_list.append(RISK_EXPLANATIONS["FastTag"])
                detected_contexts.add("FastTag")

    for phrase in REWARD_POINTS_SCAMS:
        if phrase in text_lower:
            score += 5
            detected_threat_type = "Rewards"
            flags.append(f"⚠️ **REWARDS FRAUD:** Fake point redemption offer ('{phrase}')")
            if "Rewards" not in detected_contexts:
                advice_list.append(RISK_EXPLANATIONS["Rewards"])
                detected_contexts.add("Rewards")

    threat_lists = [
        (DIGITAL_ARREST_SCAMS, 5, "🚨 **DIGITAL ARREST SCAM:** Fake Police/Customs threat detected", "Police/Legal"),
        (POLICE_CHALLAN_SCAMS, 5, "⚠️ GOV IMPOSTER: Fake Challan/Legal notice", "Traffic Challan"),
        (VIRUS_TROJAN_SCAMS, 5, "⛔ **MALWARE ALERT:** Virus/Trojan/Worm threat detected", "Tech Support"),
        (IDENTITY_THEFT_SCAMS, 5, "🚨 **IDENTITY THEFT:** Impersonation/Signature fraud detected", "Identity"),
        (HACKING_TERRORISM_SCAMS, 5, "🚨 **CYBER TERRORISM/HACKING:** Critical infrastructure/Unity threat detected", "Terrorism"),
        (SOCIAL_MEDIA_CRIMES, 3, "⚠️ SOCIAL CRIME: Harassment/Impersonation/Matrimonial fraud", "Social Media"),
        (CRYPTO_MINING_SCAMS, 3, "⚠️ CRYPTOJACKING: Unauthorized mining threat", "Crypto"),
        (FAKE_APP_SCAMS, 4, "❌ FAKE APP SCAM: Malicious software promotion detected", "Fake App"),
        (INVESTMENT_SCAMS, 3, "⚠️ INVESTMENT FRAUD: Suspicious high-return scheme", "Investment"),
        (SEXTORTION_SCAMS, 5, "⛔ **SEXTORTION ALERT:** Blackmail/Obscenity threat detected", "Extortion"),
        (CRYPTO_SCAMS, 3, "⚠️ CRYPTO SCAM: Wallet/Airdrop fraud detected", "Crypto"),
        (INDIAN_DOC_SCAMS, 4, "❌ GOV DOC SCAM: Official Identity Fraud detected", "Govt Document"),
        (OTP_PHISHING_SCAMS, 3, "⚠️ OTP/PANIC SCAM: Fake transaction or panic trigger", "Banking/OTP"),
        (INDIAN_BANKING_SCAMS, 3, "❌ BANK SCAM (India): Panic tactic detected", "Banking"),
        (INDIAN_UTILITY_SCAMS, 4, "❌ UTILITY SCAM: Fake disconnection threat", "Utility Bill"),
        (INDIAN_LOAN_APP_SCAMS, 5, "🚨 **LOAN APP SCAM:** Harassment/Blackmail detected", "Loan App"),
        (AEPS_SCAMS, 5, "🚨 **AEPS FRAUD:** Biometric/Aadhaar theft detected", "AePS"),
        (UPI_LOTTERY_SCAMS, 3, "⚠️ UPI/SCHEME FRAUD: Fake Reward/Lottery claim", "UPI/Lottery"),
        (INDIAN_JOB_SCAMS, 2, "⚠️ JOB SCAM: Suspicious work offer", "Job Offer"),
        (INDIAN_TECH_SCAMS, 3, "⚠️ TECH SCAM: Sim/5G Fraud attempt", "Telecom"),
        (GLOBAL_DELIVERY_SCAMS, 2, "📦 DELIVERY SCAM: Fake shipping notification", "Delivery"),
        (GLOBAL_FINANCE_SCAMS, 3, "💳 PHISHING: Tax/Account Suspicious Activity", "Financial"),
        (GLOBAL_RELATIONSHIP_SCAMS, 3, "💔 RELATIONSHIP SCAM: Trust/Money trick detected", "Romance"),
        (GLOBAL_TECH_SUPPORT, 4, "💻 TECH SUPPORT SCAM: Fake Virus Alert", "Tech Support"),
        (SOCIAL_SCAMS, 3, "⚠️ SOCIAL ENGINEERING: Emergency/Money trick detected", "Social"),
        (PHISHING_KEYWORDS, 3, "⚠️ **PHISHING PATTERN:** Suspicious inheritance/lottery content", "Phishing"),
        (MALWARE_KEYWORDS, 5, "💾 **MALWARE THREAT:** Dangerous file request detected", "Malware")
    ]

    for pattern_list, risk_score, message, context_tag in threat_lists:
        for phrase in pattern_list:
            if phrase in text_lower:
                score += risk_score
                detected_threat_type = context_tag
                flags.append(f"{message} ('{phrase}')")
                
                if context_tag not in detected_contexts:
                    if context_tag in RISK_EXPLANATIONS:
                        advice_list.append(RISK_EXPLANATIONS[context_tag])
                    detected_contexts.add(context_tag)

    if "enter pin" in text_lower:
        score += 10
        flags.append("⛔ CRITICAL: Asking for PIN to 'receive' money is 100% SCAM.")

    if "PDF_PASSWORD_LOCKED" in text:
        score += 10
        detected_threat_type = "PasswordPDF"
        flags.append("🔐 **SECURITY ALERT:** The uploaded PDF is password protected or corrupted.")
        advice_list.append(RISK_EXPLANATIONS["PasswordPDF"])

    if urls:
        flags.append(f"🔗 **Scan:** Found {len(urls)} link(s) in message.")
        for url in urls:
            url_lower = url.lower()
            
            # --- INPUT VALIDATION: DOUBLE EXTENSION CHECK ---
            if re.search(r'\.[a-z]{3}\.exe$', url_lower):
                score += 10
                flags.append("⛔ **CRITICAL:** Hidden Extension Malware Detected (e.g. .pdf.exe)")
            
            for ext in MALWARE_EXTENSIONS:
                if url_lower.endswith(ext):
                    score += 10
                    flags.append(f"⛔ **MALWARE ALERT:** Link ends in dangerous extension '{ext}'")
                    if "Malware" not in detected_contexts:
                        advice_list.append(RISK_EXPLANATIONS["Malware"])
                        detected_contexts.add("Malware")

            if ".apk" in url_lower:
                score += 10
                flags.append(f"⛔ MALWARE: Link ends in .apk")
            if re.search(r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                score += 4
                flags.append(f"❌ DANGEROUS: IP Address URL.")
            
            if not is_safe_source:
                for domain in SUSPICIOUS_DOMAINS:
                    if domain in url_lower:
                        score += 5
                        flags.append(f"⚠️ Suspicious Domain: '{domain}'")
                for keyword in BAD_URL_KEYWORDS:
                    if keyword in url_lower:
                        score += 5
                        flags.append(f"⚠️ Suspicious keyword in URL: '{keyword}'")

            if source_type == 'manual' and not is_safe_source:
                insp_flags, insp_score = inspect_link(url)
                score += insp_score
                flags.extend(insp_flags)

    if urls and not is_safe_source:
        score += 20
        if detected_threat_type:
            flags.append(f"⛔ CRITICAL: This message appears to be about **{detected_threat_type}**, but the link provided does NOT match our official records for that category.")
        else:
            flags.append("⛔ CRITICAL POLICY: The link provided is NOT an official government or banking domain. We treat all unverified links as high risk.")

    if is_safe_source and score > 0:
        score = max(0, score - 5)

    final_score = min(score, 10)
    
    if final_score <= 0:
        verdict = "SAFE"
        color = "safe"
        if final_score < 0: final_score = 0 
    elif 1 <= final_score <= 4:
        verdict = "SUSPICIOUS"
        color = "suspicious"
    else:
        verdict = "SCAM DETECTED"
        color = "danger"

    return {
        "verdict": verdict, 
        "color": color, 
        "score": final_score, 
        "flags": flags,
        "advice": advice_list 
    }

# ==============================================================================
# 5. FLASK ROUTES
# ==============================================================================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/extract_text', methods=['POST'])
def extract_text():
    if 'image' not in request.files: return jsonify({'error': 'No file uploaded'})
    
    files = request.files.getlist('image')
    
    if not files or files[0].filename == '': return jsonify({'error': 'No file selected'})
    
    extracted_texts = []
    
    try:
        for file in files:
            # --- INPUT VALIDATION: DOUBLE EXTENSION CHECK ---
            if file.filename.count('.') > 1 and file.filename.endswith('.exe'):
                extracted_texts.append(f"⛔ SECURITY BLOCK: '{file.filename}' detected as potential malware.")
                continue

            # --- PDF SUPPORT ---
            if file.filename.lower().endswith('.pdf'):
                # --- PERFORMANCE: SIZE CHECK (10MB) ---
                file_bytes = file.read()
                if len(file_bytes) > 10 * 1024 * 1024:
                     extracted_texts.append(f"⚠️ ERROR: '{file.filename}' > 10MB.")
                     continue
                
                try:
                    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                        # --- PERFORMANCE: PAGE LIMIT ---
                        if len(pdf.pages) > 10:
                            extracted_texts.append(f"⚠️ ERROR: '{file.filename}' too many pages (>10).")
                            continue
                            
                        pdf_text = ""
                        for page in pdf.pages:
                            extracted = page.extract_text()
                            if extracted:
                                pdf_text += extracted + "\n"
                        
                        if pdf_text.strip():
                            extracted_texts.append(pdf_text)
                        else:
                            pass 
                except Exception as e:
                    extracted_texts.append("SYSTEM_ALERT: PDF_PASSWORD_LOCKED")
                    continue 
            
            #IMAGE SUPPORT
            else:
                try:
                    image_bytes = file.read()
                    image = Image.open(io.BytesIO(image_bytes))
                    
                    # --- INPUT VALIDATION: VERIFY IMAGE ---
                    image.verify()
                    image = Image.open(io.BytesIO(image_bytes))

                    # --- QR Code Decoding ---
                    try:
                        qr_codes = decode(Image.open(io.BytesIO(image_bytes)))
                        for qr in qr_codes:
                            extracted_texts.append(f"QR CODE DATA: {qr.data.decode('utf-8')}")
                    except:
                        pass 

                    # ENABLE MULTI-LANGUAGE OCR
                    image = image.convert('L')
                    
                    if image.width > 1000 or image.height > 1000:
                        image.thumbnail((1000, 1000))
                    
                    image = ImageOps.autocontrast(image)
                    
                    try:
                        # Attempt multi-language scan
                        text = pytesseract.image_to_string(image, lang='eng+hin+tam', config='--psm 6')
                    except:
                        # Fallback
                        text = pytesseract.image_to_string(image, config='--psm 6')
                        
                    if not text.strip() or len(text) < 10:
                        text = pytesseract.image_to_string(image, config='--psm 3')
                    
                    if text.strip():
                        extracted_texts.append(text)
                    
                    # Force Cleanup
                    del image_bytes
                    del image
                    gc.collect()

                except Exception as e:
                    extracted_texts.append(f"Error processing image: {str(e)}")

        full_text = "\n\n--- [NEXT ITEM] ---\n\n".join(extracted_texts)

        if not full_text.strip():
            full_text = "System: No readable text found. \n\nAnalysis: If these images/files contain no text, they are likely SAFE."
            
        return jsonify({'text': full_text})
    except Exception as e: return jsonify({'error': str(e)})

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    text = data.get('text', '')
    source = data.get('source', 'manual') 
    
    if not text.strip(): return jsonify({'error': 'No text'})
    
    result = get_threat_analysis(text, source)
    return jsonify(result)



if __name__ == '__main__':

    app.run(debug=True, port=5000)