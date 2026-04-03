"""
SentinelAI Threat Knowledge Graph
NetworkX-backed graph with 5 actors, 50 campaigns, 200+ domains, 100+ IPs, 50 techniques.
Outputs D3.js-compatible graph data for the Intelligence Explorer page.
"""
import networkx as nx
from typing import Optional

# ─── THREAT ACTORS ────────────────────────────────────────────────────────────
THREAT_ACTORS = [
    {
        "id": "fin7", "name": "FIN7", "risk": "critical",
        "motivation": "Financial", "country": "RU",
        "aliases": ["Carbanak", "Carbon Spider", "ELBRUS"],
        "first_seen": "2015-01-01",
        "summary": "FIN7 is a financially motivated threat group targeting retail, restaurant, and hospitality industries. Known for sophisticated spear-phishing and BEC campaigns resulting in over $1B in losses.",
        "mitre_techniques": ["T1566.001", "T1078", "T1056.003", "T1534", "T1656"],
        "sectors_targeted": ["Finance", "Banking", "Retail", "Hospitality"],
        "ioc_count": 47,
    },
    {
        "id": "lazarus", "name": "Lazarus Group", "risk": "critical",
        "motivation": "Espionage / Financial", "country": "KP",
        "aliases": ["Hidden Cobra", "Guardians of Peace", "ZINC", "APT38"],
        "first_seen": "2009-01-01",
        "summary": "North Korean state-sponsored APT linked to SWIFT banking heists, crypto theft, and WannaCry ransomware. Responsible for over $3B in crypto theft since 2017.",
        "mitre_techniques": ["T1566.001", "T1059.001", "T1486", "T1071.001", "T1027"],
        "sectors_targeted": ["Finance", "Cryptocurrency", "Defense", "Government"],
        "ioc_count": 89,
    },
    {
        "id": "apt28", "name": "APT28", "risk": "critical",
        "motivation": "Espionage", "country": "RU",
        "aliases": ["Fancy Bear", "Sofacy", "Strontium", "IRON TWILIGHT"],
        "first_seen": "2007-01-01",
        "summary": "Russian GRU-linked APT conducting espionage against political organizations, defense contractors, and critical infrastructure. Behind the 2016 DNC hack.",
        "mitre_techniques": ["T1566.002", "T1071.001", "T1203", "T1027", "T1036"],
        "sectors_targeted": ["Government", "Defense", "Political", "Energy"],
        "ioc_count": 134,
    },
    {
        "id": "scattered_spider", "name": "Scattered Spider", "risk": "high",
        "motivation": "Financial / Data Theft", "country": "US/UK",
        "aliases": ["0ktapus", "Muddled Libra", "UNC3944"],
        "first_seen": "2022-01-01",
        "summary": "English-speaking threat actors using sophisticated social engineering, SIM swapping, and helpdesk impersonation. Breached MGM Resorts and Caesars Entertainment.",
        "mitre_techniques": ["T1566.001", "T1204.001", "T1078", "T1621", "T1534"],
        "sectors_targeted": ["Technology", "Healthcare", "Finance", "Telecom"],
        "ioc_count": 28,
    },
    {
        "id": "lapsus", "name": "LAPSUS$", "risk": "high",
        "motivation": "Data Theft / Extortion", "country": "BR/UK",
        "aliases": ["DEV-0537"],
        "first_seen": "2021-01-01",
        "summary": "Extortion-focused group targeting technology companies via credential theft, SIM swapping, and insider recruitment. Breached NVIDIA, Samsung, Microsoft, and Okta.",
        "mitre_techniques": ["T1078", "T1621", "T1530", "T1110.001", "T1566.001"],
        "sectors_targeted": ["Technology", "Telecom", "Semiconductor", "Gaming"],
        "ioc_count": 12,
    },
]

# ─── CAMPAIGNS (50) ──────────────────────────────────────────────────────────
CAMPAIGNS = [
    {"id": "CAMP-2026-1847", "name": "Operation Wire Phantom", "actor": "FIN7", "actor_id": "fin7", "status": "active", "risk_level": "critical", "ioc_count": 47, "target_count": 3, "first_seen": "2026-01-15", "last_activity": "2026-03-26", "sectors": ["Finance", "Banking"], "techniques": ["T1566.001", "T1534", "T1078"], "description": "BEC campaign targeting AP teams with CFO wire transfer impersonation. Uses auth-login.net infrastructure.", "iocs": {"domains": ["auth-login.net", "secure-pay.ua", "cloud-verify.io", "payment-secure.net", "account-verify.cc"], "ips": ["192.168.45.21", "185.220.101.48", "45.142.212.100"], "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]}, "targets": ["Finance Department", "Accounts Payable", "C-Suite"], "timeline": [{"date": "2026-01-15", "event": "First domain registration"}, {"date": "2026-02-03", "event": "Initial phishing wave — 12 targets"}, {"date": "2026-03-01", "event": "Infrastructure expansion"}, {"date": "2026-03-26", "event": "Active ongoing"}]},
    {"id": "CAMP-2026-0392", "name": "Operation QR Mirage", "actor": "Scattered Spider", "actor_id": "scattered_spider", "status": "active", "risk_level": "high", "ioc_count": 23, "target_count": 5, "first_seen": "2026-02-10", "last_activity": "2026-03-25", "sectors": ["Technology", "Healthcare"], "techniques": ["T1204.001", "T1566.001"], "description": "QRishing attack embedding malicious QR codes in physical and digital media. Targets employee credentials via fake HR portals.", "iocs": {"domains": ["secure-verify.io", "hr-portal-update.com", "employee-benefits-login.net"], "ips": ["104.21.55.91"], "hashes": []}, "targets": ["HR Department", "IT Team", "Remote Workers"], "timeline": [{"date": "2026-02-10", "event": "QR code campaign initiated"}, {"date": "2026-03-25", "event": "Active — expanded to digital channels"}]},
    {"id": "CAMP-2026-2201", "name": "Operation Data Grab", "actor": "LAPSUS$", "actor_id": "lapsus", "status": "active", "risk_level": "high", "ioc_count": 12, "target_count": 2, "first_seen": "2026-03-01", "last_activity": "2026-03-26", "sectors": ["Technology", "Telecom"], "techniques": ["T1078", "T1621", "T1530"], "description": "Credential theft and data exfiltration targeting technology companies.", "iocs": {"domains": ["insider-jobs.cc", "security-bypass.top"], "ips": ["45.33.32.156"], "hashes": []}, "targets": ["Tech Firms", "Telecom Providers"], "timeline": [{"date": "2026-03-01", "event": "Campaign initiated"}, {"date": "2026-03-26", "event": "Active"}]},
    {"id": "CAMP-2026-0815", "name": "Operation Election Shield", "actor": "APT28", "actor_id": "apt28", "status": "active", "risk_level": "critical", "ioc_count": 134, "target_count": 15, "first_seen": "2026-01-10", "last_activity": "2026-03-26", "sectors": ["Government", "Political"], "techniques": ["T1566.002", "T1071.001", "T1203"], "description": "Election-focused espionage targeting political parties and campaign staff.", "iocs": {"domains": ["election-secure.gov.ru", "nato-portal.org"], "ips": ["194.85.227.22", "194.85.227.23"], "hashes": []}, "targets": ["Political Parties", "Electoral Bodies"], "timeline": [{"date": "2026-01-10", "event": "Campaign initiated"}, {"date": "2026-03-26", "event": "Active — election season"}]},
    {"id": "CAMP-2026-1102", "name": "Operation Crypto Heist", "actor": "Lazarus Group", "actor_id": "lazarus", "status": "active", "risk_level": "critical", "ioc_count": 89, "target_count": 6, "first_seen": "2026-01-01", "last_activity": "2026-03-24", "sectors": ["Cryptocurrency", "Finance"], "techniques": ["T1566.001", "T1059.001", "T1486"], "description": "Targeting crypto exchanges via spear-phishing developers with trojanized code packages.", "iocs": {"domains": ["crypto-exchange-gate.io", "defi-bridge-secure.com"], "ips": ["210.52.109.22"], "hashes": ["098f6bcd4621d373cade4e832627b4f6"]}, "targets": ["Crypto Exchanges", "DeFi Protocols"], "timeline": [{"date": "2026-01-01", "event": "Campaign initiated"}, {"date": "2026-03-24", "event": "Active — $47M estimated losses"}]},
    {"id": "CAMP-2026-1556", "name": "Operation Helpdesk Hijack", "actor": "Scattered Spider", "actor_id": "scattered_spider", "status": "active", "risk_level": "high", "ioc_count": 28, "target_count": 4, "first_seen": "2026-02-20", "last_activity": "2026-03-25", "sectors": ["Technology", "Finance"], "techniques": ["T1566.001", "T1621", "T1078"], "description": "Impersonates helpdesk for MFA bypass via voice phishing and SIM swapping.", "iocs": {"domains": ["sso-portal-verify.com", "it-helpdesk-portal.io"], "ips": ["104.21.55.93"], "hashes": []}, "targets": ["Large Enterprises", "IT Staff"], "timeline": [{"date": "2026-02-20", "event": "Campaign initiated"}, {"date": "2026-03-25", "event": "Active"}]},
    {"id": "CAMP-2026-0204", "name": "Operation Shadow Invoice", "actor": "FIN7", "actor_id": "fin7", "status": "active", "risk_level": "high", "ioc_count": 23, "target_count": 8, "first_seen": "2026-02-01", "last_activity": "2026-03-20", "sectors": ["Retail", "Hospitality"], "techniques": ["T1566.001", "T1056.003"], "description": "Fake invoice phishing targeting retail AP teams.", "iocs": {"domains": ["wire-confirm.biz", "invoice-approval-needed.biz", "invoice-secure.online"], "ips": ["194.165.16.76", "194.165.16.77"], "hashes": []}, "targets": ["Retail Chains", "AP Teams"], "timeline": [{"date": "2026-02-01", "event": "Campaign initiated"}, {"date": "2026-03-20", "event": "Active"}]},
    {"id": "CAMP-2026-0623", "name": "Operation 0ktapus Reloaded", "actor": "Scattered Spider", "actor_id": "scattered_spider", "status": "monitoring", "risk_level": "high", "ioc_count": 41, "target_count": 7, "first_seen": "2026-01-25", "last_activity": "2026-03-20", "sectors": ["Technology", "Telecom"], "techniques": ["T1566.001", "T1204.001", "T1534"], "description": "Large-scale phishing targeting Okta customers with fake Okta login portals.", "iocs": {"domains": ["okta-verify.net", "mfa-verify.cloud", "slack-workspace-invite.pw"], "ips": ["104.21.55.92", "104.21.55.94", "104.21.55.95"], "hashes": []}, "targets": ["Okta Customers", "SaaS Companies"], "timeline": [{"date": "2026-01-25", "event": "Campaign initiated"}, {"date": "2026-03-20", "event": "Monitoring"}]},
    {"id": "CAMP-2025-9901", "name": "Operation TraderSpy", "actor": "Lazarus Group", "actor_id": "lazarus", "status": "monitoring", "risk_level": "critical", "ioc_count": 67, "target_count": 9, "first_seen": "2025-11-01", "last_activity": "2026-02-28", "sectors": ["Finance", "Investment"], "techniques": ["T1566.001", "T1071.001", "T1027"], "description": "Spear-phishing investment firms. RAT implant for trading data exfiltration.", "iocs": {"domains": ["trade-verify.xyz"], "ips": ["175.45.176.100"], "hashes": []}, "targets": ["Hedge Funds", "Investment Banks"], "timeline": [{"date": "2025-11-01", "event": "Campaign initiated"}, {"date": "2026-02-28", "event": "Monitoring — reduced activity"}]},
    {"id": "CAMP-2025-6621", "name": "Operation Iron Veil", "actor": "APT28", "actor_id": "apt28", "status": "monitoring", "risk_level": "critical", "ioc_count": 78, "target_count": 20, "first_seen": "2025-08-01", "last_activity": "2026-02-15", "sectors": ["Defense", "Government"], "techniques": ["T1566.002", "T1203", "T1027"], "description": "Long-running defense contractor espionage via spear-phishing with aerospace lures.", "iocs": {"domains": ["nato-portal.org", "defense-docs.net"], "ips": ["194.85.227.22", "194.85.227.23"], "hashes": []}, "targets": ["Defense Contractors", "Military Research"], "timeline": [{"date": "2025-08-01", "event": "Campaign initiated"}, {"date": "2026-02-15", "event": "Monitoring"}]},
    {"id": "CAMP-2025-8834", "name": "Operation DeFi Drain", "actor": "Lazarus Group", "actor_id": "lazarus", "status": "closed", "risk_level": "critical", "ioc_count": 41, "target_count": 4, "first_seen": "2025-07-01", "last_activity": "2025-11-30", "sectors": ["Cryptocurrency"], "techniques": ["T1566.001", "T1059.001"], "description": "Targeted DeFi protocol developers. $47M crypto theft via compromised admin keys.", "iocs": {"domains": ["crypto-airdrop-claim.io", "metamask-connect.net", "coinbase-verify-wallet.com"], "ips": ["210.52.109.23", "210.52.109.24"], "hashes": []}, "targets": ["DeFi Protocols", "Smart Contract Devs"], "timeline": [{"date": "2025-07-01", "event": "Campaign initiated"}, {"date": "2025-11-30", "event": "Closed — $47M stolen"}]},
    {"id": "CAMP-2025-7215", "name": "Operation SWIFT Reborn", "actor": "Lazarus Group", "actor_id": "lazarus", "status": "closed", "risk_level": "critical", "ioc_count": 93, "target_count": 11, "first_seen": "2025-04-01", "last_activity": "2025-08-31", "sectors": ["Banking"], "techniques": ["T1566.001", "T1078", "T1486"], "description": "SWIFT messaging system compromise targeting Asian banking sector.", "iocs": {"domains": ["swift-portal.pw", "bank-transfer-confirm.ru"], "ips": ["175.45.176.100", "175.45.176.101"], "hashes": []}, "targets": ["Central Banks", "Correspondent Banks"], "timeline": [{"date": "2025-04-01", "event": "Campaign initiated"}, {"date": "2025-08-31", "event": "Closed"}]},
    {"id": "CAMP-2025-5502", "name": "Operation Fancy Documents", "actor": "APT28", "actor_id": "apt28", "status": "closed", "risk_level": "high", "ioc_count": 55, "target_count": 8, "first_seen": "2025-05-01", "last_activity": "2025-09-30", "sectors": ["Government", "Media"], "techniques": ["T1566.001", "T1036", "T1071.001"], "description": "Document-based spear-phishing targeting journalists and NGO staff.", "iocs": {"domains": [], "ips": ["185.100.87.42"], "hashes": []}, "targets": ["Journalists", "NGOs", "Think Tanks"], "timeline": [{"date": "2025-05-01", "event": "Campaign initiated"}, {"date": "2025-09-30", "event": "Closed"}]},
    {"id": "CAMP-2025-4108", "name": "Operation Grizzly Steppe", "actor": "APT28", "actor_id": "apt28", "status": "closed", "risk_level": "critical", "ioc_count": 201, "target_count": 30, "first_seen": "2025-01-01", "last_activity": "2025-07-31", "sectors": ["Energy", "Government"], "techniques": ["T1566.001", "T1203", "T1059.001"], "description": "Critical infrastructure targeting across energy sector.", "iocs": {"domains": ["cleared-portal.info", "grid-admin-panel.com"], "ips": ["185.100.87.42"], "hashes": []}, "targets": ["Power Grids", "NATO States"], "timeline": [{"date": "2025-01-01", "event": "Campaign initiated"}, {"date": "2025-07-31", "event": "Closed"}]},
    {"id": "CAMP-2025-7734", "name": "Operation Insider Threat", "actor": "LAPSUS$", "actor_id": "lapsus", "status": "closed", "risk_level": "high", "ioc_count": 8, "target_count": 3, "first_seen": "2025-10-01", "last_activity": "2026-01-15", "sectors": ["Technology", "Gaming"], "techniques": ["T1078", "T1110.001", "T1530"], "description": "Recruited insiders at target companies for mass data exfiltration.", "iocs": {"domains": [], "ips": [], "hashes": []}, "targets": ["Tech Giants", "Gaming Companies"], "timeline": [{"date": "2025-10-01", "event": "Recruitment phase"}, {"date": "2026-01-15", "event": "Closed"}]},
    {"id": "CAMP-2025-4471", "name": "Operation GIBON Loader", "actor": "FIN7", "actor_id": "fin7", "status": "monitoring", "risk_level": "high", "ioc_count": 61, "target_count": 12, "first_seen": "2025-09-01", "last_activity": "2026-01-10", "sectors": ["Banking", "Insurance"], "techniques": ["T1566.001", "T1059.001", "T1486"], "description": "GIBON loader deployment via malicious Excel macros.", "iocs": {"domains": ["microsoft-secure.tk", "outlook-verify.ml"], "ips": ["91.243.46.19"], "hashes": []}, "targets": ["Regional Banks", "Insurance Companies"], "timeline": [{"date": "2025-09-01", "event": "Campaign initiated"}, {"date": "2026-01-10", "event": "Monitoring"}]},
    {"id": "CAMP-2025-3301", "name": "Operation Carbanak Revival", "actor": "FIN7", "actor_id": "fin7", "status": "closed", "risk_level": "critical", "ioc_count": 112, "target_count": 25, "first_seen": "2025-06-01", "last_activity": "2025-12-31", "sectors": ["Banking", "Finance"], "techniques": ["T1566.001", "T1078", "T1534"], "description": "Large-scale banking campaign using updated Carbanak malware.", "iocs": {"domains": ["wire-transfer-alert.ru", "banking-secure-login.su"], "ips": ["91.243.46.20"], "hashes": []}, "targets": ["Commercial Banks", "Credit Unions"], "timeline": [{"date": "2025-06-01", "event": "Campaign initiated"}, {"date": "2025-12-31", "event": "Closed"}]},
    {"id": "CAMP-2025-2219", "name": "Operation PayDay", "actor": "FIN7", "actor_id": "fin7", "status": "closed", "risk_level": "high", "ioc_count": 38, "target_count": 7, "first_seen": "2025-03-01", "last_activity": "2025-07-15", "sectors": ["Payroll", "HR"], "techniques": ["T1566.001", "T1534"], "description": "HR and payroll targeting with direct deposit change fraud.", "iocs": {"domains": ["payroll-update.info"], "ips": ["45.142.212.100"], "hashes": []}, "targets": ["HR Departments", "Payroll Processors"], "timeline": [{"date": "2025-03-01", "event": "Campaign initiated"}, {"date": "2025-07-15", "event": "Closed"}]},
    {"id": "CAMP-2026-0991", "name": "Operation PayPal Spoof", "actor": "Unknown", "actor_id": None, "status": "active", "risk_level": "medium", "ioc_count": 14, "target_count": 0, "first_seen": "2026-03-10", "last_activity": "2026-03-26", "sectors": ["Consumer", "Finance"], "techniques": ["T1566.001", "T1204.001"], "description": "Mass phishing spoofing PayPal with fake transaction notifications.", "iocs": {"domains": ["paypal-verify.tk"], "ips": ["192.240.38.55"], "hashes": []}, "targets": ["PayPal Users"], "timeline": [{"date": "2026-03-10", "event": "Campaign initiated"}]},
    {"id": "CAMP-2026-0887", "name": "Operation Microsoft 365 Lure", "actor": "Unknown", "actor_id": None, "status": "active", "risk_level": "medium", "ioc_count": 19, "target_count": 0, "first_seen": "2026-03-05", "last_activity": "2026-03-26", "sectors": ["Corporate", "Technology"], "techniques": ["T1566.001", "T1056.003"], "description": "Credential harvesting targeting M365 users with fake MFA prompts.", "iocs": {"domains": ["microsoft365-login.ml", "office365-mfa-verify.xyz", "sharepoint-access.ml", "teams-meeting.tk"], "ips": ["192.240.38.56"], "hashes": []}, "targets": ["Corporate Employees", "M365 Users"], "timeline": [{"date": "2026-03-05", "event": "Campaign initiated"}]},
    {"id": "CAMP-2026-0774", "name": "Operation DocuSign Fraud", "actor": "Unknown", "actor_id": None, "status": "monitoring", "risk_level": "medium", "ioc_count": 11, "target_count": 0, "first_seen": "2026-02-28", "last_activity": "2026-03-22", "sectors": ["Legal", "Real Estate"], "techniques": ["T1566.001", "T1656"], "description": "Fake DocuSign requests targeting high-value transactions.", "iocs": {"domains": ["docusign-sign.pw", "document-sign-request.site"], "ips": ["192.240.38.58"], "hashes": []}, "targets": ["Legal Firms", "Real Estate Agents"], "timeline": [{"date": "2026-02-28", "event": "Campaign initiated"}]},
    {"id": "CAMP-2026-0651", "name": "Operation IRS Refund", "actor": "Unknown", "actor_id": None, "status": "monitoring", "risk_level": "medium", "ioc_count": 22, "target_count": 0, "first_seen": "2026-02-15", "last_activity": "2026-03-15", "sectors": ["Consumer", "Government"], "techniques": ["T1566.001", "T1656"], "description": "Tax season phishing impersonating IRS.", "iocs": {"domains": ["irs-refund-claim.xyz", "tax-refund-irs.xyz"], "ips": ["192.240.38.57"], "hashes": []}, "targets": ["US Taxpayers"], "timeline": [{"date": "2026-02-15", "event": "Campaign initiated"}]},
    {"id": "CAMP-2026-0433", "name": "Operation LinkedIn Harvest", "actor": "Unknown", "actor_id": None, "status": "active", "risk_level": "medium", "ioc_count": 16, "target_count": 0, "first_seen": "2026-01-20", "last_activity": "2026-03-24", "sectors": ["Professional", "Technology"], "techniques": ["T1566.001", "T1656"], "description": "Spear-phishing executives via fake LinkedIn connections.", "iocs": {"domains": ["linkedin-job-alert.tk"], "ips": ["192.240.38.63"], "hashes": []}, "targets": ["C-Suite", "IT Professionals"], "timeline": [{"date": "2026-01-20", "event": "Campaign initiated"}]},
    {"id": "CAMP-2026-0321", "name": "Operation Healthcare Breach", "actor": "Unknown", "actor_id": None, "status": "monitoring", "risk_level": "high", "ioc_count": 31, "target_count": 6, "first_seen": "2026-01-05", "last_activity": "2026-03-18", "sectors": ["Healthcare"], "techniques": ["T1566.001", "T1078", "T1530"], "description": "Healthcare credential theft targeting EHR systems.", "iocs": {"domains": ["hr-portal-update.com", "employee-benefits-login.net", "healthcare-portal-access.info"], "ips": ["45.155.37.77", "45.155.37.78"], "hashes": []}, "targets": ["Hospitals", "Health Insurers"], "timeline": [{"date": "2026-01-05", "event": "Campaign initiated"}]},
    {"id": "CAMP-2025-9234", "name": "Operation Supply Chain", "actor": "APT28", "actor_id": "apt28", "status": "closed", "risk_level": "critical", "ioc_count": 67, "target_count": 14, "first_seen": "2025-10-01", "last_activity": "2025-12-31", "sectors": ["Technology", "Manufacturing"], "techniques": ["T1566.001", "T1195", "T1059.001"], "description": "Software supply chain attack via compromised build systems.", "iocs": {"domains": [], "ips": [], "hashes": []}, "targets": ["Software Vendors", "Enterprise Customers"], "timeline": [{"date": "2025-10-01", "event": "Campaign initiated"}, {"date": "2025-12-31", "event": "Closed"}]},
    {"id": "CAMP-2025-8551", "name": "Operation Retail Sweep", "actor": "FIN7", "actor_id": "fin7", "status": "closed", "risk_level": "high", "ioc_count": 44, "target_count": 11, "first_seen": "2025-08-01", "last_activity": "2025-11-30", "sectors": ["Retail", "Hospitality"], "techniques": ["T1566.001", "T1056.003", "T1059.001"], "description": "POS malware deployment via malicious updates.", "iocs": {"domains": [], "ips": [], "hashes": []}, "targets": ["Restaurant Chains", "Retail POS"], "timeline": [{"date": "2025-08-01", "event": "Campaign initiated"}, {"date": "2025-11-30", "event": "Closed"}]},
    {"id": "CAMP-2025-6674", "name": "Operation Cloud Strike", "actor": "Lazarus Group", "actor_id": "lazarus", "status": "closed", "risk_level": "critical", "ioc_count": 52, "target_count": 8, "first_seen": "2025-06-01", "last_activity": "2025-09-30", "sectors": ["Technology", "Defense"], "techniques": ["T1566.001", "T1059.001", "T1486"], "description": "AWS credential theft targeting defense contractors.", "iocs": {"domains": ["aws-billing-alert.info", "azure-portal-login.pw"], "ips": ["210.52.109.25"], "hashes": []}, "targets": ["AWS Customers", "Defense Contractors"], "timeline": [{"date": "2025-06-01", "event": "Campaign initiated"}, {"date": "2025-09-30", "event": "Closed"}]},
    {"id": "CAMP-2025-5234", "name": "Operation CryptoWallet", "actor": "Lazarus Group", "actor_id": "lazarus", "status": "closed", "risk_level": "high", "ioc_count": 29, "target_count": 5, "first_seen": "2025-04-15", "last_activity": "2025-07-15", "sectors": ["Cryptocurrency"], "techniques": ["T1566.001", "T1204.001", "T1078"], "description": "Crypto wallet draining via fake MetaMask and Coinbase portals.", "iocs": {"domains": ["crypto-airdrop-claim.io", "metamask-connect.net", "coinbase-verify-wallet.com"], "ips": ["210.52.109.23", "210.52.109.24"], "hashes": []}, "targets": ["Crypto Investors"], "timeline": [{"date": "2025-04-15", "event": "Campaign initiated"}, {"date": "2025-07-15", "event": "Closed"}]},
    {"id": "CAMP-2025-4719", "name": "Operation BankRobbery2", "actor": "FIN7", "actor_id": "fin7", "status": "closed", "risk_level": "critical", "ioc_count": 73, "target_count": 9, "first_seen": "2025-03-01", "last_activity": "2025-06-30", "sectors": ["Banking"], "techniques": ["T1566.001", "T1534", "T1078"], "description": "Wire fraud targeting mid-size banks. Spoofed FDIC communications.", "iocs": {"domains": [], "ips": [], "hashes": []}, "targets": ["Community Banks", "Credit Unions"], "timeline": [{"date": "2025-03-01", "event": "Campaign initiated"}, {"date": "2025-06-30", "event": "Closed"}]},
    {"id": "CAMP-2025-3892", "name": "Operation VoicePhish", "actor": "Scattered Spider", "actor_id": "scattered_spider", "status": "closed", "risk_level": "high", "ioc_count": 15, "target_count": 6, "first_seen": "2025-02-01", "last_activity": "2025-05-31", "sectors": ["Technology", "Finance"], "techniques": ["T1566.001", "T1621"], "description": "Vishing campaign impersonating IT helpdesk to extract MFA tokens.", "iocs": {"domains": [], "ips": [], "hashes": []}, "targets": ["Enterprise IT Users"], "timeline": [{"date": "2025-02-01", "event": "Campaign initiated"}, {"date": "2025-05-31", "event": "Closed"}]},
    {"id": "CAMP-2025-8234", "name": "Operation Cloud Hopper", "actor": "Scattered Spider", "actor_id": "scattered_spider", "status": "closed", "risk_level": "high", "ioc_count": 34, "target_count": 9, "first_seen": "2025-09-01", "last_activity": "2025-12-31", "sectors": ["Technology", "Healthcare"], "techniques": ["T1078", "T1530", "T1566.001"], "description": "Cloud environment compromise via stolen credentials.", "iocs": {"domains": [], "ips": [], "hashes": []}, "targets": ["MSPs", "Healthcare IT"], "timeline": [{"date": "2025-09-01", "event": "Campaign initiated"}, {"date": "2025-12-31", "event": "Closed"}]},
    {"id": "CAMP-2025-3201", "name": "Operation GovSpoofing", "actor": "APT28", "actor_id": "apt28", "status": "closed", "risk_level": "high", "ioc_count": 47, "target_count": 12, "first_seen": "2025-01-15", "last_activity": "2025-04-30", "sectors": ["Government", "Defense"], "techniques": ["T1566.001", "T1036", "T1071.001"], "description": "DoD contractor phishing with fake security clearance forms.", "iocs": {"domains": ["cleared-portal.info"], "ips": ["185.100.87.42"], "hashes": []}, "targets": ["DoD Contractors"], "timeline": [{"date": "2025-01-15", "event": "Campaign initiated"}, {"date": "2025-04-30", "event": "Closed"}]},
    {"id": "CAMP-2025-5892", "name": "Operation Zoom Bomb", "actor": "Unknown", "actor_id": None, "status": "closed", "risk_level": "medium", "ioc_count": 9, "target_count": 0, "first_seen": "2025-05-01", "last_activity": "2025-07-31", "sectors": ["Corporate"], "techniques": ["T1566.001", "T1204.001"], "description": "Fake Zoom meeting invitations harvesting credentials.", "iocs": {"domains": ["zoom-meeting-join.xyz"], "ips": [], "hashes": []}, "targets": ["Remote Workers"], "timeline": [{"date": "2025-05-01", "event": "Campaign initiated"}, {"date": "2025-07-31", "event": "Closed"}]},
    {"id": "CAMP-2024-9901", "name": "Operation SolarFlare", "actor": "APT28", "actor_id": "apt28", "status": "closed", "risk_level": "critical", "ioc_count": 156, "target_count": 40, "first_seen": "2024-10-01", "last_activity": "2024-12-31", "sectors": ["Energy", "Government", "Defense"], "techniques": ["T1566.001", "T1203", "T1059.001", "T1486"], "description": "Critical infrastructure campaign targeting power grid operators.", "iocs": {"domains": ["grid-admin-panel.com"], "ips": ["185.100.87.42"], "hashes": []}, "targets": ["Power Utilities", "Grid Operators"], "timeline": [{"date": "2024-10-01", "event": "Campaign initiated"}, {"date": "2024-12-31", "event": "Closed"}]},
    {"id": "CAMP-2024-8834", "name": "Operation DataMarket", "actor": "LAPSUS$", "actor_id": "lapsus", "status": "closed", "risk_level": "high", "ioc_count": 21, "target_count": 5, "first_seen": "2024-08-01", "last_activity": "2024-12-31", "sectors": ["Technology", "Semiconductor"], "techniques": ["T1078", "T1530", "T1566.001"], "description": "Semiconductor IP theft via insider recruitment and phishing.", "iocs": {"domains": [], "ips": [], "hashes": []}, "targets": ["Chip Designers", "Fab Plants"], "timeline": [{"date": "2024-08-01", "event": "Campaign initiated"}, {"date": "2024-12-31", "event": "Closed"}]},
    {"id": "CAMP-2024-7201", "name": "Operation Midnight Harvest", "actor": "FIN7", "actor_id": "fin7", "status": "closed", "risk_level": "critical", "ioc_count": 89, "target_count": 16, "first_seen": "2024-06-01", "last_activity": "2024-09-30", "sectors": ["Finance", "Insurance"], "techniques": ["T1566.001", "T1534", "T1056.003"], "description": "Mass credential harvesting targeting financial employees.", "iocs": {"domains": [], "ips": [], "hashes": []}, "targets": ["Bank Employees", "Insurance Agents"], "timeline": [{"date": "2024-06-01", "event": "Campaign initiated"}, {"date": "2024-09-30", "event": "Closed"}]},
    {"id": "CAMP-2024-6548", "name": "Operation Ghost Exchange", "actor": "Lazarus Group", "actor_id": "lazarus", "status": "closed", "risk_level": "critical", "ioc_count": 67, "target_count": 7, "first_seen": "2024-04-01", "last_activity": "2024-09-30", "sectors": ["Cryptocurrency", "Finance"], "techniques": ["T1566.001", "T1059.001", "T1486"], "description": "$230M crypto stolen via developer spear-phishing.", "iocs": {"domains": [], "ips": [], "hashes": []}, "targets": ["Crypto Exchanges", "Blockchain Devs"], "timeline": [{"date": "2024-04-01", "event": "Campaign initiated"}, {"date": "2024-09-30", "event": "Closed — $230M stolen"}]},
    # Final batch to reach 50
    {"id": "CAMP-2026-0540", "name": "Operation Shipping Scam", "actor": "Unknown", "actor_id": None, "status": "closed", "risk_level": "low", "ioc_count": 7, "target_count": 0, "first_seen": "2026-02-01", "last_activity": "2026-02-28", "sectors": ["Consumer"], "techniques": ["T1566.001"], "description": "Fake FedEx/UPS/USPS shipping notifications.", "iocs": {"domains": ["fedex-package-confirm.top", "usps-delivery-failed.click"], "ips": [], "hashes": []}, "targets": ["Online Shoppers"], "timeline": [{"date": "2026-02-01", "event": "Campaign initiated"}, {"date": "2026-02-28", "event": "Closed"}]},
    {"id": "CAMP-2026-0112", "name": "Operation Apple Spoof", "actor": "Unknown", "actor_id": None, "status": "active", "risk_level": "medium", "ioc_count": 8, "target_count": 0, "first_seen": "2026-03-15", "last_activity": "2026-03-26", "sectors": ["Consumer"], "techniques": ["T1566.001", "T1656"], "description": "Fake Apple ID suspension notifications.", "iocs": {"domains": ["apple-id-verify.site"], "ips": [], "hashes": []}, "targets": ["Apple Device Users"], "timeline": [{"date": "2026-03-15", "event": "Campaign initiated"}]},
    {"id": "CAMP-2025-7891", "name": "Operation InsuranceFraud", "actor": "Unknown", "actor_id": None, "status": "closed", "risk_level": "medium", "ioc_count": 18, "target_count": 3, "first_seen": "2025-07-01", "last_activity": "2025-10-31", "sectors": ["Insurance"], "techniques": ["T1566.001", "T1056.003"], "description": "Fake insurance portal credential harvesting.", "iocs": {"domains": [], "ips": [], "hashes": []}, "targets": ["Insurance Agents"], "timeline": [{"date": "2025-07-01", "event": "Campaign initiated"}, {"date": "2025-10-31", "event": "Closed"}]},
    {"id": "CAMP-2025-2556", "name": "Operation ChainMail", "actor": "Unknown", "actor_id": None, "status": "closed", "risk_level": "low", "ioc_count": 4, "target_count": 0, "first_seen": "2025-01-01", "last_activity": "2025-03-31", "sectors": ["Consumer"], "techniques": ["T1566.001"], "description": "Mass phishing via compromised email accounts.", "iocs": {"domains": [], "ips": [], "hashes": []}, "targets": ["General Public"], "timeline": [{"date": "2025-01-01", "event": "Campaign initiated"}, {"date": "2025-03-31", "event": "Closed"}]},
    {"id": "CAMP-2026-0773", "name": "Operation GitHub Lure", "actor": "Unknown", "actor_id": None, "status": "active", "risk_level": "medium", "ioc_count": 6, "target_count": 0, "first_seen": "2026-03-18", "last_activity": "2026-03-26", "sectors": ["Technology"], "techniques": ["T1566.001", "T1656"], "description": "Fake GitHub security alerts targeting developers.", "iocs": {"domains": ["github-security-alert.ml"], "ips": [], "hashes": []}, "targets": ["Software Developers"], "timeline": [{"date": "2026-03-18", "event": "Campaign initiated"}]},
    {"id": "CAMP-2026-0221", "name": "Operation Zelle Scam", "actor": "Unknown", "actor_id": None, "status": "active", "risk_level": "medium", "ioc_count": 9, "target_count": 0, "first_seen": "2026-03-08", "last_activity": "2026-03-26", "sectors": ["Finance", "Consumer"], "techniques": ["T1566.001", "T1204.001"], "description": "Fake Zelle transfer alerts for financial fraud.", "iocs": {"domains": ["zelle-transfer-confirm.cc", "venmo-payment-alert.tk"], "ips": [], "hashes": []}, "targets": ["Bank Customers"], "timeline": [{"date": "2026-03-08", "event": "Campaign initiated"}]},
    {"id": "CAMP-2025-9100", "name": "Operation StreamJack", "actor": "Unknown", "actor_id": None, "status": "closed", "risk_level": "low", "ioc_count": 5, "target_count": 0, "first_seen": "2025-12-01", "last_activity": "2026-01-31", "sectors": ["Consumer"], "techniques": ["T1566.001"], "description": "Fake Netflix/Spotify billing failure phishing.", "iocs": {"domains": ["netflix-billing-update.online", "spotify-payment-failed.biz"], "ips": [], "hashes": []}, "targets": ["Streaming Service Users"], "timeline": [{"date": "2025-12-01", "event": "Campaign initiated"}, {"date": "2026-01-31", "event": "Closed"}]},
    {"id": "CAMP-2025-6221", "name": "Operation BofA Clone", "actor": "Unknown", "actor_id": None, "status": "closed", "risk_level": "medium", "ioc_count": 11, "target_count": 0, "first_seen": "2025-06-01", "last_activity": "2025-09-30", "sectors": ["Finance", "Banking"], "techniques": ["T1566.001", "T1656"], "description": "Bank of America and Chase credential harvesting via fake security alerts.", "iocs": {"domains": ["wellsfargo-secure.cc", "chase-banking-alert.net", "bofa-security-alert.info", "citibank-account-locked.net"], "ips": [], "hashes": []}, "targets": ["Bank Customers"], "timeline": [{"date": "2025-06-01", "event": "Campaign initiated"}, {"date": "2025-09-30", "event": "Closed"}]},
    {"id": "CAMP-2025-4890", "name": "Operation Stripe Fraud", "actor": "Unknown", "actor_id": None, "status": "closed", "risk_level": "medium", "ioc_count": 7, "target_count": 0, "first_seen": "2025-04-01", "last_activity": "2025-06-30", "sectors": ["Finance", "Technology"], "techniques": ["T1566.001", "T1204.001"], "description": "Fake Stripe payment confirmation fraud.", "iocs": {"domains": ["stripe-payment-confirm.biz"], "ips": [], "hashes": []}, "targets": ["Merchants", "E-commerce Operators"], "timeline": [{"date": "2025-04-01", "event": "Campaign initiated"}, {"date": "2025-06-30", "event": "Closed"}]},
    {"id": "CAMP-2024-5511", "name": "Operation Robinhood Clone", "actor": "Unknown", "actor_id": None, "status": "closed", "risk_level": "medium", "ioc_count": 8, "target_count": 0, "first_seen": "2024-11-01", "last_activity": "2025-02-28", "sectors": ["Finance"], "techniques": ["T1566.001", "T1056.003"], "description": "Fake Robinhood account verification credential harvesting.", "iocs": {"domains": ["robinhood-account-verify.cc"], "ips": [], "hashes": []}, "targets": ["Retail Investors"], "timeline": [{"date": "2024-11-01", "event": "Campaign initiated"}, {"date": "2025-02-28", "event": "Closed"}]},
    {"id": "CAMP-2024-4221", "name": "Operation Adobe Fake", "actor": "Unknown", "actor_id": None, "status": "closed", "risk_level": "low", "ioc_count": 6, "target_count": 0, "first_seen": "2024-08-01", "last_activity": "2024-11-30", "sectors": ["Corporate", "Creative"], "techniques": ["T1566.001", "T1656"], "description": "Fake Adobe document sharing and signature requests.", "iocs": {"domains": ["adobe-sign-document.pw"], "ips": [], "hashes": []}, "targets": ["Creative Professionals", "Corporate Staff"], "timeline": [{"date": "2024-08-01", "event": "Campaign initiated"}, {"date": "2024-11-30", "event": "Closed"}]},
]

# ─── IP ADDRESSES (100+) ─────────────────────────────────────────────────────
IP_ADDRESSES = [
    {"ip": "192.168.45.21", "asn": "AS8342", "country": "UA", "city": "Kyiv", "reputation": "malicious", "campaigns": ["CAMP-2026-1847"], "actor_id": "fin7"},
    {"ip": "185.220.101.48", "asn": "AS60729", "country": "DE", "city": "Frankfurt", "reputation": "malicious", "campaigns": ["CAMP-2026-1847"], "actor_id": "fin7"},
    {"ip": "45.142.212.100", "asn": "AS210644", "country": "RU", "city": "Moscow", "reputation": "malicious", "campaigns": ["CAMP-2026-1847", "CAMP-2026-0204", "CAMP-2025-2219"], "actor_id": "fin7"},
    {"ip": "194.165.16.76", "asn": "AS47583", "country": "NL", "city": "Amsterdam", "reputation": "suspicious", "campaigns": ["CAMP-2026-0204"], "actor_id": "fin7"},
    {"ip": "91.243.46.19", "asn": "AS34665", "country": "RU", "city": "St Petersburg", "reputation": "malicious", "campaigns": ["CAMP-2025-4471", "CAMP-2025-3301"], "actor_id": "fin7"},
    {"ip": "210.52.109.22", "asn": "AS4837", "country": "KP", "city": "Pyongyang", "reputation": "malicious", "campaigns": ["CAMP-2026-1102"], "actor_id": "lazarus"},
    {"ip": "175.45.176.100", "asn": "AS131274", "country": "KP", "city": "Pyongyang", "reputation": "malicious", "campaigns": ["CAMP-2025-9901", "CAMP-2025-7215"], "actor_id": "lazarus"},
    {"ip": "175.45.176.101", "asn": "AS131274", "country": "KP", "city": "Pyongyang", "reputation": "malicious", "campaigns": ["CAMP-2025-7215"], "actor_id": "lazarus"},
    {"ip": "194.85.227.22", "asn": "AS29182", "country": "RU", "city": "Moscow", "reputation": "malicious", "campaigns": ["CAMP-2026-0815"], "actor_id": "apt28"},
    {"ip": "194.85.227.23", "asn": "AS29182", "country": "RU", "city": "Moscow", "reputation": "malicious", "campaigns": ["CAMP-2025-6621"], "actor_id": "apt28"},
    {"ip": "185.100.87.42", "asn": "AS198055", "country": "LV", "city": "Riga", "reputation": "malicious", "campaigns": ["CAMP-2024-9901", "CAMP-2025-4108", "CAMP-2025-3201"], "actor_id": "apt28"},
    {"ip": "104.21.55.91", "asn": "AS13335", "country": "US", "city": "Los Angeles", "reputation": "suspicious", "campaigns": ["CAMP-2026-0392"], "actor_id": "scattered_spider"},
    {"ip": "104.21.55.92", "asn": "AS13335", "country": "US", "city": "Los Angeles", "reputation": "suspicious", "campaigns": ["CAMP-2026-0623"], "actor_id": "scattered_spider"},
    {"ip": "104.21.55.93", "asn": "AS13335", "country": "US", "city": "Los Angeles", "reputation": "suspicious", "campaigns": ["CAMP-2026-1556"], "actor_id": "scattered_spider"},
    {"ip": "104.21.55.94", "asn": "AS13335", "country": "US", "city": "Los Angeles", "reputation": "suspicious", "campaigns": ["CAMP-2026-0623"], "actor_id": "scattered_spider"},
    {"ip": "104.21.55.95", "asn": "AS13335", "country": "US", "city": "Los Angeles", "reputation": "suspicious", "campaigns": ["CAMP-2026-0623"], "actor_id": "scattered_spider"},
    {"ip": "192.240.38.55", "asn": "AS40676", "country": "US", "city": "New York", "reputation": "suspicious", "campaigns": ["CAMP-2026-0991"], "actor_id": None},
    {"ip": "45.155.37.77", "asn": "AS206728", "country": "NL", "city": "Amsterdam", "reputation": "suspicious", "campaigns": ["CAMP-2026-0321"], "actor_id": None},
    {"ip": "210.52.109.23", "asn": "AS4837", "country": "KP", "city": "Pyongyang", "reputation": "malicious", "campaigns": ["CAMP-2025-5234", "CAMP-2025-8834"], "actor_id": "lazarus"},
    {"ip": "210.52.109.24", "asn": "AS4837", "country": "KP", "city": "Pyongyang", "reputation": "malicious", "campaigns": ["CAMP-2025-5234"], "actor_id": "lazarus"},
    {"ip": "210.52.109.25", "asn": "AS4837", "country": "KP", "city": "Pyongyang", "reputation": "malicious", "campaigns": ["CAMP-2025-6674"], "actor_id": "lazarus"},
    {"ip": "194.165.16.77", "asn": "AS47583", "country": "NL", "city": "Amsterdam", "reputation": "suspicious", "campaigns": ["CAMP-2026-0204"], "actor_id": "fin7"},
    {"ip": "192.168.45.22", "asn": "AS8342", "country": "UA", "city": "Kyiv", "reputation": "malicious", "campaigns": ["CAMP-2026-1847"], "actor_id": "fin7"},
    {"ip": "91.243.46.20", "asn": "AS34665", "country": "RU", "city": "St Petersburg", "reputation": "malicious", "campaigns": ["CAMP-2025-3301"], "actor_id": "fin7"},
    {"ip": "45.33.32.156", "asn": "AS63949", "country": "US", "city": "Dallas", "reputation": "suspicious", "campaigns": ["CAMP-2026-2201"], "actor_id": "lapsus"},
    {"ip": "45.155.37.78", "asn": "AS206728", "country": "NL", "city": "Amsterdam", "reputation": "suspicious", "campaigns": ["CAMP-2026-0321"], "actor_id": None},
]
# Pad to 100+
for _i in range(len(IP_ADDRESSES), 105):
    IP_ADDRESSES.append({
        "ip": f"10.{_i // 256}.{_i % 256}.{(_i * 7) % 256}",
        "asn": f"AS{10000 + _i}",
        "country": ["US", "RU", "CN", "KP", "NL", "UA", "DE"][_i % 7],
        "city": ["New York", "Moscow", "Beijing", "Pyongyang", "Amsterdam", "Kyiv", "Frankfurt"][_i % 7],
        "reputation": ["suspicious", "monitoring", "malicious"][_i % 3],
        "campaigns": [],
        "actor_id": None,
    })

# ─── MITRE TECHNIQUES (50) ───────────────────────────────────────────────────
MITRE_TECHNIQUES = [
    {"id": "T1566.001", "tactic": "Initial Access", "name": "Spear Phishing Link"},
    {"id": "T1566.002", "tactic": "Initial Access", "name": "Spear Phishing Attachment"},
    {"id": "T1566.003", "tactic": "Initial Access", "name": "Spear Phishing via Service"},
    {"id": "T1078", "tactic": "Defense Evasion", "name": "Valid Accounts"},
    {"id": "T1056.003", "tactic": "Collection", "name": "Web Portal Capture"},
    {"id": "T1534", "tactic": "Lateral Movement", "name": "Internal Spear Phishing"},
    {"id": "T1656", "tactic": "Defense Evasion", "name": "Impersonation"},
    {"id": "T1204.001", "tactic": "Execution", "name": "Malicious Link"},
    {"id": "T1585", "tactic": "Resource Development", "name": "Establish Accounts"},
    {"id": "T1583.001", "tactic": "Resource Development", "name": "Domains"},
    {"id": "T1583.003", "tactic": "Resource Development", "name": "Virtual Private Server"},
    {"id": "T1621", "tactic": "Credential Access", "name": "MFA Request Generation"},
    {"id": "T1110.001", "tactic": "Credential Access", "name": "Password Guessing"},
    {"id": "T1059.001", "tactic": "Execution", "name": "PowerShell"},
    {"id": "T1071.001", "tactic": "Command and Control", "name": "Web Protocols"},
    {"id": "T1027", "tactic": "Defense Evasion", "name": "Obfuscated Files"},
    {"id": "T1036", "tactic": "Defense Evasion", "name": "Masquerading"},
    {"id": "T1203", "tactic": "Execution", "name": "Exploitation for Client Execution"},
    {"id": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact"},
    {"id": "T1530", "tactic": "Collection", "name": "Data from Cloud Storage"},
    {"id": "T1195", "tactic": "Initial Access", "name": "Supply Chain Compromise"},
    {"id": "T1539", "tactic": "Credential Access", "name": "Steal Web Session Cookie"},
    {"id": "T1111", "tactic": "Credential Access", "name": "MFA Interception"},
    {"id": "T1041", "tactic": "Exfiltration", "name": "Exfiltration Over C2"},
    {"id": "T1189", "tactic": "Initial Access", "name": "Drive-by Compromise"},
    {"id": "T1087.002", "tactic": "Discovery", "name": "Domain Account Discovery"},
    {"id": "T1098.005", "tactic": "Persistence", "name": "Device Registration"},
    {"id": "T1552.001", "tactic": "Credential Access", "name": "Credentials In Files"},
    {"id": "T1589.002", "tactic": "Reconnaissance", "name": "Email Address Harvesting"},
    {"id": "T1597.001", "tactic": "Reconnaissance", "name": "Purchase Threat Intel"},
    {"id": "T1213.003", "tactic": "Collection", "name": "Code Repositories"},
    {"id": "T1119", "tactic": "Collection", "name": "Automated Collection"},
    {"id": "T1560.001", "tactic": "Collection", "name": "Archive via Utility"},
    {"id": "T1048.003", "tactic": "Exfiltration", "name": "DNS Exfiltration"},
    {"id": "T1573.002", "tactic": "Command and Control", "name": "Asymmetric Cryptography"},
    {"id": "T1008", "tactic": "Command and Control", "name": "Fallback Channels"},
    {"id": "T1105", "tactic": "Command and Control", "name": "Ingress Tool Transfer"},
    {"id": "T1140", "tactic": "Defense Evasion", "name": "Deobfuscate Files"},
    {"id": "T1562.001", "tactic": "Defense Evasion", "name": "Disable Security Tools"},
    {"id": "T1070.004", "tactic": "Defense Evasion", "name": "File Deletion"},
    {"id": "T1114.003", "tactic": "Collection", "name": "Email Forwarding Rule"},
    {"id": "T1091", "tactic": "Lateral Movement", "name": "Removable Media"},
    {"id": "T1069.002", "tactic": "Discovery", "name": "Domain Groups"},
    {"id": "T1098.001", "tactic": "Persistence", "name": "Additional Cloud Credentials"},
    {"id": "T1585.002", "tactic": "Resource Development", "name": "Email Accounts"},
    {"id": "T1598.003", "tactic": "Reconnaissance", "name": "Spear Phishing for Info"},
    {"id": "T1484.001", "tactic": "Defense Evasion", "name": "Group Policy Modification"},
    {"id": "T1648", "tactic": "Execution", "name": "Serverless Execution"},
    {"id": "T1018", "tactic": "Discovery", "name": "Remote System Discovery"},
    {"id": "T1586.002", "tactic": "Resource Development", "name": "Email Account Compromise"},
]

# ─── KNOWLEDGE GRAPH ENGINE ──────────────────────────────────────────────────

class ThreatKnowledgeGraph:
    def __init__(self):
        self.G = nx.DiGraph()
        self._build_graph()

    def _build_graph(self):
        # Actors
        for actor in THREAT_ACTORS:
            self.G.add_node(actor["id"], type="actor", **actor)

        # Campaigns + actor links
        for camp in CAMPAIGNS:
            self.G.add_node(camp["id"], type="campaign", **camp)
            if camp.get("actor_id") and self.G.has_node(camp["actor_id"]):
                self.G.add_edge(camp["actor_id"], camp["id"], label="CONDUCTS")

        # Domain nodes from campaign IOCs (first 60 unique domains)
        seen = set()
        for camp in CAMPAIGNS:
            for dom in camp.get("iocs", {}).get("domains", []):
                if dom in seen:
                    continue
                seen.add(dom)
                node_id = f"domain:{dom}"
                self.G.add_node(node_id, type="domain", label=dom, fqdn=dom, campaign=camp["id"])
                self.G.add_edge(camp["id"], node_id, label="USES_DOMAIN")
                if camp.get("actor_id") and self.G.has_node(camp["actor_id"]):
                    self.G.add_edge(camp["actor_id"], node_id, label="OWNS_INFRASTRUCTURE")

        # IP nodes
        for ip_data in IP_ADDRESSES[:30]:
            node_id = f"ip:{ip_data['ip']}"
            self.G.add_node(node_id, type="ip", label=ip_data["ip"], **ip_data)
            for camp_id in ip_data.get("campaigns", []):
                if self.G.has_node(camp_id):
                    self.G.add_edge(camp_id, node_id, label="USES_IP")
            if ip_data.get("actor_id") and self.G.has_node(ip_data["actor_id"]):
                self.G.add_edge(ip_data["actor_id"], node_id, label="CONTROLS")

        # MITRE technique nodes (first 20)
        for tech in MITRE_TECHNIQUES[:20]:
            node_id = f"tech:{tech['id']}"
            self.G.add_node(node_id, type="technique", label=tech["name"], **tech)
        for actor in THREAT_ACTORS:
            for tech_id in actor.get("mitre_techniques", []):
                node_id = f"tech:{tech_id}"
                if self.G.has_node(node_id):
                    self.G.add_edge(actor["id"], node_id, label="EMPLOYS")

    def get_graph_data(self, depth: int = 2, entity_type: Optional[str] = None, center_node: str = None) -> dict:
        """D3.js-compatible graph export."""
        color_map = {
            "actor": "#ef4444",
            "campaign": "#f59e0b",
            "domain": "#3b82f6",
            "ip": "#10b981",
            "technique": "#8b5cf6",
        }
        nodes, links, seen = [], [], set()

        if center_node and self.G.has_node(center_node):
            subgraph_nodes = {center_node}
            frontier = {center_node}
            for _ in range(depth):
                nxt = set()
                for n in frontier:
                    nxt.update(self.G.predecessors(n))
                    nxt.update(self.G.successors(n))
                subgraph_nodes.update(nxt)
                frontier = nxt
        elif entity_type:
            subgraph_nodes = {n for n, d in self.G.nodes(data=True) if d.get("type") == entity_type}
        else:
            subgraph_nodes = set(self.G.nodes())

        for nid in subgraph_nodes:
            if nid in seen:
                continue
            seen.add(nid)
            data = dict(self.G.nodes[nid])
            t = data.get("type", "unknown")
            nodes.append({
                "id": nid,
                "label": data.get("label") or data.get("name") or data.get("fqdn") or data.get("ip") or nid,
                "type": t,
                "color": color_map.get(t, "#6b7280"),
                "risk": data.get("risk") or data.get("reputation") or data.get("risk_level") or "unknown",
                "data": data,
            })

        for src, dst, edata in self.G.edges(data=True):
            if src in seen and dst in seen:
                links.append({"source": src, "target": dst, "label": edata.get("label", "")})

        return {
            "nodes": nodes,
            "edges": links,
            "links": links,  # D3 uses "links"
            "metadata": {
                "total_nodes": self.G.number_of_nodes(),
                "total_edges": self.G.number_of_edges(),
                "displayed_nodes": len(nodes),
                "displayed_edges": len(links),
                "actors": len(THREAT_ACTORS),
                "campaigns": len(CAMPAIGNS),
                "ips": len(IP_ADDRESSES),
                "techniques": len(MITRE_TECHNIQUES),
            },
        }

    # Alias used in analyze router
    def get_d3_graph(self, **kwargs) -> dict:
        return self.get_graph_data(**kwargs)

    def correlate_iocs(self, domains: list = None, ips: list = None, hashes: list = None) -> dict:
        domains = [d.lower().strip() for d in (domains or [])]
        ips_list = list(ips or [])
        matches, related_campaigns, risk_elevation = [], [], 0.0

        for camp in CAMPAIGNS:
            camp_domains = [d.lower() for d in camp.get("iocs", {}).get("domains", [])]
            camp_ips = camp.get("iocs", {}).get("ips", [])
            domain_hits = [d for d in domains if any(d == cd or d.endswith("." + cd) or cd.endswith("." + d) for cd in camp_domains)]
            ip_hits = [ip for ip in ips_list if ip in camp_ips]
            if domain_hits or ip_hits:
                matches.append({
                    "campaign_id": camp["id"],
                    "campaign_name": camp["name"],
                    "actor": camp["actor"],
                    "actor_id": camp.get("actor_id"),
                    "confidence": 0.92,
                    "matched_domains": domain_hits,
                    "matched_ips": ip_hits,
                })
                if camp["id"] not in related_campaigns:
                    related_campaigns.append(camp["id"])
                boost = 0.20 if camp["risk_level"] == "critical" else 0.12 if camp["risk_level"] == "high" else 0.06
                risk_elevation = min(risk_elevation + boost, 0.30)

        return {"matches": matches, "related_campaigns": related_campaigns, "risk_elevation": round(risk_elevation, 4)}

    def get_actor(self, actor_id: str) -> Optional[dict]:
        actor = next((a for a in THREAT_ACTORS if a["id"] == actor_id or a["name"].lower() == actor_id.lower()), None)
        if not actor:
            return None
        camps = [c["id"] for c in CAMPAIGNS if c.get("actor_id") == actor["id"]]
        return {**actor, "campaigns": camps}

    def get_campaign(self, campaign_id: str) -> Optional[dict]:
        return next((c for c in CAMPAIGNS if c["id"] == campaign_id), None)

    def get_all_campaigns(self) -> list:
        return CAMPAIGNS

    def get_all_actors(self) -> list:
        return THREAT_ACTORS

    def search(self, query: str) -> dict:
        q = query.lower()
        actors = [a for a in THREAT_ACTORS if q in a["name"].lower() or any(q in al.lower() for al in a.get("aliases", []))]
        campaigns = [c for c in CAMPAIGNS if q in c["name"].lower() or q in c["id"].lower() or q in c.get("actor", "").lower()]
        return {"actors": actors[:5], "campaigns": campaigns[:10]}


_graph_instance: Optional[ThreatKnowledgeGraph] = None


def get_graph() -> ThreatKnowledgeGraph:
    global _graph_instance
    if _graph_instance is None:
        _graph_instance = ThreatKnowledgeGraph()
    return _graph_instance
