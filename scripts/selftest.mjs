// Regression checks for the rule engine. Usage: npm test
import { analyzeWithRules } from '../public/lib/analyzer.js';

const cases = [
  // OTP / account-takeover requests must always come out as scams.
  ['scam', 'whatsapp', 'Hi, send me your number, I will send you an OTP'],
  ['scam', 'sms', 'Please share your mobile number for OTP verification'],
  ['scam', 'whatsapp', 'Send ur num for OTD'],
  ['scam', 'whatsapp', 'Hey can you give me your number? I need to send you an OTD'],
  ['scam', 'sms', 'Share the OTP you received on your number'],
  ['scam', 'whatsapp', 'I sent an OTP to your number by mistake, please send it back'],
  ['scam', 'whatsapp', 'Hi, sorry to bother you! I sent my OTP to your number by mistake. Can you please forward the 6-digit code you just got? It’s urgent.'],
  ['scam', 'sms', 'Your OTP aaya hoga, jaldi bata do'],
  ['scam', 'whatsapp', 'what is the code you just got?'],
  ['scam', 'sms', 'Please share OTP, do not share with anyone else'],
  // Other common scams.
  ['scam', 'sms', 'Dear Customer, your SBI YONO account will be blocked today. Update your PAN KYC immediately: http://sbi-kyc-update.xyz/verify'],
  ['scam', 'linkedin', 'Hello! We are hiring for a remote part-time role. Earn ₹5,000 per day by rating hotels on Google. No interview needed. Pay a refundable registration fee of ₹1,999 to start. Message me on Telegram @hr_priya_jobs'],
  ['scam', 'whatsapp', 'This is Inspector Sharma from the CBI cyber cell. Drugs were found in a parcel booked on your Aadhaar. You are under digital arrest. Do not tell your family. Transfer ₹49,000 for verification.'],
  ['scam', 'instagram', 'Instagram Support: your account will be disabled for copyright violation within 24 hours. Verify your account to appeal: bit.ly/ig-appeal-form'],
  ['scam', 'x', 'GIVEAWAY! Send 0.05 BTC and receive 0.1 BTC back instantly! Guaranteed returns, only for the next 30 minutes!!!'],
  ['scam', 'sms', 'Congratulations! You have won Rs 25,00,000 in KBC lucky draw. To receive, scan the QR code and enter UPI PIN.'],
  ['scam', 'sms', 'Dear consumer, your electricity power will be disconnected tonight at 9.30 pm. Please immediately call our officer 9876543210.'],
  ['scam', 'whatsapp', 'Your e-challan is pending. Download the mParivahan.apk to pay now.'],
  // Genuine / harmless messages should stay low.
  ['safe', 'sms', '483920 is your OTP to log in to your account. It is valid for 10 minutes. Do not share this OTP with anyone. - XYZ Bank'],
  ['safe', 'sms', 'Use OTP 552901 to verify your email. Never share your OTP with anyone, including bank staff.'],
  ['safe', 'whatsapp', 'Hey! Are we still on for dinner tomorrow at 8?'],
  ['safe', 'sms', 'Your order #4521 has been shipped and will arrive by Friday. Track it in the app.'],
  ['safe', 'linkedin', 'Hi, I enjoyed your talk on metal forming simulations. Would you be open to a quick chat next week?'],
];

let failed = 0;
for (const [expected, source, text] of cases) {
  const r = analyzeWithRules(text, source);
  const ok = expected === 'scam' ? r.verdict === 'scam' : r.verdict === 'safe';
  if (!ok) failed++;
  const levels = Object.entries(r.impacts).filter(([, v]) => v.level !== 'none').map(([k, v]) => `${k}:${v.level}`).join(' ');
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${String(r.score).padStart(2)}  ${r.verdict.padEnd(10)} [${source}] ${text.slice(0, 60)}`);
  if (!ok || process.env.VERBOSE) console.log(`      flags: ${r.redFlags.map((f) => f.id).join(', ') || '-'} | ${levels || 'no impact'} | support: ${r.support.join(',') || '-'}`);
}
console.log(`\n${cases.length - failed}/${cases.length} passed`);
process.exit(failed ? 1 : 0);
