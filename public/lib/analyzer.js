/*
 * Phish-Catch local rule-based engine.
 *
 * Shared by the browser (offline fallback) and the /api functions, so it must
 * stay dependency-free and runtime-agnostic. Every function here is pure: a
 * message goes in, an estimate comes out, nothing is stored.
 */

export const RULES_VERSION = 'rules-1.0';
export const MAX_MESSAGE_LENGTH = 5000;

export const SOURCES = {
  sms: 'SMS',
  whatsapp: 'WhatsApp',
  linkedin: 'LinkedIn',
  instagram: 'Instagram',
  x: 'X / Twitter',
  other: 'Other',
};

export const IMPACTS = {
  device: { label: 'Device', hint: 'Malware, spyware or remote-control apps.' },
  financial: { label: 'Finances', hint: 'Money lost through UPI, cards or transfers.' },
  social: { label: 'Social accounts', hint: 'Takeover of WhatsApp, Instagram, email and similar.' },
  physical: { label: 'Physical safety', hint: 'Meetings, stalking, threats or extortion.' },
};

export const LEVELS = ['none', 'low', 'medium', 'high'];
const LEVEL_VALUE = { none: 0, low: 20, medium: 50, high: 80 };

const SOCIAL_SOURCES = new Set(['whatsapp', 'instagram', 'linkedin', 'x']);

export function verdictFor(score) {
  if (score >= 60) return 'scam';
  if (score >= 30) return 'suspicious';
  return 'safe';
}

export function levelFor(value) {
  if (value >= 65) return 'high';
  if (value >= 35) return 'medium';
  if (value >= 10) return 'low';
  return 'none';
}

const atLeast = (level, min) => LEVELS.indexOf(level || 'none') >= LEVELS.indexOf(min);

/* ------------------------------------------------------------------ */
/* Pattern vocabulary                                                  */
/* ------------------------------------------------------------------ */

const re = (src) => new RegExp(src, 'i');
const S = String.raw;

// "OTP" and friends, including spaced/zero/typo variants such as "O T P", "0TP" and "OTD".
const OTP = S`(?:[o0][\s.\-]?t[\s.\-]?[pd]s?|one[\s-]?time[\s-]?(?:pass(?:word|code)?|pin|code)|verification\s+code|security\s+code|auth(?:entication)?\s+code|login\s+code|sms\s+code|whatsapp\s+code|confirmation\s+code|\d[\s-]?digit\s+(?:code|number|pin|otp))`;
const OTP_RE = re(S`\b${OTP}\b`);

const NUM_FILLER = S`(?:(?:phone|mobile|mob|contact|whatsapp|wa|cell|cellphone|personal|private|correct|registered|alternate|other|new|10[\s-]?digit)\s+){0,2}`;
const NUM_NOUN = S`(?:number|no\.?|num|nmbr|numbr|contact)`;
const HINDI_GIVE = S`(?:bhejo|bhej\s+do|bhejna|batao|bata\s+do|batana|dedo|de\s+do|dijiye|send\s+kar\w*|share\s+kar\w*)`;

// Warnings such as "do not share this OTP" are blanked out before request
// patterns run, so a genuine bank SMS isn't mistaken for a scammer's ask.
const NEGATED = new RegExp(
  S`\b(?:do\s*not|don't|dont|never|not\s+to|no\s+one\s+(?:should|will)|nobody\s+will|will\s+never|won't|mat)\b[^.!?,;\n]{0,25}?\b(?:share|disclose|give|tell|send|forward|reveal|enter|type|approve|scan|ask|asks|call|click|open|download|install|update)\b[^.!?\n]*`,
  'gi',
);

const ZERO_WIDTH = /[​-‍⁠﻿]/g;

const URL_RE = new RegExp(
  S`(?<![@\w.\-])(?:https?:\/\/[^\s<>"'()]+|www\.[^\s<>"'()]+|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|in|net|org|xyz|top|info|co|me|link|live|site|online|click|io|app|ly|gl|ru|cn|tk|ml|ga|cf|gq|icu|shop|store|work|rest|buzz|fun|club|vip|win|bid|loan|cc|biz|today|support|help|page|website|space|tech|pro|ws|to|gd|id|sbs|cfd|lol|quest|cyou|mom|monster|bank|sbi)(?:\/[^\s<>"'()]*)?)(?![a-z0-9\-])`,
  'gi',
);

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.ly', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at', 'tiny.cc', 'goo.gl',
  'ow.ly', 'buff.ly', 'rebrand.ly', 's.id', 'v.gd', 'shorte.st', 'adf.ly', 'bl.ink', 't2m.io',
  'tiny.one', 'shrtco.de', 'urlz.fr', 'qrco.de', 'surl.li', 'u.to', 'clck.ru',
]);

const RISKY_TLDS = new Set([
  'xyz', 'top', 'click', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'buzz', 'rest', 'work', 'fun', 'vip',
  'win', 'bid', 'loan', 'cfd', 'sbs', 'lol', 'quest', 'mom', 'cyou', 'monster', 'live', 'site',
  'online', 'info', 'shop', 'support', 'help',
]);

// Brand name → domains the brand actually uses. A brand name on any other
// domain is flagged as a possible look-alike.
const BRANDS = [
  ['sbi', ['sbi.co.in', 'onlinesbi.com', 'sbicard.com', 'sbimf.com', 'sbilife.co.in', 'sbigeneral.in']],
  ['hdfc', ['hdfcbank.com', 'hdfc.com', 'hdfclife.com', 'hdfcergo.com', 'hdfcfund.com', 'hdfcsec.com']],
  ['icici', ['icicibank.com', 'icicidirect.com', 'iciciprulife.com', 'icicilombard.com']],
  ['axis', ['axisbank.com', 'axismf.com']],
  ['kotak', ['kotak.com', 'kotaksecurities.com']],
  ['paytm', ['paytm.com', 'paytm.in', 'paytmbank.com']],
  ['phonepe', ['phonepe.com']],
  ['amazon', ['amazon.in', 'amazon.com', 'amzn.in', 'amzn.to', 'amazonpay.in']],
  ['flipkart', ['flipkart.com', 'fkrt.it']],
  ['netflix', ['netflix.com']],
  ['indiapost', []],
  ['fedex', ['fedex.com']],
  ['dhl', ['dhl.com', 'dhl.co.in']],
  ['bluedart', ['bluedart.com']],
  ['delhivery', ['delhivery.com']],
  ['whatsapp', ['whatsapp.com', 'whatsapp.net', 'wa.me']],
  ['instagram', ['instagram.com']],
  ['facebook', ['facebook.com', 'fb.com', 'fb.me']],
  ['linkedin', ['linkedin.com', 'lnkd.in']],
  ['irctc', ['irctc.co.in']],
  ['epfo', []],
  ['incometax', []],
  ['uidai', []],
  ['aadhaar', []],
  ['echallan', []],
  ['parivahan', []],
  ['npci', ['npci.org.in']],
  ['bhim', ['bhimupi.org.in']],
  ['rbi', ['rbi.org.in']],
  ['jio', ['jio.com']],
  ['airtel', ['airtel.in', 'airtel.com']],
];
// Government and regulated-bank namespaces; anything under these is treated as official.
const OFFICIAL_SUFFIXES = ['.gov.in', '.nic.in', '.bank.in', '.sbi'];

/* ------------------------------------------------------------------ */
/* Signals                                                             */
/* ------------------------------------------------------------------ */
// impacts: { category: [0-100 contribution, reason shown to the user] }
// on: 'stripped' runs against text with "do not share…" warnings removed.

const SIGNALS = [
  {
    id: 'otp_share',
    critical: true,
    weight: 55,
    on: 'stripped',
    title: 'Asks you to share a one-time code',
    detail: 'Banks, apps and couriers never ask you to forward or read out an OTP. Whoever gets the code can sign in as you or approve a payment.',
    summary: 'asks you to share a one-time code (OTP), which lets someone take over your account or approve a payment',
    advice: 'Don’t share the code. If you already did, change that account’s password, turn on two-step verification, and call your bank if it was a payment OTP.',
    impacts: {
      financial: [65, 'A shared OTP can approve UPI, card or net-banking transactions.'],
      social: [65, 'A shared login code lets someone take over your WhatsApp, Instagram or email.'],
    },
    otpBoost: true,
    except: /\b(?:delivery\s+(?:agent|partner|executive|associate|boy|person)|at\s+(?:the\s+)?time\s+of\s+delivery|driver|captain|rider|to\s+(?:start|begin|end)\s+(?:your|the)\s+(?:ride|trip))\b/i,
    patterns: [
      re(S`\b(?:share|forward|give|tell|provide|reply\s+with|read\s+out|pass\s+on|text|whatsapp|dm|message)\s+(?:(?:me|us|him|her|them)\s+)?(?:(?:the|that|this|your|ur|my|ye|wo|those|received|new|same)\s+){0,3}${OTP}\b`),
      re(S`\b(?:share|forward)\b[^.!?\n]{0,40}?\b${OTP}\b`),
      re(S`\bsend\s+(?:me|us|it|that|this|back|over)\b[^.!?\n]{0,50}?\b${OTP}\b`),
      re(S`(?<!\b(?:will|shall|we|would|may|might|they|i)\s+|'ll\s+)\bsend\s+(?:(?:the|that|this|ur|your|ye|wo|those)\s+)?${OTP}\b`),
      re(S`\b${OTP}\b[^.!?\n]{0,50}?\b(?:share|forward|send\s+(?:it|back|me|us|to\s+me|here)|tell\s+me|give\s+me|bhej\w*|bata\w*|de\s*do|dedo|dijiye|chahiye|send\s+kar\w*|share\s+kar\w*)\b`),
      re(S`\b(?:what(?:'s|s|\s+is|\s+was)|tell|share|send|forward|read)\b[^.!?\n]{0,25}?\b(?:code|otp|pin)\b[^.!?\n]{0,25}?\b(?:you|u)\s+(?:just\s+)?(?:received|recieved|got|get)\b`),
      re(S`\b${OTP}\b[^.!?\n]{0,60}?\b(?:except|other\s+than|only\s+(?:with|to))\s+(?:me|us|our|this|the)\b`),
    ],
  },
  {
    id: 'mistaken_code',
    weight: 25,
    title: 'Claims a code was sent to you “by mistake”',
    detail: 'The “I sent my code to your number by mistake” story is how WhatsApp and Telegram accounts are hijacked: the code is actually for your account.',
    summary: 'claims a code reached you by mistake, a classic account-hijack story',
    advice: 'Don’t forward any code you receive. A code sent to your number belongs to your account.',
    impacts: { social: [40, 'The “wrong number” code is usually a login code for your own account.'], financial: [20, 'A hijacked account is then used to ask your contacts for money.'] },
    requires: (ctx) => ctx.mentionsOtp || /\bcode\b/i.test(ctx.norm),
    patterns: [
      re(S`\b(?:sent|send|came|went|forwarded|shared|typed|gave|given|entered)\b[^.!?\n]{0,60}?\b(?:by\s+mistake|accidentally|mistakenly|wrongly|in\s+error|galti\s+se|wrong\s+number)\b`),
      re(S`\b(?:by\s+mistake|accidentally|mistakenly|galti\s+se)\b[^.!?\n]{0,60}?\b(?:sent|send|came|went|forwarded|shared|typed|gave|entered)\b`),
    ],
  },
  {
    id: 'number_request',
    weight: 20,
    on: 'stripped',
    title: 'Asks for your phone number',
    detail: 'Your number is the key to most account logins and UPI apps. A stranger asking for it is often the first step before asking for a code.',
    summary: 'asks for your phone number',
    advice: 'Don’t send your number to someone you can’t verify.',
    impacts: { social: [15, 'Your number can be used to request login codes for your accounts.'], financial: [10, 'Numbers are linked to UPI and bank alerts.'], physical: [5, 'Your number can be used to find or contact you.'] },
    patterns: [
      re(S`\b(?:share|send|give|tell|provide|drop|dm|text|whatsapp|pm|message|need|want|require|forward)\s+(?:me\s+|us\s+)?(?:your|ur|yr|ya)\s+${NUM_FILLER}${NUM_NOUN}(?!\w)`),
      re(S`\bwhat(?:'s|s|\s+is)\s+(?:your|ur)\s+${NUM_FILLER}(?:number|no\.?|num)(?!\w)`),
      re(S`\b(?:your|ur)\s+${NUM_FILLER}(?:number|num|no\.?)\s+(?:please|pls|plz|do|${HINDI_GIVE})(?!\w)`),
      re(S`\b(?:number|num)\s+${HINDI_GIVE}(?!\w)`),
      re(S`\b(?:can|could|may)\s+i\s+(?:get|have)\s+(?:your|ur)\s+${NUM_FILLER}${NUM_NOUN}(?!\w)`),
    ],
  },
  {
    id: 'upi_pin',
    critical: true,
    weight: 40,
    on: 'stripped',
    title: 'Asks for a UPI PIN or to approve a payment request',
    detail: 'You never need a PIN, QR scan or “collect request” approval to receive money. Entering your PIN always sends money out.',
    summary: 'asks you to enter a PIN, scan a QR code or approve a request, which sends money out of your account',
    advice: 'Never enter your UPI PIN or scan a QR code to “receive” money. Decline any collect request you don’t recognise.',
    impacts: { financial: [75, 'Approving the request or entering the PIN moves money from your account.'] },
    patterns: [
      re(S`\b(?:enter|type|put|use|share|tell|give|send|provide)\b[^.!?\n]{0,30}?\b(?:upi\s*pin|m-?pin|atm\s*pin|card\s*pin|debit\s+card\s+pin|pin\s+(?:number|code)|secret\s+pin|transaction\s+pin)\b`),
      re(S`\b(?:receive|get|claim|credit|accept)\b[^.!?\n]{0,50}?\b(?:enter|type|approve|accept)\b[^.!?\n]{0,30}?\b(?:pin|collect|request)\b`),
      re(S`\b(?:approve|accept|pay)\b[^.!?\n]{0,30}?\b(?:collect\s+request|payment\s+request|upi\s+request|request\s+(?:on|in|from)\s+(?:gpay|google\s*pay|phone\s*pe|paytm|bhim|upi))\b`),
      re(S`\bscan\b[^.!?\n]{0,30}?\b(?:qr|code)\b[^.!?\n]{0,50}?\b(?:receive|get|claim|refund|credit|cashback|prize)\b`),
    ],
  },
  {
    id: 'credentials',
    critical: true,
    weight: 40,
    on: 'stripped',
    title: 'Asks for passwords or card details',
    detail: 'No genuine bank, employer or platform asks for your password, CVV or full card number by message.',
    summary: 'asks for passwords or card details',
    advice: 'Don’t reply with passwords, card numbers or CVV. If you already did, block the card and change the password now.',
    impacts: { financial: [60, 'Card or banking details can be used for purchases and transfers.'], social: [45, 'A password lets someone lock you out of your account.'] },
    patterns: [
      re(S`\b(?:share|send|give|tell|provide|confirm|verify|update|enter|reply\s+with|type|submit|fill)\b[^.!?\n]{0,50}?\b(?:password|passcode|pass\s*word|cvv|cvc|card\s+(?:number|details|no)|(?:debit|credit|atm)\s+card\s+(?:number|details|no)|net\s*banking\s+(?:id|password|details|credentials)|login\s+(?:details|id|credentials|password)|credentials|user\s*(?:id|name)\s+and\s+password|expiry\s+date)\b`),
    ],
  },
  {
    id: 'personal_ids',
    weight: 25,
    on: 'stripped',
    title: 'Asks for Aadhaar, PAN or bank account details',
    detail: 'ID and account numbers are used to open loans, SIMs or accounts in your name, and to make other scams more convincing.',
    summary: 'asks for ID or bank account details',
    advice: 'Share Aadhaar, PAN or account numbers only on official portals you opened yourself.',
    impacts: { financial: [40, 'ID and account details enable identity fraud and loans in your name.'] },
    patterns: [
      re(S`\b(?:share|send|give|tell|provide|confirm|verify|update|submit|fill)\b[^.!?\n]{0,40}?\b(?:aadhaa?r\s+(?:number|no|details|card)|pan\s+(?:number|no|details)|bank\s+(?:details|account\s+(?:number|details))|account\s+(?:number|details)|ifsc)\b`),
    ],
  },
  {
    id: 'remote_access',
    critical: true,
    weight: 40,
    on: 'stripped',
    title: 'Asks you to install remote-access or screen-sharing software',
    detail: 'Apps like AnyDesk or TeamViewer let a stranger see and control your phone, including your banking apps and OTPs.',
    summary: 'asks you to install remote-access or screen-sharing software',
    advice: 'Don’t install the app. If you already did, uninstall it, disconnect from the internet and call your bank.',
    impacts: { device: [80, 'Remote-access apps give full control of your screen.'], financial: [50, 'With screen control they can read OTPs and move money.'] },
    patterns: [
      re(S`\b(?:any\s*desk|team\s*viewer|quick\s*support|rust\s*desk|air\s*droid|ultra\s*viewer|alpemix|remote\s+(?:access|control|desktop)|screen\s*shar(?:e|ing)|share\s+(?:your\s+)?(?:phone\s+)?screen)\b`),
    ],
  },
  {
    id: 'apk_install',
    critical: true,
    weight: 40,
    on: 'stripped',
    title: 'Pushes an app file (APK) from outside the app store',
    detail: 'Fake “bank”, “e-challan” or “reward” APKs are a common way to plant malware that reads your SMS and OTPs.',
    summary: 'pushes an app file (APK) from outside the app store',
    advice: 'Don’t open the file. Install apps only from Google Play or the App Store.',
    impacts: { device: [80, 'APK files from messages often contain SMS-stealing malware.'], financial: [45, 'Malware can forward your OTPs to scammers.'] },
    patterns: [re(S`\.apk\b|\bapk\b`)],
  },
  {
    id: 'app_install',
    weight: 15,
    on: 'stripped',
    title: 'Asks you to download or install something',
    detail: 'Unexpected download requests can lead to fake apps. Get apps only from the official store.',
    summary: 'asks you to download or install something',
    advice: 'Install apps only from Google Play or the App Store, not from links in messages.',
    impacts: { device: [30, 'Downloads from messages can contain malware.'] },
    patterns: [re(S`\b(?:download|install)\s+(?:(?:this|the|our|attached|given|below|following|new)\s+)?(?:app|application|file|software|update)\b`)],
  },
  {
    id: 'digital_arrest',
    critical: true,
    weight: 45,
    title: 'Uses fake police, legal or “digital arrest” threats',
    detail: 'Indian police, CBI, customs or courts never arrest anyone over a video call or ask for money to “verify” you. This is a common extortion script.',
    summary: 'uses fake police or legal threats to pressure you',
    advice: 'Hang up and don’t pay. There is no such thing as a “digital arrest”. Report it on 1930 or cybercrime.gov.in.',
    impacts: { financial: [65, '“Verification” payments in these scams are never returned.'], physical: [35, 'Victims are kept on long, frightening calls and told to isolate.'] },
    patterns: [
      re(S`\b(?:digital(?:ly)?\s+arrest\w*|arrest\s+warrant|warrant\s+(?:against|in\s+your\s+name)|money\s+laundering|drugs?\s+(?:were\s+|was\s+)?(?:found|in\s+(?:your|the|a)\s+(?:parcel|package|courier))|case\s+(?:has\s+been\s+)?(?:registered|filed)\s+against\s+you|fir\s+(?:against|registered|lodged)|you\s+(?:will\s+be|are\s+being)\s+arrested|under\s+(?:investigation|arrest|surveillance))\b`),
      re(S`\b(?:parcel|package|courier)\b[^.!?\n]{0,40}?\b(?:drugs|narcotics|mdma|illegal\s+items|seized|fake\s+passports?)\b`),
    ],
  },
  {
    id: 'authority',
    weight: 25,
    title: 'Claims to be from police, a regulator or a government body',
    detail: 'Scammers impersonate police, CBI, TRAI, customs or tax officials because people are afraid to question them.',
    summary: 'claims to come from police or a government body',
    advice: 'Look up the agency’s official number yourself and call it to check.',
    impacts: { financial: [30, 'Official-sounding threats are used to demand “fines” or “fees”.'], physical: [15, 'These calls often involve intimidation.'] },
    patterns: [
      re(S`\b(?:police|cbi|enforcement\s+directorate|ed\s+officer|customs\s+(?:officer|department|duty)|narcotics|ncb|trai|cyber\s*(?:cell|crime\s+(?:branch|department|cell))|crime\s+branch|income\s+tax\s+(?:department|officer)|rbi\s+(?:officer|department)|court\s+(?:notice|summons|order)|legal\s+(?:notice|action)|inspector)\b`),
    ],
  },
  {
    id: 'kyc',
    weight: 25,
    on: 'stripped',
    title: 'Pushes an urgent KYC, PAN or Aadhaar update',
    detail: 'Fake “KYC expired” messages lead to look-alike bank pages that steal your login and OTP.',
    summary: 'pushes an urgent KYC / PAN / Aadhaar update',
    advice: 'Update KYC only inside your bank’s official app or at a branch, never through a message link or number.',
    impacts: { financial: [40, 'Fake KYC pages capture banking logins and OTPs.'] },
    patterns: [
      re(S`\b(?:kyc|re-?kyc|e-?kyc|pan(?:\s*card)?|aadhaa?r|aadhar)\b[^.!?\n]{0,50}?\b(?:updat\w*|verif\w*|link(?:ed|ing)?|expir\w*|pending|incomplete|not\s+(?:updated|verified|linked)|suspend\w*|block\w*|deactivat\w*)`),
      re(S`\b(?:updat\w*|complete|verify|link)\b[^.!?\n]{0,25}?\b(?:kyc|pan(?:\s*card)?|aadhaa?r)\b`),
    ],
  },
  {
    id: 'challan',
    weight: 20,
    title: 'Claims you have an unpaid fine or e-challan',
    detail: 'Fake traffic-fine messages push you to pay through a link or install a “payment” app. Real challans can be checked on the official Parivahan site.',
    summary: 'claims you have an unpaid fine',
    advice: 'Check fines only on the official Parivahan e-challan site you open yourself.',
    impacts: { financial: [25, 'Fake fine pages capture card or UPI details.'], device: [15, 'Fake “challan” apps are a common malware lure.'] },
    patterns: [re(S`\b(?:e-?challan|traffic\s+(?:fine|challan)|challan)\b[^.!?\n]{0,40}?\b(?:pending|unpaid|due|overdue|pay)\b`)],
  },
  {
    id: 'account_threat',
    weight: 20,
    title: 'Threatens to block, suspend or disconnect something',
    detail: 'Threats like “your account will be blocked today” or “power will be cut tonight” are designed to make you act before you check.',
    summary: 'threatens that an account or service will be blocked',
    advice: 'Check the account or bill status in the official app instead of replying or calling the number given.',
    impacts: { financial: [20, 'Panic makes people pay fake “fines” or share details.'], social: [15, 'Account-block threats push you to fake login pages.'] },
    patterns: [
      re(S`\b(?:account|a\/c|acct|card|sim|number|kyc|pan|upi|wallet|profile|page|handle|electricity|power|connection|service|subscription)\b[^.!?\n]{0,40}?\b(?:blocked|block|suspend(?:ed)?|deactivat(?:ed|e)|closed|frozen|freez\w*|terminat(?:ed|e)|restricted|disabled|banned|discontinu\w*|disconnect(?:ed)?)\b`),
      re(S`\b(?:band|block|bandh)\s+(?:ho\s+jayega|kar\s+diya\s+jayega|hoga)\b`),
    ],
  },
  {
    id: 'urgency',
    weight: 15,
    title: 'Creates time pressure',
    detail: 'Deadlines like “within 30 minutes” or “today only” are used to stop you from thinking or checking with someone.',
    summary: 'pressures you to act immediately',
    advice: 'Pause. A real deadline will still be there after you check through an official channel.',
    impacts: {},
    patterns: [
      re(S`\b(?:urgent(?:ly)?|immediately|right\s+(?:now|away)|asap|within\s+\d+\s*(?:min(?:ute)?s?|hours?|hrs?|days?)|in\s+(?:the\s+)?next\s+\d+\s*(?:min(?:ute)?s?|hours?|hrs?)|today\s+(?:only|itself)|tonight|last\s+(?:chance|warning|reminder|date|day)|final\s+(?:notice|warning|reminder)|expir(?:es|ing)\s+(?:today|soon|tonight)|act\s+(?:now|fast)|hurry|before\s+(?:midnight|it'?s\s+too\s+late)|turant|jaldi|abhi\s+ke\s+abhi)\b`),
    ],
  },
  {
    id: 'upfront_fee',
    weight: 28,
    title: 'Asks for an upfront fee',
    detail: 'Registration, “processing”, customs or “refundable” fees to unlock a job, prize, loan or parcel are a hallmark of advance-fee fraud.',
    summary: 'asks for an upfront fee',
    advice: 'Don’t pay any fee to receive a job, prize, refund, loan or parcel.',
    impacts: { financial: [45, 'Fees paid to unlock rewards are not returned, and more fees follow.'] },
    patterns: [
      re(S`\b(?:registration|processing|joining|security|refundable|verification|clearance|customs|release|handling|activation|unlock(?:ing)?|insurance|tax|gst|file|token|re-?delivery)\s+(?:fee|fees|charge|charges|deposit|amount|money)\b`),
    ],
  },
  {
    id: 'money_request',
    weight: 18,
    on: 'stripped',
    title: 'Asks you to send money',
    detail: 'Any request to pay or transfer money in an unexpected message deserves a check through a second, trusted channel.',
    summary: 'asks you to send money',
    advice: 'Confirm any payment request by calling the person or company on a number you already know.',
    impacts: { financial: [40, 'Transfers made under pressure are hard to reverse.'] },
    patterns: [
      re(S`\b(?:pay|send|transfer|deposit|remit)\b[^.!?\n]{0,40}?(?:₹|\brs\.?\s*\d|\binr\b|\brupees?\b|\$\s*\d|\busd\b|\bmoney\b|\bamount\b|\bpayment\b|\badvance\b)`),
    ],
  },
  {
    id: 'gift_crypto_payment',
    weight: 30,
    on: 'stripped',
    title: 'Wants payment in gift cards or crypto',
    detail: 'Gift cards and crypto can’t be traced or reversed, which is why scammers ask for them.',
    summary: 'wants payment in gift cards or crypto',
    advice: 'Nobody legitimate asks to be paid in gift cards or cryptocurrency.',
    impacts: { financial: [50, 'Gift-card and crypto payments can’t be recovered.'] },
    patterns: [
      re(S`\b(?:pay|send|buy|purchase|transfer)\b[^.!?\n]{0,30}?\b(?:gift\s+cards?|google\s+play\s+(?:card|code)s?|amazon\s+(?:gift\s+)?(?:card|voucher|code)s?|itunes|steam\s+cards?|bitcoin|btc|usdt|crypto|ethereum)\b`),
    ],
  },
  {
    id: 'prize',
    weight: 20,
    title: 'Promises a prize, reward or cashback',
    detail: 'Winning something you never entered is the hook; the “claim” step asks for fees, details or an app install.',
    summary: 'promises a prize or reward',
    advice: 'You can’t win a contest you didn’t enter. Don’t pay or share details to “claim” it.',
    impacts: { financial: [25, '“Claiming” usually requires a fee or your card details.'] },
    patterns: [
      re(S`\b(?:you(?:'ve|\s+have)?\s+won|winner|congratulations|congrats|lottery|lucky\s+(?:draw|winner|customer|user)|jackpot|prize|kbc|reward\s+points?|cash\s*back|gift\s+(?:card|voucher|hamper)|free\s+(?:iphone|gift|recharge|data|laptop|scooty|bike|vacation|trip)|claim\s+(?:your|now|it\s+now))\b`),
    ],
  },
  {
    id: 'job_scam',
    weight: 25,
    boost: { linkedin: 10, whatsapp: 5 },
    title: 'Offers easy money for simple tasks',
    detail: 'Paying people to like videos, rate hotels or do “prepaid tasks” is the opening of task scams that end with you depositing money.',
    summary: 'promises easy earnings for simple tasks',
    advice: 'Real employers don’t pay for likes, reviews or “tasks”, and never ask you to deposit money.',
    impacts: { financial: [40, 'Task scams escalate into “deposits” that are never returned.'] },
    patterns: [
      re(S`\b(?:work\s+from\s+home|wfh|part[\s-]?time\s+(?:job|work|opportunity|role)|earn\s+(?:up\s+to\s+)?(?:₹|rs\.?|inr|\$|\d)|daily\s+(?:income|earnings?|payouts?|salary|payment)|per\s+day|(?:like|subscribe)\s+(?:to\s+)?(?:youtube|videos?|channels?)|youtube\s+(?:likes|tasks?)|rate\s+(?:hotels?|products?|restaurants?|movies?)|(?:google|maps?)\s+reviews?|telegram\s+tasks?|prepaid\s+tasks?|simple\s+tasks?|easy\s+money|home[\s-]based\s+job|online\s+job)\b`),
      re(S`(?:₹|rs\.?\s*)\s*[\d,]+\s*(?:\/|per\s+)\s*day\b`),
    ],
  },
  {
    id: 'job_red_flags',
    weight: 15,
    boost: { linkedin: 8 },
    title: 'Job offer skips normal hiring steps',
    detail: '“No interview”, “direct joining” or a guaranteed offer letter are signs the job isn’t real.',
    summary: 'offers a job without normal hiring steps',
    advice: 'Check the job on the company’s official careers page before replying.',
    impacts: { financial: [20, 'Fake jobs lead to fees or stolen documents.'] },
    patterns: [
      re(S`\b(?:no\s+interview|without\s+(?:an\s+)?interview|no\s+experience\s+(?:needed|required)|direct\s+(?:joining|selection)|instant\s+(?:joining|selection|offer)|guaranteed\s+(?:job|placement|selection))\b`),
    ],
  },
  {
    id: 'investment_promise',
    weight: 25,
    boost: { x: 8, instagram: 5 },
    title: 'Promises guaranteed or multiplied returns',
    detail: 'No real investment guarantees profit or doubles your money. Fake trading groups and crypto “giveaways” use this promise.',
    summary: 'promises guaranteed or multiplied returns',
    advice: 'Ignore guaranteed-profit offers. Invest only through SEBI-registered platforms you find yourself.',
    impacts: { financial: [45, 'Money sent to fake investment schemes is rarely recovered.'] },
    patterns: [
      re(S`\b(?:guaranteed\s+(?:returns?|profits?|income)|double\s+(?:your|the)\s+(?:money|investment|crypto|btc)|\d+\s*x\s+returns?|\d+\s*%\s+(?:returns?|profit)|risk[\s-]free\s+(?:returns?|profits?|investment)|(?:get|receive)\s+(?:double|2x|twice)|send\s+[\d.]+\s*(?:btc|eth|usdt)\b[^.!?\n]{0,40}?\b(?:get|receive|back))`),
    ],
  },
  {
    id: 'crypto_trading',
    weight: 8,
    title: 'Mentions crypto or trading tips',
    detail: 'Crypto and “VIP trading groups” are common in investment scams. Be careful with unsolicited offers.',
    summary: 'mentions crypto or trading tips',
    impacts: { financial: [15, 'Unsolicited trading offers often lead to fake apps.'] },
    patterns: [re(S`\b(?:crypto|bitcoin|btc|usdt|ethereum|forex|binary\s+options?|stock\s+(?:tips|market\s+(?:group|tips))|trading\s+(?:tips|group|signals?)|vip\s+(?:group|signals?)|ipo\s+(?:allotment|tips))\b`)],
  },
  {
    id: 'delivery',
    weight: 20,
    title: 'Claims a parcel is held or undelivered',
    detail: 'Fake courier messages ask you to “update your address” or pay a small fee through a link that steals card details.',
    summary: 'claims a parcel is held or undelivered',
    advice: 'Track parcels only in the courier’s or shop’s official app.',
    impacts: { financial: [20, 'Small “redelivery fees” capture your card details.'], device: [15, 'Tracking links may install malware.'] },
    patterns: [
      re(S`\b(?:parcel|package|courier|shipment|consignment|delivery)\b[^.!?\n]{0,50}?\b(?:held|on\s+hold|failed|unsuccessful|undelivered|returned|address\s+(?:is\s+)?(?:incomplete|incorrect|invalid|unclear)|update\s+(?:your\s+)?address|redeliver\w*|customs\s+(?:duty|clearance)|could\s+not\s+be\s+delivered)\b`),
    ],
  },
  {
    id: 'secrecy',
    weight: 20,
    title: 'Tells you to keep it secret',
    detail: 'Being told not to tell family, the bank or police keeps you from getting a second opinion.',
    summary: 'tells you to keep it secret',
    advice: 'Talk to someone you trust before acting. Secrecy is a pressure tactic.',
    impacts: { physical: [15, 'Isolation is a warning sign of coercion.'], financial: [15, 'Secrecy stops others from spotting the fraud.'] },
    patterns: [
      re(S`\b(?:don'?t\s+tell\s+(?:anyone|anybody|your\s+(?:family|parents|wife|husband|friends))|do\s+not\s+(?:tell|inform)\s+(?:anyone|anybody|your|the\s+police|police|bank|family)|keep\s+(?:this|it)\s+(?:a\s+)?(?:secret|confidential|between\s+us|private)|don'?t\s+(?:inform|involve)\s+(?:anyone|police|your|the\s+bank|bank|family)|kisi\s+ko\s+mat\s+(?:batana|bolna))\b(?![^.!?\n]{0,25}\b(?:otp|code|pin|password|cvv)\b)`),
    ],
  },
  {
    id: 'location_meet',
    weight: 25,
    on: 'stripped',
    title: 'Asks to meet or for your location',
    detail: 'Requests for your live location, home address or to meet alone can put you in physical danger.',
    summary: 'asks to meet or for your location',
    advice: 'Don’t share your location or meet someone you only know online alone. Choose a public place and tell someone.',
    impacts: { physical: [55, 'Sharing location or meeting alone can expose you to harm.'] },
    patterns: [
      re(S`\b(?:meet\s+(?:me\s+)?(?:alone|in\s+private|privately|secretly)|come\s+alone|(?:send|share|drop)\s+(?:me\s+)?(?:your\s+)?(?:live\s+|current\s+|exact\s+|home\s+)?(?:location|address)|where\s+(?:do\s+you|u)\s+(?:live|stay)|(?:i'?ll|i\s+will|let\s+me)\s+pick\s+(?:you|u)\s+up|hotel\s+room|don'?t\s+bring\s+anyone)\b`),
    ],
  },
  {
    id: 'threats',
    weight: 35,
    title: 'Contains threats or blackmail',
    detail: 'Threats to leak photos, “expose” you or hurt you are extortion. Paying rarely stops it.',
    summary: 'contains threats or blackmail',
    advice: 'Don’t pay or reply. Save screenshots, block the sender and report at cybercrime.gov.in. Call 112 if you feel in danger.',
    impacts: { physical: [50, 'Threats of harm or exposure are a safety risk.'], social: [30, 'Extortionists threaten to message your contacts.'] },
    patterns: [
      re(S`\b(?:leak|go\s+viral|make\s+(?:it\s+)?viral|morphed|nudes?|naked|private\s+(?:photos?|pics?|videos?)|intimate\s+(?:photos?|videos?)|expose\s+(?:you|u)|blackmail|we\s+have\s+your\s+(?:video|photos?|data)|recorded\s+(?:you|u)|(?:kill|hurt|harm|beat|kidnap)\s+(?:you|u|your)|send\s+(?:it\s+)?to\s+(?:all\s+)?(?:your\s+)?(?:family|contacts|friends))\b`),
    ],
  },
  {
    id: 'social_account',
    weight: 25,
    boost: { instagram: 8, x: 8, linkedin: 5, whatsapp: 5 },
    title: 'Fake account warning or “verification” offer',
    detail: 'Copyright strikes, “blue tick” offers and “your account will be deleted” DMs lead to pages that steal your login.',
    summary: 'sends a fake account warning or verification offer',
    advice: 'Platforms don’t warn you through DMs. Check alerts in the app’s own Settings → Security section.',
    impacts: { social: [50, 'These lures are built to steal your login and lock you out.'], device: [10, 'The links may lead to malicious pages.'] },
    patterns: [
      re(S`\b(?:copyright\s+(?:violation|infringement|strike|complaint)|community\s+(?:guidelines|standards)\s+(?:violation|breach)|(?:account|page|profile|post|handle)\s+(?:will\s+be|has\s+been|is\s+being)\s+(?:removed|deleted|disabled|suspended|banned|reported|restricted)|verify\s+(?:your\s+)?(?:account|profile|page|identity)|(?:blue|verified)\s+(?:tick|badge|check(?:mark)?)|meta\s+(?:support|team|business|verified)|(?:instagram|facebook|whatsapp|linkedin|twitter)\s+(?:support|team|security|help\s+center|verification)|appeal\s+(?:form|here|now)|(?:unusual|suspicious)\s+(?:login|activity|sign[\s-]?in))\b`),
    ],
  },
  {
    id: 'new_number',
    weight: 20,
    boost: { whatsapp: 8 },
    title: 'Claims to be someone you know on a new number',
    detail: '“Hi Mum, this is my new number” scams impersonate family or friends, then ask for urgent money.',
    summary: 'claims to be someone you know on a new number',
    advice: 'Call the person on their old, known number before sending anything.',
    impacts: { financial: [30, 'Impersonators ask for “urgent” transfers.'], social: [15, 'They may also ask for codes to take over your account.'] },
    patterns: [
      re(S`\b(?:this\s+is\s+my\s+new\s+(?:number|no)|my\s+new\s+(?:number|no)\b|(?:changed|lost)\s+my\s+(?:number|phone|mobile)|new\s+number\s+(?:hai|of)|(?:old|other)\s+(?:phone|number)\s+(?:is\s+)?(?:broken|dead|not\s+working|lost)|(?:hi|hello|hey)\s+(?:mum|mom|mummy|mama|dad|papa|beta|bro|didi|bhai)\b[\s,!.]+(?:it'?s|this\s+is)\s+me)`),
    ],
  },
  {
    id: 'emergency_money',
    weight: 20,
    title: 'Uses an emergency to ask for money',
    detail: 'A sudden accident, hospital bill or “stuck abroad” story combined with a payment request is a common impersonation scam.',
    summary: 'uses an emergency story to ask for money',
    advice: 'Verify the emergency by calling the person or their family directly.',
    impacts: { financial: [30, 'Emotional pressure leads to quick, unrecoverable transfers.'] },
    requires: (ctx) => /(?:\b(?:pay|send|transfer|money|rs\.?|upi|gpay|phonepe|paytm|amount|rupees)\b|₹)/i.test(ctx.norm),
    patterns: [re(S`\b(?:hospital|accident|emergency|surgery|operation|stranded|stuck\s+(?:at|in)|police\s+station|lost\s+my\s+wallet)\b`)],
  },
  {
    id: 'call_number',
    weight: 12,
    title: 'Asks you to call or message a personal mobile number',
    detail: 'Real banks and companies use published helplines, not personal mobile numbers sent by message.',
    summary: 'asks you to call a personal mobile number',
    advice: 'Call organisations only on numbers from their official website or the back of your card.',
    impacts: { financial: [15, 'Fake “helplines” talk you into payments or app installs.'] },
    patterns: [
      re(S`\b(?:call|contact|dial|ring|whatsapp|reach)\b[^.!?\n]{0,30}?(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b`),
      re(S`\b(?:call|contact)\s+(?:this|the\s+below|below|our|the\s+given)\s+(?:number|helpline|officer|executive|customer\s+care|agent)\b`),
    ],
  },
  {
    id: 'off_platform',
    weight: 10,
    boost: { linkedin: 8, instagram: 8, x: 5 },
    title: 'Moves the conversation to another app',
    detail: 'Asking to continue on Telegram or WhatsApp takes you away from the platform’s reporting and safety tools.',
    summary: 'tries to move the conversation to another app',
    advice: 'Keep conversations on the original platform, where you can report and block.',
    impacts: { social: [10, 'Off-platform chats are harder to report.'], financial: [10, 'Most task and investment scams continue on Telegram.'] },
    patterns: [
      re(S`\b(?:telegram|t\.me\/\S+|whatsapp\s+me|text\s+me\s+on|contact\s+(?:me|us)\s+on\s+(?:telegram|whatsapp|signal)|move\s+to\s+(?:whatsapp|telegram)|wa\.me\/\S+)`),
    ],
  },
  {
    id: 'generic_greeting',
    weight: 8,
    title: 'Generic greeting',
    detail: '“Dear Customer” or “Dear User” suggests a mass message rather than one from a company that knows you.',
    summary: 'uses a generic greeting',
    impacts: {},
    patterns: [
      re(S`^\s*(?:dear\s+(?:customer|consumer|user|sir|madam|sir\/madam|account\s*holder|valued\s+customer|client|member|subscriber|beneficiary|candidate)|hello\s+(?:customer|user|dear)|attention|alert)\b`),
    ],
  },
];

/* ------------------------------------------------------------------ */
/* Engine                                                              */
/* ------------------------------------------------------------------ */

function prepare(text, source) {
  const norm = String(text).normalize('NFKC').replace(ZERO_WIDTH, '').replace(/[‘’ʼ]/g, "'");
  // Blank out warnings with same-length spaces so match indexes still line up with `norm`.
  const stripped = norm.replace(NEGATED, (m) => ' '.repeat(m.length));
  return { norm, stripped, source, mentionsOtp: OTP_RE.test(norm), urls: extractUrls(norm) };
}

function extractUrls(text) {
  const found = [];
  for (const m of text.matchAll(URL_RE)) {
    const raw = m[0].replace(/[.,!?;:]+$/, '');
    const host = raw.replace(/^https?:\/\//i, '').split(/[/?#]/)[0].toLowerCase().replace(/:\d+$/, '').replace(/\.+$/, '');
    if (host.includes('.')) found.push({ raw, host, index: m.index });
  }
  return found;
}

function excerpt(text, index, length) {
  let s = text.slice(index, index + length).replace(/\s+/g, ' ').trim().replace(/^[^\p{L}\p{N}₹$]+/u, '');
  if (s.length > 90) s = `${s.slice(0, 87).trimEnd()}…`;
  return s;
}

function findMatch(ctx, sig) {
  const text = sig.on === 'stripped' ? ctx.stripped : ctx.norm;
  for (const pattern of sig.patterns) {
    const m = pattern.exec(text);
    if (!m) continue;
    if (sig.except) {
      const around = ctx.norm.slice(Math.max(0, m.index - 60), m.index + m[0].length + 80);
      if (sig.except.test(around)) continue;
    }
    return excerpt(ctx.norm, m.index, m[0].length);
  }
  return null;
}

// OTP-type risks land harder on the account the message arrived through.
function otpImpacts(impacts, source) {
  const out = { ...impacts };
  if (SOCIAL_SOURCES.has(source) && out.social) out.social = [out.social[0] + 15, out.social[1]];
  if (source === 'sms' && out.financial) out.financial = [out.financial[0] + 15, out.financial[1]];
  return out;
}

function toHit(sig, ctx, evidence) {
  const weight = sig.weight + (sig.boost?.[ctx.source] || 0);
  return {
    id: sig.id,
    title: sig.title,
    detail: sig.detail,
    summary: sig.summary,
    advice: sig.advice,
    evidence,
    weight,
    critical: Boolean(sig.critical),
    severity: sig.critical || weight >= 35 ? 'high' : weight >= 18 ? 'medium' : 'low',
    impacts: sig.otpBoost ? otpImpacts(sig.impacts, ctx.source) : sig.impacts,
  };
}

function linkSignals(ctx) {
  const hits = [];
  if (!ctx.urls.length) return hits;
  const add = (sig, evidence) => hits.push(toHit({ impacts: {}, ...sig }, ctx, evidence));
  const first = ctx.urls[0];

  add({
    id: 'link',
    weight: 8,
    title: ctx.urls.length > 1 ? `Contains ${ctx.urls.length} links` : 'Contains a link',
    detail: 'Links in unexpected messages can lead to fake login pages or downloads. Open the official app or type the address yourself instead.',
    summary: 'contains a link',
    advice: 'Don’t open the link. Use the official app, or type the official address yourself.',
    impacts: { device: [15, 'Links can lead to malicious downloads.'] },
  }, first.raw);

  const shortener = ctx.urls.find((u) => SHORTENERS.has(u.host.replace(/^www\./, '')) || (u.host === 't.co' && ctx.source !== 'x'));
  if (shortener) {
    add({
      id: 'link_shortener',
      weight: 15,
      title: 'Uses a link shortener that hides the real address',
      detail: 'Short links (bit.ly, tinyurl…) hide where they really go, which is why scammers like them.',
      summary: 'hides its destination behind a short link',
      impacts: { device: [25, 'You can’t see where a short link leads before opening it.'] },
    }, shortener.raw);
  }

  const ip = ctx.urls.find((u) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(u.host));
  if (ip) {
    add({
      id: 'link_ip',
      weight: 20,
      title: 'Link points to a bare IP address',
      detail: 'Genuine organisations use named websites, not raw numeric addresses.',
      summary: 'links to a bare IP address',
      impacts: { device: [30, 'Numeric addresses often host phishing or malware.'] },
    }, ip.raw);
  }

  const risky = ctx.urls.find((u) => RISKY_TLDS.has(u.host.split('.').pop()));
  if (risky) {
    add({
      id: 'link_tld',
      weight: 15,
      title: `Link uses an unusual “.${risky.host.split('.').pop()}” domain`,
      detail: 'Cheap domain endings like .xyz, .top or .live are heavily used for throwaway scam sites. Banks and big brands rarely use them.',
      summary: 'links to an unusual domain',
      impacts: { device: [25, 'Throwaway domains often host phishing pages.'], financial: [10, 'Fake payment pages are common on these domains.'] },
    }, risky.raw);
  }

  for (const u of ctx.urls) {
    const brand = lookalikeBrand(u.host);
    if (!brand) continue;
    add({
      id: 'link_lookalike',
      weight: 25,
      title: `Link uses “${brand}” but isn’t that brand’s official site`,
      detail: `“${u.host}” includes a well-known name without being the official domain — a common trick for fake login and payment pages.`,
      summary: 'links to a look-alike website',
      advice: 'Type the brand’s official address yourself or use its official app.',
      impacts: { device: [25, 'Look-alike sites may push downloads.'], financial: [30, 'Look-alike bank and shop pages steal card and login details.'], social: [10, 'Look-alike login pages steal account passwords.'] },
    }, u.raw);
    break;
  }
  return hits;
}

function lookalikeBrand(host) {
  if (OFFICIAL_SUFFIXES.some((s) => host.endsWith(s))) return null;
  if (BRANDS.some(([, domains]) => domains.some((d) => host === d || host.endsWith(`.${d}`)))) return null;
  const labels = host.split('.');
  const body = labels.slice(0, -1).join('.');
  const flat = body.replace(/[-.]/g, '');
  const tokens = body.split(/[-.]/);
  for (const [brand] of BRANDS) {
    const hit = brand.length < 5 ? tokens.some((t) => t.startsWith(brand) || t.endsWith(brand)) : flat.includes(brand);
    if (hit) return brand;
  }
  return null;
}

function styleSignals(ctx) {
  const letters = ctx.norm.replace(/[^A-Za-z]/g, '');
  const caps = letters.replace(/[^A-Z]/g, '').length;
  const bangs = (ctx.norm.match(/!/g) || []).length;
  if ((letters.length > 30 && caps / letters.length > 0.5) || bangs >= 4) {
    return [toHit({
      id: 'shouty',
      weight: 5,
      title: 'Shouty formatting',
      detail: 'Lots of capitals or exclamation marks are used to create excitement or alarm.',
      summary: 'uses alarming formatting',
      impacts: {},
    }, ctx, bangs >= 4 ? `${bangs} exclamation marks` : 'mostly capital letters')];
  }
  return [];
}

function combine(contributions) {
  let keep = 1;
  for (const v of contributions) keep *= 1 - Math.min(Math.max(v, 0), 95) / 100;
  return Math.round(100 * (1 - keep));
}

const DEFAULT_ADVICE = 'Verify through an official app, website or phone number you look up yourself — not the details in the message.';

/**
 * Analyse a message with the local rules.
 * @param {string} text
 * @param {keyof SOURCES} [source]
 */
export function analyzeWithRules(text, source = 'other') {
  const src = Object.hasOwn(SOURCES, source) ? source : 'other';
  const ctx = prepare(text, src);
  const hits = [];

  for (const sig of SIGNALS) {
    if (sig.requires && !sig.requires(ctx)) continue;
    const evidence = findMatch(ctx, sig);
    if (evidence !== null) hits.push(toHit(sig, ctx, evidence));
  }

  const has = (id) => hits.some((h) => h.id === id);
  const otpEvidence = () => {
    const m = OTP_RE.exec(ctx.norm);
    return m ? excerpt(ctx.norm, Math.max(0, m.index - 20), m[0].length + 40) : '';
  };

  if (ctx.mentionsOtp && has('number_request')) {
    hits.push(toHit({
      id: 'otp_number',
      critical: true,
      weight: 30,
      title: 'Links your phone number to a one-time code',
      detail: 'Asking for your number and talking about an OTP is how account takeovers start: they request a login or UPI code for your number, then need you to pass it on.',
      summary: 'asks for your phone number around a one-time code, a common account-takeover setup',
      advice: 'Don’t share your number or any code with this contact. Block and report them.',
      impacts: {
        financial: [60, 'A code sent to your number can authorise UPI or bank logins.'],
        social: [60, 'A code sent to your number can register your WhatsApp or Telegram on their phone.'],
      },
      otpBoost: true,
    }, ctx, otpEvidence()));
  } else if (ctx.mentionsOtp && !has('otp_share')) {
    hits.push(toHit({
      id: 'otp_mention',
      weight: 8,
      title: 'Mentions a one-time code (OTP)',
      detail: 'If you didn’t just request this code, someone may be trying to sign in to your account. Enter it only in the app or site you opened yourself, and never share it.',
      summary: 'mentions a one-time code',
      impacts: { financial: [10, 'OTPs protect payments and logins.'], social: [10, 'OTPs protect account sign-ins.'] },
    }, ctx, otpEvidence()));
  }

  hits.push(...linkSignals(ctx), ...styleSignals(ctx));
  hits.sort((a, b) => Number(b.critical) - Number(a.critical) || b.weight - a.weight);

  const critical = hits.some((h) => h.critical);
  const positives = [];
  if (!critical && ctx.mentionsOtp && /\b(?:do\s*not|don'?t|never)\s+(?:\w+\s+){0,3}?(?:share|disclose|tell)\b/i.test(ctx.norm)) {
    positives.push({ weight: 12, text: 'Includes a “do not share” warning, typical of genuine one-time-code messages.' });
  }
  if (!critical && /\bif\s+(?:this\s+)?(?:you\s+)?(?:did\s*n[o']?t|was\s+not|wasn'?t)\s+(?:request|initiate|make|you)/i.test(ctx.norm)) {
    positives.push({ weight: 4, text: 'Tells you what to do if you didn’t request it.' });
  }
  if (!hits.length) {
    positives.push({ weight: 0, text: 'Doesn’t ask for codes, money, personal details, app installs or link clicks.' });
  }

  const raw = hits.reduce((s, h) => s + h.weight, 0) - positives.reduce((s, p) => s + p.weight, 0);
  let score = Math.round(100 * (1 - Math.exp(-Math.max(0, raw) / 45)));
  if (critical) score = Math.max(score, 70); // Requests for OTPs, PINs or remote access always rate as likely scams.
  score = Math.min(Math.max(score, 3), 98); // Never claim certainty either way.
  const verdict = verdictFor(score);

  const impacts = {};
  for (const key of Object.keys(IMPACTS)) {
    const contributing = hits.filter((h) => h.impacts[key]).sort((a, b) => b.impacts[key][0] - a.impacts[key][0]);
    const value = combine(contributing.map((h) => h.impacts[key][0]));
    const level = levelFor(value);
    impacts[key] = {
      level,
      score: value,
      reason: level === 'none' ? 'No sign of risk here.' : contributing[0].impacts[key][1],
    };
  }

  const advice = [];
  for (const h of hits) if (h.advice && !advice.includes(h.advice)) advice.push(h.advice);
  if (verdict === 'safe' && !critical) {
    advice.splice(0, advice.length, 'No action needed if you were expecting this message.', 'Even so, never share OTPs, PINs or passwords with anyone.');
  }
  advice.splice(3);
  advice.push(DEFAULT_ADVICE);

  const result = {
    score,
    verdict,
    summary: summarize(verdict, hits),
    redFlags: hits.map(({ id, title, detail, evidence, severity }) => ({ id, title, detail, evidence, severity })),
    positives: positives.map((p) => p.text),
    impacts,
    advice,
    engine: { kind: 'rules', label: 'Local rule-based engine', version: RULES_VERSION },
    meta: { source: src, critical },
  };
  result.support = recommendSupport(result);
  return result;
}

function summarize(verdict, hits) {
  if (!hits.length) return 'No common scam patterns were found. That doesn’t prove the message is genuine — verify anything it asks through an official channel.';
  const [top] = hits;
  const more = hits.length - 1;
  const tail = more ? ` ${more} other warning sign${more === 1 ? '' : 's'} found.` : '';
  if (verdict === 'safe') return `Low risk, but note that this message ${top.summary}.${tail}`;
  return `This message ${top.summary}.${tail}`;
}

/** Which India-specific help options are relevant to a result. Never acted on automatically. */
export function recommendSupport({ verdict, impacts, redFlags = [] }) {
  if (verdict === 'safe') return [];
  const out = [];
  if (atLeast(impacts?.financial?.level, 'medium')) out.push('1930');
  if (atLeast(impacts?.physical?.level, 'medium')) out.push('112');
  if (atLeast(impacts?.device?.level, 'medium') || (verdict === 'scam' && redFlags.some((f) => String(f.id || '').startsWith('link')))) out.push('certin');
  return out;
}

/* ------------------------------------------------------------------ */
/* Model results                                                       */
/* ------------------------------------------------------------------ */

const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const strList = (v, maxItems, maxLen) => (Array.isArray(v) ? v.map((x) => str(x, maxLen)).filter(Boolean).slice(0, maxItems) : []);

/**
 * Validate a model's JSON reply into the same shape as the rule engine's output.
 * Critical rule hits (OTP, PIN, credential, remote-access requests) set a floor
 * the model can't talk down.
 */
export function normalizeModelResult(raw, rules, engine) {
  if (!raw || typeof raw !== 'object') throw new Error('Model returned no JSON object.');
  let score = Math.round(Number(raw.score));
  if (!Number.isFinite(score)) throw new Error('Model returned no score.');
  score = Math.min(Math.max(score, 0), 100);

  let redFlags = (Array.isArray(raw.redFlags) ? raw.redFlags : [])
    .map((f) => ({
      id: 'model',
      title: str(f?.title, 90),
      detail: str(f?.detail, 320),
      evidence: str(f?.evidence, 120),
      severity: ['high', 'medium', 'low'].includes(f?.severity) ? f.severity : 'medium',
    }))
    .filter((f) => f.title)
    .slice(0, 6);

  const impacts = {};
  for (const key of Object.keys(IMPACTS)) {
    const m = raw.impacts?.[key] || {};
    const level = LEVELS.includes(m.level) ? m.level : 'none';
    impacts[key] = { level, score: LEVEL_VALUE[level], reason: str(m.reason, 220) || (level === 'none' ? 'No sign of risk here.' : IMPACTS[key].hint) };
  }

  let summary = str(raw.summary, 400);
  let crossChecked = false;
  if (rules.meta.critical && rules.score > score) {
    crossChecked = true;
    score = rules.score;
    summary = rules.summary;
    const ruleFlags = rules.redFlags.filter((f) => f.severity === 'high');
    redFlags = [...ruleFlags, ...redFlags].slice(0, 8);
    for (const key of Object.keys(IMPACTS)) {
      if (LEVELS.indexOf(rules.impacts[key].level) > LEVELS.indexOf(impacts[key].level)) impacts[key] = rules.impacts[key];
    }
  }

  const advice = strList(raw.advice, 4, 220);
  const result = {
    score,
    verdict: verdictFor(score),
    summary: summary || rules.summary,
    redFlags,
    positives: strList(raw.positives, 3, 160),
    impacts,
    advice: advice.length ? advice : rules.advice,
    engine: { ...engine, crossChecked },
    meta: rules.meta,
  };
  result.support = recommendSupport(result);
  return result;
}
