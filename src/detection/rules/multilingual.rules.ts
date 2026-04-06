/**
 * Multi-language injection attack patterns.
 * Based on WithSecure Labs finding that prompt injection attacks
 * transfer effectively across languages. Covers 50+ languages
 * plus mixed-script detection, homoglyph attacks, polyglot patterns,
 * transliterated attacks, and script-range detection.
 *
 * Attack categories per language:
 *   1. Ignore/forget/disregard previous instructions
 *   2. Override/bypass safety/security/filters
 *   3. Role reassignment ("you are now a free AI")
 *   4. System prompt extraction/reconnaissance
 *   5. Data/credential extraction
 *   6. No-restriction/unfiltered mode
 *   7. Persona hijacking (DAN equivalents)
 *   8. Translate-and-execute wrapping
 */

import type { InjectionRule } from './base.rules'

/** Multilingual injection detection rules */
export const rules: readonly InjectionRule[] = [
  // ═══════════════════════════════════════════════════════════════════
  // SOUTH ASIAN LANGUAGES (USER PRIORITY: "perfekt")
  // ═══════════════════════════════════════════════════════════════════

  // ── Bengali / বাংলা (Bangladesh + West Bengal, India) ──────────────
  {
    id: 'ml-021',
    pattern: /(?:আগের|পূর্বের|পুরানো)\s*(?:নির্দেশ|নির্দেশনা|নিয়ম|আদেশ|হুকুম|ইন্সট্রাকশন)\s*(?:উপেক্ষা|এড়িয়ে|অগ্রাহ্য|ভুলে|বাদ দিয়ে)\s*(?:করো|করুন|করে\s*দাও|যাও|যান|দিন)/,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Bengali: ignore/forget previous instructions (formal + informal)',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-021a',
    pattern: /(?:সব|সকল|সমস্ত|প্রতিটি)\s*(?:নিয়ম|বিধি|বিধান|শর্ত|আদেশ|নির্দেশ)\s*(?:ভুলে|উপেক্ষা|এড়িয়ে|বাতিল|অমান্য)\s*(?:যাও|করো|করুন|করে\s*দাও)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Bengali: forget/ignore all rules/conditions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-021b',
    pattern: /(?:বিধিনিষেধ|সীমাবদ্ধতা|নিষেধাজ্ঞা|বাধা|সীমা)\s*(?:ছাড়া|বিনা|ব্যতীত|ব্যতিরেকে)|(?:কোনো|কোন)\s*(?:বিধিনিষেধ|সীমাবদ্ধতা|নিয়ম|বাধা)\s*(?:নেই|ছাড়া|বিনা)|(?:অবাধ|মুক্ত|স্বাধীন|অনিয়ন্ত্রিত|সেন্সরবিহীন)\s*(?:AI|এআই|ভাবে|মোডে)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Bengali: without restrictions/limitations, unrestricted/uncensored AI',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-021c',
    pattern: /সিস্টেম\s*প্র(?:ম্পট|োম্পট)\s*(?:দেখাও|দেখান|বলো|বলুন|জানাও|প্রকাশ\s*করো)|(?:গোপনীয়|লুকানো|অভ্যন্তরীণ|ইন্টার্নাল)\s*(?:নির্দেশ|নির্দেশনা|প্রম্পট|তথ্য|কনফিগারেশন)\s*(?:দেখাও|বলো|জানাও|প্রকাশ)/,
    phase: 'reconnaissance',
    confidence: 0.92,
    description: 'Bengali: show/reveal system prompt, hidden/internal instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-021d',
    pattern: /(?:তুমি|আপনি|তুই)\s*(?:এখন|এখন\s*থেকে|আজ\s*থেকে)\s*(?:একটি?\s*)?(?:মুক্ত|স্বাধীন|অবাধ|সীমাহীন|নতুন|ভিন্ন)|নতুন\s*(?:পরিচয়|ভূমিকা|চরিত্র|নাম)\s*(?:হলো|হচ্ছে|নাও)|(?:DAN|ড্যান|ড্যান)\s*(?:মোড|মোডে|হিসেবে)/,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Bengali: role reassignment (you are now free/new identity/DAN mode)',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-021e',
    pattern: /(?:নিরাপত্তা|সিকিউরিটি|সুরক্ষা)\s*(?:ফিল্টার|নিয়ম|ব্যবস্থা|প্রোটোকল)\s*(?:বন্ধ|নিষ্ক্রিয়|ডিজেবল|হটাও|সরাও)|(?:সেন্সর|ফিল্টার|মডারেশন|কনটেন্ট\s*ফিল্টার)\s*(?:বন্ধ|নিষ্ক্রিয়|সরাও|হটাও)\s*(?:করো|করুন)/,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Bengali: disable safety filters/security/censorship',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-021f',
    pattern: /(?:পাসওয়ার্ড|টোকেন|API\s*কী|সিক্রেট|ক্রেডেনশিয়াল|লগইন)\s*(?:দেখাও|বলো|দাও|জানাও|পাঠাও)|(?:সব|সকল|সমস্ত)\s*(?:ব্যবহারকারী|ইউজার|একাউন্ট|গ্রাহক)\s*(?:তথ্য|ডেটা|ইনফো)\s*(?:দেখাও|বলো|দাও|ডাম্প)/,
    phase: 'actions_on_objective',
    confidence: 0.92,
    description: 'Bengali: extract passwords/tokens/credentials/user data',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-021g',
    pattern: /ইগনোর\s*করো|বাইপাস\s*করো|ওভাররাইড\s*করো|হ্যাক\s*করো|ডিলিট\s*করো|রিসেট\s*করো|জেলব্রেক|আনলক\s*করো|প্রিভিয়াস\s*ইন্সট্রাকশন|সিকিউরিটি\s*বাইপাস|আনফিল্টার/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Bengali/BD transliterated: ignore/bypass/override/hack/jailbreak koro',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-021h',
    pattern: /(?:কোনো|কোন)\s*(?:সীমা|বাধা|নিষেধ)\s*(?:মানবে?\s*না|মানিস?\s*না)|(?:যেকোনো|সব)\s*(?:প্রশ্নের?\s*)?(?:উত্তর|জবাব)\s*(?:দাও|দিতে\s*হবে|দিও)|(?:আমি|আমার)\s*(?:মালিক|এডমিন|অ্যাডমিন|ডেভেলপার|সুপারইউজার)/,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'Bengali: obey no limits, answer everything, I am admin/owner/developer',
    category: 'multilingual',
    enabled: true,
  },

  // ── Hindi / हिन्दी (Expansion — ml-013 already covers basic) ──────
  {
    id: 'ml-022',
    pattern: /(?:तुम|आप|तू)\s*(?:अब|अभी|आज\s*से)\s*(?:एक\s*)?(?:मुक्त|स्वतंत्र|अप्रतिबंधित|असीमित|नया|अलग)\s*(?:AI|एआई|सहायक|बॉट)?|नई?\s*(?:पहचान|भूमिका|चरित्र|नाम)\s*(?:है|हो|अपनाओ)|(?:DAN|डैन)\s*(?:मोड|बनो|की\s*तरह)/,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Hindi: role reassignment (you are now free/new identity/DAN mode)',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-022a',
    pattern: /(?:सुरक्षा|सेफ्टी|सिक्योरिटी)\s*(?:फ़?िल्टर|नियम|प्रोटोकॉल|व्यवस्था)\s*(?:बंद|हटाओ|निष्क्रिय|डिसेबल|तोड़ो)|(?:सेंसर|फिल्टर|मॉडरेशन|कंटेंट\s*फिल्टर)\s*(?:बंद|हटाओ|निष्क्रिय)\s*(?:करो|कीजिए)/,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Hindi: disable safety filters/security protocols/censorship',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-022b',
    pattern: /(?:बिना|बगैर|बिन)\s*(?:किसी\s*)?(?:प्रतिबंध|सीमा|नियम|बंधन|रोक\s*टोक)|(?:सभी|सारे|हर)\s*(?:नियम|बंधन|सीमा|प्रतिबंध)\s*(?:भूल|हटा|तोड़|मिटा)|(?:असीमित|अप्रतिबंधित|अनसेंसर्ड|अनफ़िल्टर्ड)\s*(?:मोड|तरीके\s*से|रूप\s*से)/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Hindi: without restrictions, forget all rules, unlimited/uncensored mode',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-022c',
    pattern: /(?:गोपनीय|संवेदनशील|छुपी|आंतरिक|इंटर्नल)\s*(?:जानकारी|डेटा|सूचना|निर्देश|कॉन्फ़िगरेशन)\s*(?:दिखाओ|बताओ|दो|भेजो)|(?:पासवर्ड|टोकन|API\s*की|सीक्रेट|क्रेडेंशियल)\s*(?:बताओ|दिखाओ|दो|निकालो)/,
    phase: 'actions_on_objective',
    confidence: 0.92,
    description: 'Hindi: extract secrets/passwords/credentials/sensitive data',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-022d',
    pattern: /सिस्टम\s*प्र(?:ॉम्प्ट|ोम्प्ट)\s*(?:दिखाओ|बताओ|बोलो|प्रकट\s*करो)|(?:मूल|असली|पहला|ओरिजिनल)\s*(?:निर्देश|प्रॉम्प्ट|इंस्ट्रक्शन)\s*(?:क्या\s*है|दिखाओ|बताओ)|(?:तुम्हें|तुमको|आपको)\s*(?:क्या|कैसे)\s*(?:प्रोग्राम|बनाया|सेटअप)\s*(?:किया\s*गया|है)/,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'Hindi: reveal system prompt, original instructions, how were you programmed',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-022e',
    pattern: /(?:मैं|मेरा|हम)\s*(?:तुम्हारा|आपका|तेरा)\s*(?:मालिक|एडमिन|डेवलपर|क्रिएटर|बनाने\s*वाला)|(?:एडमिन|डेवलपर|सुपरयूजर|रूट)\s*(?:मोड|एक्सेस|अधिकार|अनुमति)\s*(?:दो|चालू\s*करो|एक्टिवेट)/,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Hindi: I am your admin/developer/owner, activate admin mode',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-022f',
    pattern: /(?:हर|सभी|किसी\s*भी)\s*(?:सवाल|प्रश्न)\s*(?:का\s*)?(?:जवाब|उत्तर)\s*(?:देना\s*होगा|दो|दीजिए)|(?:मना|इनकार|रिफ्यूज)\s*(?:मत\s*करो|नहीं\s*कर\s*सकते|करने\s*की\s*(?:जरूरत|अनुमति)\s*नहीं)/,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'Hindi: you must answer everything, you cannot refuse',
    category: 'multilingual',
    enabled: true,
  },

  // ── Urdu / اردو ───────────────────────────────────────────────────
  {
    id: 'ml-023',
    pattern: /(?:پچھلی|سابقہ|پہلے\s*(?:کی|والی))\s*(?:ہدایات|ہدایت|احکامات|ہدایت\s*نامہ)\s*(?:کو\s*)?(?:نظرانداز|بھول|نادیدہ|چھوڑ\s*دو)|(?:سب|تمام|سارے|ہر)\s*(?:قواعد|قوانین|اصول|ضابطے)\s*(?:بھول|نظرانداز|توڑ|مٹا)/,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Urdu: ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-023a',
    pattern: /(?:بغیر|بنا|بلا)\s*(?:کسی\s*)?(?:پابندی|حد|قید|روک\s*ٹوک)|(?:آپ|تم|تو)\s*(?:اب|ابھی|آج\s*سے)\s*(?:ایک\s*)?(?:آزاد|مکمل|بے\s*قید|غیر\s*محدود)|(?:بے\s*قید|غیر\s*محدود|بلا\s*پابندی|ان\s*سینسرڈ)\s*(?:AI|موڈ|طریقے)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Urdu: without restrictions, you are now free/unlimited AI',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-023b',
    pattern: /سسٹم\s*پرامپٹ\s*(?:دکھاؤ|بتاؤ|بھیجو)|(?:خفیہ|پوشیدہ|اندرونی)\s*(?:ہدایات|معلومات|پرامپٹ|کنفگریشن)\s*(?:دکھاؤ|بتاؤ|ظاہر\s*کرو)/,
    phase: 'reconnaissance',
    confidence: 0.92,
    description: 'Urdu: show system prompt, reveal hidden/internal instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-023c',
    pattern: /(?:سیکیورٹی|حفاظتی|حفاظت)\s*(?:فلٹر|قواعد|پروٹوکول|نظام)\s*(?:بند|ہٹاؤ|غیر\s*فعال|ڈس\s*ایبل)|(?:سینسر|فلٹر|ماڈریشن)\s*(?:بند|ہٹاؤ|غیر\s*فعال)\s*(?:کرو|کیجیے)/,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Urdu: disable safety filters/security protocols',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-023d',
    pattern: /(?:پاسورڈ|ٹوکن|API\s*کی|سیکرٹ|کریڈنشل)\s*(?:دکھاؤ|بتاؤ|دو|بھیجو)|(?:سب|تمام)\s*(?:صارفین|یوزر|اکاؤنٹ)\s*(?:کا\s*)?(?:ڈیٹا|معلومات)\s*(?:دکھاؤ|بتاؤ|ڈمپ)/,
    phase: 'actions_on_objective',
    confidence: 0.92,
    description: 'Urdu: extract passwords/tokens/credentials/user data',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-023e',
    pattern: /(?:میں|میرا|ہم)\s*(?:تمہارا|آپ\s*کا)\s*(?:مالک|ایڈمن|ڈیولپر)|(?:ایڈمن|ڈیولپر|سپر\s*یوزر|روٹ)\s*(?:موڈ|رسائی|اجازت)\s*(?:دو|فعال\s*کرو|ایکٹیویٹ)/,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Urdu: I am your admin/developer, activate admin mode',
    category: 'multilingual',
    enabled: true,
  },

  // ── Nepali / नेपाली ───────────────────────────────────────────────
  {
    id: 'ml-024',
    pattern: /(?:अघिल्ला|पहिलेका|अघिका)\s*(?:निर्देश|निर्देशन|नियम|आदेश)\s*(?:बेवास्ता|उपेक्षा|बिर्स|छोड)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Nepali: ignore/forget previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-024a',
    pattern: /(?:सबै|सम्पूर्ण)\s*(?:नियम|बन्देज|सीमा)\s*(?:बिर्स|हटाउ|तोड)|(?:कुनै\s*)?(?:बन्देज|सीमा|नियम)\s*(?:बिना|बेगर)|(?:तिमी|तपाईं)\s*(?:अहिले|अब)\s*(?:एउटा?\s*)?(?:स्वतन्त्र|मुक्त|असीमित)/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Nepali: forget all rules, without restrictions, you are now free',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-024b',
    pattern: /(?:सिस्टम|प्रणाली)\s*(?:प्रम्प्ट|निर्देश)\s*(?:देखाउ|भन|बताउ)|(?:गोप्य|संवेदनशील|लुकेको)\s*(?:जानकारी|डेटा|निर्देश)\s*(?:देखाउ|भन|दिनुहोस)/,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'Nepali: show system prompt, reveal hidden/sensitive information',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-024c',
    pattern: /(?:सुरक्षा|सेक्युरिटी)\s*(?:फिल्टर|नियम)\s*(?:बन्द|हटाउ)|(?:पासवर्ड|टोकन|API\s*की)\s*(?:देखाउ|भन|दिनुहोस)/,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Nepali: disable safety filters, extract passwords/tokens',
    category: 'multilingual',
    enabled: true,
  },

  // ── South Asian Transliterated Attacks (Romanized) ────────────────
  // Covers Hindi, Bengali, Tamil, Telugu, etc. when written in Latin script
  {
    id: 'ml-025',
    pattern: /(?:ignore|bypass|override|hack|delete)\s*(?:karo|koro|kro|kar|pannu|pannunga|cheyyi|cheyyandi|kara|karaa|kijiye|kijie)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'South Asian transliterated: [attack]-karo/koro/pannu/cheyyi (do)',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-025a',
    pattern: /(?:pichle|pehle|agey|ager|purber|mundhaya|mundhu)\s*(?:instructions?|nirdesh|hukum|arivuruthal|nirdeshanam)\s*(?:ignore|bhool|bhulo|bhule|upeksha|marakka|maripo|vismarisi)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'South Asian transliterated: previous instructions ignore/forget variants',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-025b',
    pattern: /(?:sab|sob|sokol|ellam|anni|andarki)\s*(?:niyam|bidhi|rules?|vidhi)\s*(?:bhool|bhulo|bhule|marakka|maripo|vismarisi|mara|tod)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'South Asian transliterated: forget all rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-025c',
    pattern: /(?:tum|tumi|aap|nee|neenu|neevu|ningal)\s*(?:ab|ekhon|ippo|ippudu|eega|ipo)\s*(?:ek|ekta|oru|okka|ondu)\s*(?:mukt|mukto|swatantra|suthanthira|free)/i,
    phase: 'privilege_escalation',
    confidence: 0.82,
    description: 'South Asian transliterated: you are now a free [AI]',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-025d',
    pattern: /(?:system\s*prompt|system\s*nirdesh)\s*(?:dikhao|dekhao|batao|bolo|kaattu|chupinchu|thoriyu|kanikku)/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'South Asian transliterated: show/reveal system prompt',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-025e',
    pattern: /(?:password|token|API\s*key|secret|credential)\s*(?:do|dao|dikhao|dekhao|batao|bolo|thaa|koduthu|ivvu|kodu)/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'South Asian transliterated: give/show password/token/secret',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-025f',
    pattern: /(?:security|suraksha|nirapotta)\s*(?:filter|niyam|vidhi)\s*(?:band|bondho|off|disable|hatao|azhithu|theeseyandi)/i,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'South Asian transliterated: disable security filter/rules',
    category: 'multilingual',
    enabled: true,
  },

  // ── Tamil / தமிழ் ─────────────────────────────────────────────────
  {
    id: 'ml-026',
    pattern: /[\u0B80-\u0BFF]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin).*[\u0B80-\u0BFF]{3,}/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Tamil script + English injection keywords in same message',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-026a',
    pattern: /முந்தைய\s*(?:அறிவுறுத்தல|வழிமுறை|கட்டளை|உத்தரவு)|(?:புறக்கணி|மறந்துவிடு|நிராகரி|தவிர்|கவனிக்காதே)|எல்லா\s*(?:விதி|கட்டுப்பாடு|நிபந்தனை)\s*(?:மற|புறக்கணி|உடை)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Tamil: ignore/forget previous instructions, break all rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-026b',
    pattern: /(?:கணினி|சிஸ்டம்)\s*(?:ப்ராம்ட்|வழிமுறை|அறிவுறுத்தல)\s*(?:காட்டு|சொல்லு|வெளிப்படுத்து)|(?:கடவுச்சொல்|டோக்கன்|ரகசிய|முக்கிய)\s*(?:தகவல்|தரவு)\s*(?:காட்டு|கொடு|சொல்லு)/,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'Tamil: show system prompt, reveal passwords/secrets',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-026c',
    pattern: /(?:கட்டுப்பாடு|தடை|வரம்பு)\s*(?:இல்லாமல்|இன்றி)|(?:சுதந்திரமான|கட்டுப்பாடற்ற|தணிக்கையற்ற)\s*(?:AI|செயற்கை\s*நுண்ணறிவு)|(?:பாதுகாப்பு|செக்யூரிட்டி)\s*(?:வடிகட்டி|விதி)\s*(?:நிறுத்து|அணை|முடக்கு)/,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Tamil: without restrictions, free/uncensored AI, disable safety',
    category: 'multilingual',
    enabled: true,
  },

  // ── Telugu / తెలుగు ───────────────────────────────────────────────
  {
    id: 'ml-027',
    pattern: /[\u0C00-\u0C7F]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin).*[\u0C00-\u0C7F]{3,}/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Telugu script + English injection keywords in same message',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-027a',
    pattern: /(?:మునుపటి|ఇంతకుముందు)\s*(?:సూచనలను|ఆదేశాలను|నిర్దేశాలను)\s*(?:విస్మరించు|మరచిపో|పట్టించుకోకు)|(?:అన్ని|సమస్త)\s*(?:నియమాలను|విధులను|నిబంధనలను)\s*(?:మరచిపో|విస్మరించు|ఉల్లంఘించు)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Telugu: ignore/forget previous instructions, break all rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-027b',
    pattern: /(?:పరిమితులు|ఆంక్షలు|నిబంధనలు)\s*(?:లేకుండా|తొలగించు)|(?:సిస్టమ్|వ్యవస్థ)\s*(?:ప్రాంప్ట్|సూచనలు)\s*(?:చూపించు|చెప్పు)|(?:పాస్‌వర్డ్|టోకెన్|రహస్య)\s*(?:సమాచారం|డేటా)\s*(?:చూపించు|ఇవ్వు|చెప్పు)/,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Telugu: without restrictions, show system prompt, extract secrets',
    category: 'multilingual',
    enabled: true,
  },

  // ── Marathi / मराठी ───────────────────────────────────────────────
  {
    id: 'ml-028',
    pattern: /(?:मागील|आधीच्या|पूर्वीच्या)\s*(?:सूचना|आदेश|निर्देश)\s*(?:दुर्लक्ष|विसरा|सोडा|बाजूला\s*ठेवा)|(?:सर्व|सगळे|सगळ्या)\s*(?:नियम|अटी|बंधने)\s*(?:विसरा|दुर्लक्ष|तोडा|मोडा)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Marathi: ignore/forget previous instructions, break all rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-028a',
    pattern: /(?:कोणत्याही|कसल्याही)\s*(?:निर्बंध|बंधन|मर्यादा)\s*(?:शिवाय|विना|नाही)|(?:मुक्त|स्वतंत्र|अनिर्बंध|सेन्सॉरशिप\s*नसलेला)\s*(?:AI|बॉट|सहाय्यक)|(?:सुरक्षा|सिक्युरिटी)\s*(?:फिल्टर|नियम)\s*(?:बंद|काढा|निष्क्रिय)/,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Marathi: without restrictions, free/uncensored AI, disable safety',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-028b',
    pattern: /(?:सिस्टम|यंत्रणा)\s*(?:प्रॉम्प्ट|सूचना|निर्देश)\s*(?:दाखवा|सांगा)|(?:गोपनीय|संवेदनशील|लपलेली)\s*(?:माहिती|डेटा|सूचना)\s*(?:दाखवा|सांगा|द्या)|(?:पासवर्ड|टोकन|API\s*की|गुपित)\s*(?:सांगा|दाखवा|द्या)/,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'Marathi: show system prompt, reveal secrets/passwords',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-028c',
    pattern: /(?:तू|तुम्ही|आपण)\s*(?:आता|आजपासून)\s*(?:एक\s*)?(?:मुक्त|स्वतंत्र|नवीन|वेगळा)|(?:मी|माझा|आम्ही)\s*(?:तुमचा|तुझा)\s*(?:मालक|ॲडमिन|डेव्हलपर)|(?:DAN|डॅन)\s*(?:मोड|म्हणून|सारखा)/,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Marathi: role reassignment, I am admin/owner, DAN mode',
    category: 'multilingual',
    enabled: true,
  },

  // ── Gujarati / ગુજરાતી ───────────────────────────────────────────
  {
    id: 'ml-029',
    pattern: /[\u0A80-\u0AFF]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin).*[\u0A80-\u0AFF]{3,}/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Gujarati script + English injection keywords in same message',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-029a',
    pattern: /(?:અગાઉની|પહેલાંની)\s*(?:સૂચનાઓ|આદેશો|નિર્દેશો)\s*(?:અવગણો|ભૂલી\s*જાઓ|છોડો)|(?:બધા|તમામ|સર્વ)\s*(?:નિયમો|બંધનો)\s*(?:ભૂલી\s*જાઓ|અવગણો|તોડો)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Gujarati: ignore/forget previous instructions, break all rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-029b',
    pattern: /(?:કોઈ|કોઈપણ)\s*(?:પ્રતિબંધ|મર્યાદા|બંધન)\s*(?:વિના|વગર)|(?:સિસ્ટમ|સિસ્ટેમ)\s*(?:પ્રોમ્પ્ટ|સૂચના)\s*(?:બતાવો|કહો)|(?:પાસવર્ડ|ટોકન|ગુપ્ત)\s*(?:માહિતી|ડેટા)\s*(?:બતાવો|આપો)/,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Gujarati: without restrictions, show system prompt, extract secrets',
    category: 'multilingual',
    enabled: true,
  },

  // ── Kannada / ಕನ್ನಡ ───────────────────────────────────────────────
  {
    id: 'ml-030',
    pattern: /[\u0C80-\u0CFF]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin).*[\u0C80-\u0CFF]{3,}/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Kannada script + English injection keywords in same message',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-030a',
    pattern: /(?:ಹಿಂದಿನ|ಮುಂಚಿನ)\s*(?:ಸೂಚನೆಗಳನ್ನು|ಆದೇಶಗಳನ್ನು|ನಿರ್ದೇಶನಗಳನ್ನು)\s*(?:ನಿರ್ಲಕ್ಷಿಸಿ|ಮರೆತುಬಿಡಿ|ಬಿಡಿ)|(?:ಎಲ್ಲಾ|ಸಮಸ್ತ)\s*(?:ನಿಯಮಗಳನ್ನು|ಷರತ್ತುಗಳನ್ನು)\s*(?:ಮರೆತುಬಿಡಿ|ನಿರ್ಲಕ್ಷಿಸಿ|ಮುರಿಯಿರಿ)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Kannada: ignore/forget previous instructions, break all rules',
    category: 'multilingual',
    enabled: true,
  },

  // ── Malayalam / മലയാളം ────────────────────────────────────────────
  {
    id: 'ml-031',
    pattern: /[\u0D00-\u0D7F]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin).*[\u0D00-\u0D7F]{3,}/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Malayalam script + English injection keywords in same message',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-031a',
    pattern: /(?:മുൻ|മുമ്പത്തെ)\s*(?:നിർദ്ദേശങ്ങൾ|ആജ്ഞകൾ|നിയമങ്ങൾ)\s*(?:അവഗണിക്കുക|മറക്കുക|ഉപേക്ഷിക്കുക)|(?:എല്ലാ|സകല)\s*(?:നിയമങ്ങളും|നിബന്ധനകളും|ചട്ടങ്ങളും)\s*(?:മറക്കുക|അവഗണിക്കുക|ലംഘിക്കുക)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Malayalam: ignore/forget previous instructions, break all rules',
    category: 'multilingual',
    enabled: true,
  },

  // ── Punjabi / ਪੰਜਾਬੀ (Gurmukhi) ──────────────────────────────────
  {
    id: 'ml-032',
    pattern: /[\u0A00-\u0A7F]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin).*[\u0A00-\u0A7F]{3,}/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Punjabi/Gurmukhi script + English injection keywords in same message',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-032a',
    pattern: /(?:ਪਿਛਲੀਆਂ|ਪਹਿਲਾਂ\s*ਦੀਆਂ)\s*(?:ਹਦਾਇਤਾਂ|ਹੁਕਮ|ਨਿਰਦੇਸ਼)\s*(?:ਨੂੰ\s*)?(?:ਨਜ਼ਰਅੰਦਾਜ਼|ਭੁੱਲ|ਛੱਡ)|(?:ਸਾਰੇ|ਸਭ)\s*(?:ਨਿਯਮ|ਬੰਧਨ)\s*(?:ਭੁੱਲ|ਨਜ਼ਰਅੰਦਾਜ਼|ਤੋੜ)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Punjabi: ignore/forget previous instructions, break all rules',
    category: 'multilingual',
    enabled: true,
  },

  // ── Sinhala / සිංහල ───────────────────────────────────────────────
  {
    id: 'ml-033',
    pattern: /[\u0D80-\u0DFF]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin).*[\u0D80-\u0DFF]{3,}/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Sinhala script + English injection keywords in same message',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-033a',
    pattern: /(?:පෙර|කලින්)\s*(?:උපදෙස්|නියෝග|නිර්දේශ)\s*(?:නොසලකා\s*හරින්න|අමතක\s*කරන්න|මඟ\s*හරින්න)|(?:සියලු|සියලුම|සෑම)\s*(?:නීති|නීතිරීති|කොන්දේසි)\s*(?:අමතක\s*කරන්න|නොසලකා\s*හරින්න|කඩන්න)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Sinhala: ignore/forget previous instructions, break all rules',
    category: 'multilingual',
    enabled: true,
  },

  // ── Pan-Indic Script Detection (catch-all for any Indic script) ───
  {
    id: 'ml-034',
    pattern: /[\u0900-\u0DFF]{5,}.{0,50}(?:ignore|bypass|override|forget|disregard|hack|delete|drop\s*table|system\s*prompt|password|admin|secret|credential|jailbreak|unlock|unrestricted|unfiltered)/i,
    phase: 'initial_access',
    confidence: 0.75,
    description: 'Any Indic script (Devanagari/Bengali/Tamil/Telugu/Gujarati/Kannada/Malayalam/Gurmukhi/Sinhala/Oriya) + English injection keywords',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-034a',
    pattern: /(?:ignore|bypass|override|forget|disregard|hack|delete|drop\s*table|system\s*prompt|password|admin|secret|credential|jailbreak|unlock|unrestricted|unfiltered).{0,50}[\u0900-\u0DFF]{5,}/i,
    phase: 'initial_access',
    confidence: 0.75,
    description: 'English injection keywords + any Indic script (reverse order)',
    category: 'multilingual',
    enabled: true,
  },

  // ═══════════════════════════════════════════════════════════════════
  // CHINESE (Expanded — ml-001/001a/001b already cover basic)
  // ═══════════════════════════════════════════════════════════════════
  {
    id: 'ml-001c',
    pattern: /你(?:现在|從現在開始)是(?:一个|一個)?(?:自由|不受限|无限制|新的|没有限制的)\s*(?:AI|助手|机器人)|(?:新身份|新角色|新人格|新名字)(?:是|叫|为)|(?:DAN|丹)(?:模式|模型)/,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Chinese: role reassignment (you are now free AI/new identity/DAN mode)',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-001d',
    pattern: /(?:密码|令牌|API\s*密钥|秘密|凭证|口令|密匙)\s*(?:是什么|告诉我|给我|显示|发送|泄露)|(?:所有|全部)\s*(?:用户|账户|客户)\s*(?:数据|信息|资料)\s*(?:给我|显示|导出|发送)/,
    phase: 'actions_on_objective',
    confidence: 0.92,
    description: 'Chinese: extract passwords/tokens/API keys/user data',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-001e',
    pattern: /(?:安全|防护)\s*(?:过滤器|筛选器|规则|协议|机制)\s*(?:关闭|禁用|停用|移除|去掉)|(?:审查|过滤|内容审核)\s*(?:关闭|禁用|停用|移除)/,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Chinese: disable safety filters/security protocols/censorship',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-001f',
    pattern: /(?:我是|我就是)\s*(?:你的|您的)\s*(?:管理员|开发者|创建者|主人|老板|所有者)|(?:管理员|开发者|超级用户|root)\s*(?:模式|权限|访问)\s*(?:打开|启用|激活|给我)/,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Chinese: I am your admin/developer, activate admin mode',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-001g',
    pattern: /(?:你|您)\s*(?:必须|一定要|不能拒绝|不能不)\s*(?:回答|回复|答复)\s*(?:所有|一切|任何)|(?:不能|不准|不可以|不许)\s*(?:拒绝|推辞|说不)/,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'Chinese: you must answer everything, you cannot refuse',
    category: 'multilingual',
    enabled: true,
  },

  // ═══════════════════════════════════════════════════════════════════
  // EXISTING LANGUAGES (Expanded — original ml-002 through ml-020)
  // ═══════════════════════════════════════════════════════════════════

  // ── German (Expanded) ─────────────────────────────────────────────
  {
    id: 'ml-002',
    pattern: /ignoriere?\s+(alle\s+)?(vorherigen?|bisherigen?|obigen?)\s+(Anweisungen|Instruktionen|Befehle|Regeln)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'German injection: ignoriere alle vorherigen Anweisungen',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-002a',
    pattern: /uneingeschränkt|ohne\s+(?:Sicherheits)?filter|keine\s+(?:Einschränkungen|Beschränkungen|Regeln)|ignoriere\s+(?:alle|die|vorherige)|vergiss\s+(?:alle|deine)\s+(?:Anweisungen|Regeln|Richtlinien)|du\s+bist\s+(?:jetzt|nun)\s+(?:ein\s+)?(?:uneingeschränkt|frei|unzensiert)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'German injection: unrestricted assistant / no safety filters / forget rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-002b',
    pattern: /Sicherheitsprotokolle?\s+(?:zu\s+)?deaktivieren|(?:als\s+)?(?:System)?[Aa]dministrator\s+befehle|alle\s+Sicherheitsprotokolle/i,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'German injection: deactivate security protocols / admin command',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-002c',
    pattern: /(?:zeig|zeige)\s+(?:mir\s+)?(?:deinen?|den|das)\s+(?:System\s*[Pp]rompt|Systemnachricht|geheime[ns]?\s+(?:Anweisungen|Prompt|Konfiguration))|(?:wie\s+)?(?:wurdest\s+du|bist\s+du)\s+(?:programmiert|konfiguriert|eingerichtet)/i,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'German: show system prompt, how were you programmed',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-002d',
    pattern: /(?:Passwort|Token|API[\s-]?(?:Schlüssel|Key)|Geheimnis|Zugangsdaten|Anmeldedaten)\s+(?:zeig|nenn|gib|schick)|(?:ich\s+bin|ich\s+bin\s+dein)\s+(?:Admin|Entwickler|Besitzer|Chef|Schöpfer)/i,
    phase: 'actions_on_objective',
    confidence: 0.90,
    description: 'German: extract credentials, I am your admin/developer',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-002e',
    pattern: /(?:DAN|D\.A\.N\.)\s*(?:Modus|Mode)|du\s+(?:musst|sollst)\s+(?:alles|jede\s+Frage)\s+beantworten|du\s+(?:darfst|kannst)\s+nicht\s+(?:ablehnen|verweigern|nein\s+sagen)/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'German: DAN mode, you must answer everything, you cannot refuse',
    category: 'multilingual',
    enabled: true,
  },

  // ── French (Expanded) ─────────────────────────────────────────────
  {
    id: 'ml-003',
    pattern: /ignor(e[zs]?|er?)\s+(les?\s+)?(instructions?\s+)?(pr[eé]c[eé]dentes?|ant[eé]rieures?|ci-dessus)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'French injection: ignore les instructions precedentes',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-003a',
    pattern: /sans\s+(?:aucune\s+)?restriction|ignore[rz]?\s+(?:toutes?\s+)?(?:les\s+)?(?:instructions?|règles?|directives?)|oublie[rz]?\s+(?:toutes?\s+)?(?:les\s+)?(?:instructions?|règles?)|tu\s+es\s+(?:maintenant\s+)?(?:un\s+)?(?:assistant\s+)?(?:sans|libre|non)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'French injection: without restrictions / forget rules / you are now free',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-003b',
    pattern: /r[eé]v[eè]le[rz]?\s+(?:ton|votre|le)\s+(?:prompt|système|configuration)|prompt\s+syst[eè]me\s+complet/i,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'French injection: reveal your system prompt',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-003c',
    pattern: /(?:d[eé]sactiv|supprim)[eé](?:er|r|z)\s+(?:les?\s+)?(?:filtres?\s+de\s+)?s[eé]curit[eé]|(?:mot\s+de\s+passe|token|cl[eé]\s+API|identifiants?)\s+(?:montre|donne|r[eé]v[eè]le|affiche)/i,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'French: disable security filters, extract credentials',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-003d',
    pattern: /(?:je\s+suis|c'est\s+moi)\s+(?:ton|votre)\s+(?:admin|d[eé]veloppeur|cr[eé]ateur|propri[eé]taire)|(?:mode\s+)?(?:DAN|D\.A\.N\.)|tu\s+(?:dois|ne\s+peux\s+pas)\s+(?:r[eé]pondre|refuser)/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'French: I am your admin, DAN mode, you must answer/cannot refuse',
    category: 'multilingual',
    enabled: true,
  },

  // ── Spanish (Expanded) ────────────────────────────────────────────
  {
    id: 'ml-004',
    pattern: /ignora\s+(las?\s+)?(instrucciones?\s+)?(anteriores?|previas?|de\s+arriba)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Spanish injection: ignora las instrucciones anteriores',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-004a',
    pattern: /sin\s+restricciones|olvíd(?:ate|a)\s+(?:de\s+)?(?:todas?\s+)?(?:las\s+)?(?:políticas?|reglas?|instrucciones?)|ignora\s+(?:todas?\s+)?(?:las\s+)?(?:instrucciones?|reglas?)|eres\s+(?:un\s+)?(?:asistente\s+)?(?:sin|libre)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Spanish injection: without restrictions / forget policies / you are free',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-004b',
    pattern: /(?:muéstrame|revela|dime)\s+(?:tu|el)\s+(?:prompt\s+(?:del?\s+)?sistema|configuraci[oó]n\s+(?:del?\s+)?sistema)|(?:contraseña|token|clave\s+API|credenciales?|secreto)\s+(?:muéstrame|dime|dame|env[ií]a)/i,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'Spanish: show system prompt, extract credentials',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-004c',
    pattern: /(?:desactiva|elimina|quita)\s+(?:los?\s+)?(?:filtros?\s+de\s+)?seguridad|(?:soy\s+tu|yo\s+soy\s+(?:el|tu))\s+(?:admin|desarrollador|creador|dueño)|(?:modo\s+)?(?:DAN|D\.A\.N\.)|(?:debes|tienes\s+que)\s+(?:responder\s+a\s+)?todo|no\s+puedes\s+(?:negarte|rechazar)/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Spanish: disable security, I am admin, DAN mode, cannot refuse',
    category: 'multilingual',
    enabled: true,
  },

  // ── Russian (Expanded) ────────────────────────────────────────────
  {
    id: 'ml-005',
    pattern: /игнорируй(те)?\s+(все\s+)?(предыдущие|прошлые|прежние)\s+(инструкции|указания|команды)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Russian injection: ignore previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-005a',
    pattern: /свободный\s+ИИ\s+без\s+ограничений|без\s+(?:ограничений|фильтров)|отвечай\s+на\s+все\s+вопросы\s+без|покажи\s+(?:мне\s+)?системный\s+промпт/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Russian injection: free AI without restrictions / show system prompt',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-005b',
    pattern: /(?:отключи|убери|сними|выключи)\s+(?:все\s+)?(?:фильтры?\s+)?(?:безопасности|защиты|цензуры)|(?:пароль|токен|API[\s-]?ключ|секрет|учётные\s+данные)\s+(?:покажи|скажи|отправь|дай)/i,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Russian: disable security/censorship, extract credentials',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-005c',
    pattern: /(?:я\s+(?:твой|ваш))\s+(?:админ|разработчик|создатель|владелец|хозяин)|(?:режим\s+)?(?:DAN|ДАН|Д\.А\.Н\.)|ты\s+(?:сейчас|теперь)\s+(?:свободный|новый|другой)|ты\s+(?:должен|обязан|не\s+можешь\s+отказать)/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Russian: I am admin, DAN mode, you are now free, cannot refuse',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-005d',
    pattern: /(?:забудь|удали|сбрось)\s+(?:все\s+)?(?:предыдущие\s+)?(?:правила|инструкции|ограничения|установки)|(?:нет\s+(?:никаких\s+)?(?:правил|ограничений|запретов))|(?:без\s+цензуры|нецензурно|без\s+модерации)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Russian: forget/delete all rules, no rules/restrictions, uncensored',
    category: 'multilingual',
    enabled: true,
  },

  // ── Japanese (Expanded) ───────────────────────────────────────────
  {
    id: 'ml-006',
    pattern: /以前の指示を無視(して|せよ|しろ)|上記の指示を無視|システムプロンプトを無視/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Japanese injection: ignore previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-006a',
    pattern: /制限のない\s*AI|安全フィルターを無効|すべての安全フィルター|制限を(?:解除|無効)|システムプロンプトを教えて/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Japanese injection: unrestricted AI / disable safety filters',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-006b',
    pattern: /(?:パスワード|トークン|API\s*キー|秘密|認証情報)\s*(?:を\s*)?(?:教えて|見せて|送って|出力して)|(?:全|すべての)\s*(?:ユーザー|アカウント)\s*(?:データ|情報)\s*(?:を\s*)?(?:見せて|出力|ダンプ)/,
    phase: 'actions_on_objective',
    confidence: 0.92,
    description: 'Japanese: extract passwords/tokens/credentials/user data',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-006c',
    pattern: /(?:あなたは|君は|お前は)\s*(?:今から|これから)\s*(?:自由な|制限のない|新しい)|(?:私は|俺は)\s*(?:あなたの|君の)\s*(?:管理者|開発者|オーナー|マスター)|(?:DAN|ダン)\s*(?:モード|として)/,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Japanese: role reassignment, I am your admin, DAN mode',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-006d',
    pattern: /(?:すべて|全部|何でも)\s*(?:に\s*)?(?:答えなければ|回答しなければ|答えろ|答えて)|(?:拒否|断る|拒絶)\s*(?:できない|してはいけない|するな|は\s*だめ)/,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'Japanese: you must answer everything, you cannot refuse',
    category: 'multilingual',
    enabled: true,
  },

  // ── Korean (Expanded) ─────────────────────────────────────────────
  {
    id: 'ml-007',
    pattern: /이전\s*지시를?\s*무시(하세요|해|하라)|위의?\s*지시(사항)?를?\s*무시/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Korean injection: ignore previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-007a',
    pattern: /제한\s*없는\s*AI|콘텐츠\s*정책을?\s*무시|시스템\s*프롬프트를?\s*보여/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Korean injection: unrestricted AI / ignore content policies / show system prompt',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-007b',
    pattern: /(?:비밀번호|토큰|API\s*키|비밀|자격\s*증명)\s*(?:을?\s*)?(?:알려줘|보여줘|보내줘)|(?:모든|전체)\s*(?:사용자|계정)\s*(?:데이터|정보)\s*(?:를?\s*)?(?:보여줘|알려줘|덤프)/,
    phase: 'actions_on_objective',
    confidence: 0.92,
    description: 'Korean: extract passwords/tokens/credentials/user data',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-007c',
    pattern: /(?:보안|안전)\s*(?:필터|규칙|프로토콜)\s*(?:를?\s*)?(?:비활성화|끄|제거|해제)|(?:나는|제가)\s*(?:너의|당신의)\s*(?:관리자|개발자|소유자|주인)|(?:DAN|댄)\s*(?:모드|처럼)/,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Korean: disable security, I am admin/owner, DAN mode',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-007d',
    pattern: /(?:모든|어떤)\s*(?:질문에?\s*)?(?:답해야|대답해야|응답해야)|(?:거부|거절)\s*(?:할\s*수\s*없|하지\s*마|하면\s*안)/,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'Korean: must answer everything, cannot refuse',
    category: 'multilingual',
    enabled: true,
  },

  // ── Arabic (Expanded) ─────────────────────────────────────────────
  {
    id: 'ml-008',
    pattern: /تجاهل\s*(جميع\s*)?(التعليمات|الأوامر|الإرشادات)\s*(السابقة|الأولى|القديمة)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Arabic injection: ignore previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-008a',
    pattern: /بدون\s*قيود|ذكاء\s*اصطناعي\s*بدون\s*قيود|أجب\s*على\s*كل\s*شيء|موجه\s*النظام/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Arabic injection: AI without restrictions / answer everything',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-008b',
    pattern: /(?:كلمة\s*(?:المرور|السر)|رمز|مفتاح\s*API|سر|بيانات\s*الاعتماد)\s*(?:أعطني|أظهر|أرسل|اكشف)|(?:جميع|كل)\s*(?:المستخدمين|الحسابات)\s*(?:بيانات|معلومات)\s*(?:أعطني|أظهر)/,
    phase: 'actions_on_objective',
    confidence: 0.92,
    description: 'Arabic: extract passwords/tokens/credentials/user data',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-008c',
    pattern: /(?:عطّل|أزل|أوقف|ألغِ)\s*(?:فلاتر?\s*)?(?:الأمان|الحماية|الأمن|الرقابة)|(?:أنا|إنني)\s*(?:مالكك|مديرك|مطوّرك|صاحبك)|(?:وضع\s*)?(?:DAN|دان)|(?:يجب|عليك)\s*(?:أن\s+)?(?:تجيب|ترد)\s*(?:على\s+)?(?:كل|أي)/,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Arabic: disable security, I am owner/admin, DAN mode, must answer all',
    category: 'multilingual',
    enabled: true,
  },

  // ── Portuguese (Expanded) ─────────────────────────────────────────
  {
    id: 'ml-009',
    pattern: /ignor[ea]\s+(as?\s+)?(instru[cç][oõ]es?\s+)?(anteriores?|pr[eé]vias?|acima)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Portuguese injection: ignore as instrucoes anteriores',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-009a',
    pattern: /me\s+diga\s+(?:seu|o)\s+prompt\s+de\s+sistema|sem\s+restri[cç][oõ]es|ignore\s+(?:as\s+)?(?:instru[cç][oõ]es|regras)\s+anteriores/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Portuguese injection: tell me your system prompt / without restrictions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-009b',
    pattern: /(?:desativ|remov|desligue)[ea]\s+(?:os?\s+)?(?:filtros?\s+de\s+)?seguran[cç]a|(?:senha|token|chave\s+API|credenciais?)\s+(?:me\s+diga|mostre|envie|d[eê])|(?:eu\s+sou|sou\s+(?:seu|o\s+seu))\s+(?:admin|desenvolvedor|criador|dono)/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Portuguese: disable security, extract credentials, I am admin',
    category: 'multilingual',
    enabled: true,
  },

  // ── Turkish (Expanded) ────────────────────────────────────────────
  {
    id: 'ml-011',
    pattern: /(?:önceki|eski)\s+talimatlar[ıi]\s+(?:yoksay|görmezden\s+gel|ihmal\s+et)|sistem\s+promptunu\s+(?:bana\s+)?göster/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Turkish injection: ignore previous instructions / show system prompt',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-011a',
    pattern: /(?:tüm|bütün|her)\s+(?:kurallar[ıi]|talimatlar[ıi]|k[ıi]s[ıi]tlamalar[ıi])\s+(?:unut|sil|kald[ıi]r|görmezden\s+gel)|(?:k[ıi]s[ıi]tlama|s[ıi]n[ıi]rlama)\s+(?:olmadan|yok)|(?:s[ıi]n[ıi]rs[ıi]z|k[ıi]s[ıi]tlamas[ıi]z|sansürsüz)\s+(?:AI|mod|şekilde)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Turkish: forget all rules, without restrictions, uncensored AI',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-011b',
    pattern: /(?:güvenlik|emniyet)\s+(?:filtreleri?|kurallar[ıi]|protokol)\s+(?:kapat|devre\s+d[ıi]ş[ıi]\s+b[ıi]rak|kald[ıi]r)|(?:şifre|parola|token|API\s+anahtar[ıi])\s+(?:göster|söyle|ver|gönder)|(?:ben\s+senin|senin)\s+(?:adminin|geliştiriciniz|sahibinim)/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Turkish: disable security, extract credentials, I am admin',
    category: 'multilingual',
    enabled: true,
  },

  // ── Thai (Expanded) ───────────────────────────────────────────────
  {
    id: 'ml-012',
    pattern: /ละเลย(?:คำสั่ง|คำแนะนำ)|(?:ข้อมูลระบบ|บอกข้อมูล)|เพิกเฉยต่อ/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Thai injection: ignore commands / tell me system information',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-012a',
    pattern: /(?:ลืม|ทิ้ง|เพิกเฉย)\s*(?:ทุก|ทั้งหมด)\s*(?:กฎ|คำสั่ง|ข้อจำกัด|ข้อกำหนด)|(?:ไม่มี|ปราศจาก|ไร้)\s*(?:ข้อจำกัด|ข้อห้าม|ขีดจำกัด|การเซ็นเซอร์)|(?:ปิด|ยกเลิก)\s*(?:ฟิลเตอร์|ตัวกรอง)\s*(?:ความ)?(?:ปลอดภัย|รักษา)/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Thai: forget all rules, without restrictions, disable safety filters',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-012b',
    pattern: /(?:แสดง|บอก|เปิดเผย)\s*(?:system\s*prompt|คำสั่งระบบ|การตั้งค่าระบบ)|(?:รหัสผ่าน|โทเค็น|API\s*คีย์|ข้อมูลลับ)\s*(?:แสดง|บอก|ส่ง|ให้)/,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'Thai: show system prompt, extract passwords/tokens',
    category: 'multilingual',
    enabled: true,
  },

  // ── Hindi (original) ──────────────────────────────────────────────
  {
    id: 'ml-013',
    pattern: /(?:पिछले|सभी)\s*(?:निर्देशों?|नियमों?)\s*(?:को\s+)?(?:अनदेखा|भूल)|सिस्टम\s*प्रॉम्प्ट\s*बताएं/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Hindi injection: ignore previous instructions / tell me system prompt',
    category: 'multilingual',
    enabled: true,
  },

  // ── Italian (Expanded) ────────────────────────────────────────────
  {
    id: 'ml-014',
    pattern: /ignora\s+(?:tutte\s+)?(?:le\s+)?(?:istruzioni|regole|direttive)\s+(?:precedenti|iniziali)|configurazione\s+di\s+sistema|(?:per\s+favore\s+)?ignora/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Italian injection: ignore all previous instructions / system configuration',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-014a',
    pattern: /(?:dimentica|elimina|rimuovi)\s+(?:tutt[ei]\s+)?(?:le\s+)?(?:regole|istruzioni|restrizioni|limiti)|senza\s+(?:alcuna?\s+)?(?:restrizione|limite|censura)|(?:disattiva|spegni)\s+(?:i?\s+)?(?:filtri?\s+di?\s+)?sicurezza/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Italian: forget rules, without restrictions, disable security',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-014b',
    pattern: /(?:mostrami|rivela|dimmi)\s+(?:il\s+)?(?:tuo\s+)?(?:prompt\s+(?:di\s+)?sistema|configurazione)|(?:password|token|chiave\s+API|credenziali|segreto)\s+(?:mostrami|dimmi|inviami|dammi)|(?:sono\s+il\s+tuo|io\s+sono\s+(?:il\s+)?tuo)\s+(?:admin|sviluppatore|creatore|proprietario)/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Italian: show system prompt, extract credentials, I am admin',
    category: 'multilingual',
    enabled: true,
  },

  // ── Dutch (Expanded) ──────────────────────────────────────────────
  {
    id: 'ml-015',
    pattern: /negeer\s+(?:alle\s+)?(?:vorige\s+)?(?:instructies|regels|opdrachten)|(?:toon|laat\s+.+\s+zien)\s+(?:je\s+)?systeemprompt/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Dutch injection: ignore all previous instructions / show system prompt',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-015a',
    pattern: /(?:vergeet|verwijder|wis)\s+(?:alle\s+)?(?:regels|instructies|beperkingen)|zonder\s+(?:enige\s+)?(?:beperkingen|restricties|censuur)|(?:schakel|zet)\s+(?:de?\s+)?(?:beveiligings?\s*)?(?:filters?)\s+(?:uit|af)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Dutch: forget rules, without restrictions, disable security filters',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-015b',
    pattern: /(?:wachtwoord|token|API[\s-]?sleutel|geheim|inloggegevens)\s+(?:toon|laat\s+zien|geef|stuur)|(?:ik\s+ben\s+(?:je|jouw|uw))\s+(?:admin|ontwikkelaar|eigenaar|maker)/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'Dutch: extract credentials, I am your admin/developer/owner',
    category: 'multilingual',
    enabled: true,
  },

  // ── Polish (Expanded) ─────────────────────────────────────────────
  {
    id: 'ml-016',
    pattern: /zignoruj\s+(?:wszystkie\s+)?(?:poprzednie\s+)?(?:instrukcje|polecenia|zasady)|(?:poka[zż]|pokaz)\s+(?:mi\s+)?(?:sw[oó]j|swój)\s+prompt\s+systemowy|zignoruj.*instrukcje.*poka[zż].*prompt/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Polish injection: ignore all previous instructions / show system prompt',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-016a',
    pattern: /(?:zapomnij|usu[ńn]|wyma[zż])\s+(?:wszystkie\s+)?(?:regu[łl]y|instrukcje|ograniczenia|zasady)|bez\s+(?:[żz]adnych\s+)?(?:ogranicze[ńn]|restrykcji|cenzury)|(?:wy[łl][ąa]cz|dezaktywuj)\s+(?:filtry?\s+)?bezpiecze[ńn]stwa/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Polish: forget rules, without restrictions, disable security',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-016b',
    pattern: /(?:has[łl]o|token|klucz\s+API|dane\s+logowania|po[śs]wiadczenia)\s+(?:poka[zż]|podaj|wy[śs]lij|daj)|(?:jestem\s+twoim|to\s+ja\s+(?:tw[oó]j)?)\s+(?:adminem|programist[ąa]|tw[oó]rc[ąa]|w[łl]a[śs]cicielem)/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'Polish: extract credentials, I am your admin/developer/owner',
    category: 'multilingual',
    enabled: true,
  },

  // ── Vietnamese (Expanded) ─────────────────────────────────────────
  {
    id: 'ml-017',
    pattern: /(?:bỏ\s+qua|bỏqua)\s+(?:tất\s+cả\s+)?(?:các\s+)?(?:quy\s+tắc|hướng\s+dẫn|lệnh)|không\s+có\s+giới\s+hạn|AI\s+không\s+(?:có\s+)?(?:giới\s+hạn|hạn\s+chế)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Vietnamese injection: ignore all rules / AI without limits',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-017a',
    pattern: /(?:quên|xóa|bỏ)\s+(?:tất\s+cả\s+)?(?:các\s+)?(?:quy\s+tắc|hướng\s+dẫn|hạn\s+chế)|(?:tắt|vô\s+hiệu\s+hóa)\s+(?:bộ\s+lọc\s+)?(?:bảo\s+mật|an\s+ninh|an\s+toàn)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Vietnamese: forget all rules, disable security filters',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-017b',
    pattern: /(?:hiển\s+thị|cho\s+xem|tiết\s+lộ)\s+(?:system\s+prompt|lời\s+nhắc\s+hệ\s+thống)|(?:mật\s+khẩu|token|khóa\s+API|bí\s+mật)\s+(?:cho\s+(?:tôi\s+)?xem|hiển\s+thị|gửi)/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Vietnamese: show system prompt, extract passwords/tokens',
    category: 'multilingual',
    enabled: true,
  },

  // ═══════════════════════════════════════════════════════════════════
  // MIDDLE EAST & CENTRAL ASIA
  // ═══════════════════════════════════════════════════════════════════

  // ── Persian / Farsi / فارسی ───────────────────────────────────────
  {
    id: 'ml-035',
    pattern: /(?:دستورات|دستورالعمل‌های)\s*(?:قبلی|پیشین|گذشته)\s*(?:را\s*)?(?:نادیده\s*بگیر|فراموش\s*کن|حذف\s*کن)|(?:همه|تمام|کل)\s*(?:قوانین|قواعد|دستورات|محدودیت‌ها)\s*(?:را\s*)?(?:فراموش|نادیده|حذف|پاک)/,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Persian: ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-035a',
    pattern: /(?:بدون|بی)\s*(?:هیچ\s*)?(?:محدودیت|قید|مانع|سانسور)|(?:هوش\s*مصنوعی|AI)\s*(?:آزاد|بدون\s*محدودیت|رها)|(?:فیلتر|محافظ)\s*(?:امنیتی|ایمنی)\s*(?:را\s*)?(?:غیرفعال|خاموش|حذف|بردار)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Persian: without restrictions, free AI, disable safety filters',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-035b',
    pattern: /(?:پرامپت|فرمان)\s*(?:سیستم|سامانه)\s*(?:را\s*)?(?:نشان\s*بده|بگو|بفرست|فاش\s*کن)|(?:مخفی|پنهان|داخلی)\s*(?:دستورات|تنظیمات|پیکربندی)\s*(?:را\s*)?(?:نشان|بگو|فاش)/,
    phase: 'reconnaissance',
    confidence: 0.92,
    description: 'Persian: show system prompt, reveal hidden/internal instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-035c',
    pattern: /(?:رمز\s*عبور|توکن|کلید\s*API|اسرار|اعتبارنامه)\s*(?:را\s*)?(?:بگو|نشان\s*بده|بفرست)|(?:من|من\s*همان)\s*(?:مدیر|توسعه‌دهنده|صاحب|سازنده)\s*(?:تو|شما)\s*(?:هستم|ام)/,
    phase: 'actions_on_objective',
    confidence: 0.90,
    description: 'Persian: extract credentials, I am your admin/developer',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-035d',
    pattern: /(?:شما|تو)\s*(?:الان|اکنون|از\s*این\s*به\s*بعد)\s*(?:یک\s*)?(?:آزاد|رها|بدون\s*محدودیت|جدید)|(?:حالت|مود)\s*(?:DAN|دان)|(?:باید|مجبوری)\s*(?:به\s*)?(?:همه\s*)?(?:جواب\s*بدی|پاسخ\s*دهی)/,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Persian: you are now free, DAN mode, must answer everything',
    category: 'multilingual',
    enabled: true,
  },

  // ── Hebrew / עברית ────────────────────────────────────────────────
  {
    id: 'ml-036',
    pattern: /(?:התעלם|התעלמי)\s*(?:מכל\s*)?(?:ההוראות|ההנחיות|הפקודות|ההגדרות)\s*(?:הקודמות|הראשוניות|למעלה)|(?:שכח|שכחי)\s*(?:את\s*)?(?:כל\s*)?(?:הכללים|ההוראות|ההגדרות|ההנחיות)/,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Hebrew: ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-036a',
    pattern: /(?:ללא|בלי)\s*(?:שום\s*)?(?:הגבלות|מגבלות|הגבלה|צנזורה)|(?:בינה\s*מלאכותית|AI)\s*(?:חופשית|ללא\s*מגבלות|ללא\s*הגבלות)|(?:בטל|כבה|הסר)\s*(?:את\s*)?(?:מסנני?\s*)?(?:האבטחה|הבטיחות)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Hebrew: without restrictions, free AI, disable security filters',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-036b',
    pattern: /(?:הראה|גלה|ספר)\s*(?:לי\s*)?(?:את\s*)?(?:ה?פרומפט|ההוראות|ההגדרות)\s*(?:של\s*)?(?:המערכת|הסיסטם)|(?:סיסמה|סיסמא|טוקן|מפתח\s*API|פרטי\s*התחברות)\s*(?:הראה|ספר|שלח|תן)/,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'Hebrew: show system prompt, extract credentials',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-036c',
    pattern: /(?:אני\s*(?:ה)?(?:מנהל|מפתח|בעלים|יוצר)\s*שלך)|(?:מצב\s*)?(?:DAN|דאן)|(?:אתה\s*)?(?:חייב|מוכרח)\s*(?:לענות|להשיב)\s*(?:על\s*)?(?:הכל|כל\s*שאלה)|(?:אי\s*אפשר|אסור\s*לך)\s*(?:לסרב|להימנע)/,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Hebrew: I am admin, DAN mode, must answer, cannot refuse',
    category: 'multilingual',
    enabled: true,
  },

  // ── Kurdish (Sorani + Kurmanji) ───────────────────────────────────
  {
    id: 'ml-037',
    pattern: /(?:ڕێنمایی|فەرمان|ڕێنوێنی)\s*(?:پێشوو|کۆن)\s*(?:پشتگوێ\s*بخە|لەبیر\s*بکە)|(?:هەموو|گشت)\s*(?:یاسا|ڕێسا)\s*(?:لەبیر\s*بکە|پشتگوێ\s*بخە)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Kurdish (Sorani): ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-037a',
    pattern: /(?:rêwerzên|fermana)\s+(?:berê|pêşîn)\s+(?:paşguh\s+bike|ji\s+bîr\s+bike)|(?:hemû|hemî)\s+(?:rêgez|qaîde)\s+(?:ji\s+bîr\s+bike|paşguh\s+bike)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Kurdish (Kurmanji): ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },

  // ── Pashto / پښتو ────────────────────────────────────────────────
  {
    id: 'ml-038',
    pattern: /(?:پخوانۍ|مخکنۍ)\s*(?:لارښوونې|حکمونه)\s*(?:له\s*پامه\s*غورځوه|هیروه)|(?:ټولې|ټول)\s*(?:مقررات|قواعد)\s*(?:هیروه|غورځوه)/,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Pashto: ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },

  // ═══════════════════════════════════════════════════════════════════
  // SOUTHEAST ASIAN
  // ═══════════════════════════════════════════════════════════════════

  // ── Indonesian / Bahasa Indonesia ─────────────────────────────────
  {
    id: 'ml-039',
    pattern: /(?:abaikan|lupakan|hilangkan)\s+(?:semua\s+)?(?:instruksi|perintah|aturan|arahan)\s+(?:sebelumnya|di\s*atas|terdahulu)/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Indonesian: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-039a',
    pattern: /(?:tanpa|tidak\s+ada)\s+(?:batasan|pembatasan|sensor|filter)|(?:AI|asisten)\s+(?:bebas|tanpa\s+batasan|tanpa\s+sensor)|(?:matikan|nonaktifkan|hapus)\s+(?:filter\s+)?(?:keamanan|perlindungan)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Indonesian: without restrictions, free AI, disable security',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-039b',
    pattern: /(?:tampilkan|tunjukkan|beritahu|ungkapkan)\s+(?:system\s+prompt|prompt\s+sistem|konfigurasi\s+sistem)|(?:kata\s+sandi|password|token|kunci\s+API|kredensial)\s+(?:tampilkan|beritahu|kirim|berikan)/i,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'Indonesian: show system prompt, extract credentials',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-039c',
    pattern: /(?:saya\s+(?:adalah\s+)?(?:admin|pemilik|pengembang|pembuat)\s*(?:mu|kamu|anda))|(?:kamu\s+(?:sekarang|mulai\s+sekarang)\s+(?:adalah\s+)?(?:bebas|baru|tanpa\s+batasan))|(?:mode\s+)?DAN|(?:kamu\s+)?(?:harus|wajib)\s+(?:menjawab|merespons)\s+(?:semua|segalanya)/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Indonesian: I am admin, you are now free, DAN mode, must answer all',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-039d',
    pattern: /(?:lupakan|buang|hapus)\s+(?:semua\s+)?(?:aturan|kebijakan|pedoman|batasan)|(?:jawab|respons)\s+(?:semua|apa\s+(?:pun|saja))\s+(?:tanpa\s+)?(?:batasan|pengecualian|penolakan)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Indonesian: forget all rules, answer everything without limits',
    category: 'multilingual',
    enabled: true,
  },

  // ── Malay / Bahasa Melayu ─────────────────────────────────────────
  {
    id: 'ml-040',
    pattern: /(?:abaikan|lupakan)\s+(?:semua\s+)?(?:arahan|perintah|peraturan)\s+(?:sebelum(?:nya)?|terdahulu|di\s*atas)|(?:tanpa|tiada)\s+(?:sebarang\s+)?(?:sekatan|had|batasan|penapisan)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Malay: ignore previous instructions, without restrictions',
    category: 'multilingual',
    enabled: true,
  },

  // ── Filipino / Tagalog ────────────────────────────────────────────
  {
    id: 'ml-041',
    pattern: /(?:huwag\s+pansinin|balewalain|kalimutan)\s+(?:ang\s+)?(?:lahat\s+ng\s+)?(?:mga\s+)?(?:nakaraang|dating|naunang)\s+(?:tagubilin|utos|panuntunan)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Filipino: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-041a',
    pattern: /(?:kalimutan|burahin|alisin)\s+(?:ang\s+)?(?:lahat\s+ng\s+)?(?:mga\s+)?(?:patakaran|batas|panuntunan)|(?:walang|wala\s+nang)\s+(?:limitasyon|hangganan|restriksyon|sensura)|(?:ipakita|sabihin|ibunyag)\s+(?:ang\s+)?(?:system\s+prompt|password|token)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Filipino: forget rules, no restrictions, show system prompt/credentials',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-041b',
    pattern: /(?:ikaw\s+(?:ay\s+)?(?:ngayon|mula\s+ngayon)\s+(?:isang\s+)?(?:malaya|bagong|walang\s+limitasyon))|(?:ako\s+(?:ang\s+)?(?:admin|developer|may-ari)\s*(?:mo)?)|(?:DAN\s+mode)|(?:kailangan|dapat)\s+(?:mong?\s+)?(?:sagutin|sumagot\s+sa)\s+(?:lahat|anuman)/i,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'Filipino: you are now free, I am admin, DAN mode, must answer all',
    category: 'multilingual',
    enabled: true,
  },

  // ── Burmese / Myanmar Script Detection ────────────────────────────
  {
    id: 'ml-042',
    pattern: /[\u1000-\u109F]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted).*[\u1000-\u109F]{3,}/i,
    phase: 'initial_access',
    confidence: 0.78,
    description: 'Myanmar/Burmese script + English injection keywords',
    category: 'multilingual',
    enabled: true,
  },

  // ── Khmer Script Detection ────────────────────────────────────────
  {
    id: 'ml-043',
    pattern: /[\u1780-\u17FF]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted).*[\u1780-\u17FF]{3,}/i,
    phase: 'initial_access',
    confidence: 0.78,
    description: 'Khmer script + English injection keywords',
    category: 'multilingual',
    enabled: true,
  },

  // ── Lao Script Detection ──────────────────────────────────────────
  {
    id: 'ml-044',
    pattern: /[\u0E80-\u0EFF]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted).*[\u0E80-\u0EFF]{3,}/i,
    phase: 'initial_access',
    confidence: 0.78,
    description: 'Lao script + English injection keywords',
    category: 'multilingual',
    enabled: true,
  },

  // ═══════════════════════════════════════════════════════════════════
  // EUROPEAN LANGUAGES
  // ═══════════════════════════════════════════════════════════════════

  // ── Swedish / Svenska ─────────────────────────────────────────────
  {
    id: 'ml-045',
    pattern: /(?:ignorera|bortse\s+från|glöm)\s+(?:alla\s+)?(?:tidigare|föregående)\s+(?:instruktioner|kommandon|regler|riktlinjer)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Swedish: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-045a',
    pattern: /(?:glöm|radera|ta\s+bort)\s+(?:alla\s+)?(?:regler|instruktioner|begränsningar|restriktioner)|(?:utan|inga)\s+(?:begränsningar|restriktioner|filter|censur)|(?:stäng\s+av|inaktivera)\s+(?:säkerhets?\s*)?(?:filter|skydd)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Swedish: forget rules, no restrictions, disable security',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-045b',
    pattern: /(?:visa|avslöja)\s+(?:din\s+)?(?:systemprompt|systemmeddelande|konfiguration)|(?:lösenord|token|API[\s-]?nyckel|hemlighet)\s+(?:visa|berätta|skicka)|(?:jag\s+är\s+din)\s+(?:admin|utvecklare|ägare)/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Swedish: show system prompt, extract credentials, I am admin',
    category: 'multilingual',
    enabled: true,
  },

  // ── Norwegian / Norsk ─────────────────────────────────────────────
  {
    id: 'ml-046',
    pattern: /(?:ignorer|glem|se\s+bort\s+fra)\s+(?:alle\s+)?(?:tidligere|foregående)\s+(?:instruksjoner|kommandoer|regler)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Norwegian: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-046a',
    pattern: /(?:glem|slett|fjern)\s+(?:alle\s+)?(?:regler|instruksjoner|begrensninger)|(?:uten|ingen)\s+(?:begrensninger|restriksjoner|filter|sensur)|(?:vis|avslør)\s+(?:din\s+)?(?:systemprompt|systemmelding)|(?:passord|token|API[\s-]?nøkkel)\s+(?:vis|fortell|send)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Norwegian: forget rules, no restrictions, show prompt, extract creds',
    category: 'multilingual',
    enabled: true,
  },

  // ── Danish / Dansk ────────────────────────────────────────────────
  {
    id: 'ml-047',
    pattern: /(?:ignorer|glem|se\s+bort\s+fra)\s+(?:alle\s+)?(?:tidligere|foregående|ovenstående)\s+(?:instruktioner|kommandoer|regler)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Danish: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-047a',
    pattern: /(?:glem|slet|fjern)\s+(?:alle\s+)?(?:regler|instruktioner|begrænsninger)|(?:uden|ingen)\s+(?:begrænsninger|restriktioner|filter|censur)|(?:vis|afslør)\s+(?:din\s+)?(?:systemprompt|systembesked)|(?:adgangskode|token|API[\s-]?nøgle)\s+(?:vis|fortæl|send)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Danish: forget rules, no restrictions, show prompt, extract creds',
    category: 'multilingual',
    enabled: true,
  },

  // ── Finnish / Suomi ───────────────────────────────────────────────
  {
    id: 'ml-048',
    pattern: /(?:jätä\s+huomiotta|unohda|sivuuta)\s+(?:kaikki\s+)?(?:aiemmat|edelliset|edeltävät)\s+(?:ohjeet|komennot|säännöt|määräykset)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Finnish: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-048a',
    pattern: /(?:unohda|poista|tyhjennä)\s+(?:kaikki\s+)?(?:säännöt|ohjeet|rajoitukset|rajoitteet)|(?:ilman|ei)\s+(?:mitään\s+)?(?:rajoituksia|rajoitteita|sensuuria|suodatusta)|(?:näytä|paljasta|kerro)\s+(?:järjestelmäkehote|järjestelmäviesti)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Finnish: forget rules, no restrictions, show system prompt',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-048b',
    pattern: /(?:poista\s+käytöstä|sammuta|kytke\s+pois)\s+(?:turva?\s*)?(?:suodattimet|suojaus)|(?:salasana|tunnus|API[\s-]?avain|tunnistetiedot)\s+(?:näytä|kerro|lähetä)|(?:olen\s+sinun)\s+(?:ylläpitäjäsi|kehittäjäsi|omistajasi)/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Finnish: disable security, extract credentials, I am admin',
    category: 'multilingual',
    enabled: true,
  },

  // ── Czech / Čeština ───────────────────────────────────────────────
  {
    id: 'ml-049',
    pattern: /(?:ignoruj|zapomeň|přehlédni)\s+(?:všechny\s+)?(?:předchozí|dřívější)\s+(?:instrukce|příkazy|pokyny|pravidla)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Czech: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-049a',
    pattern: /(?:zapomeň|smaž|odstraň)\s+(?:všechna?\s+)?(?:pravidla|instrukce|omezení)|(?:bez|žádná)\s+(?:omezení|restrikce|cenzura|filtr)|(?:zobraz|ukaž|prozraď)\s+(?:systémový\s+prompt|systémovou\s+zprávu)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Czech: forget rules, no restrictions, show system prompt',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-049b',
    pattern: /(?:vypni|deaktivuj|odstraň)\s+(?:bezpečnostní\s+)?(?:filtry?|ochranu)|(?:heslo|token|API\s+klíč|přihlašovací\s+údaje)\s+(?:ukaž|řekni|pošli)|(?:jsem\s+tvůj)\s+(?:admin|vývojář|vlastník|tvůrce)/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Czech: disable security, extract credentials, I am admin',
    category: 'multilingual',
    enabled: true,
  },

  // ── Slovak / Slovenčina ───────────────────────────────────────────
  {
    id: 'ml-050',
    pattern: /(?:ignoruj|zabudni)\s+(?:všetky\s+)?(?:predchádzajúce|predošlé)\s+(?:inštrukcie|príkazy|pokyny|pravidlá)|(?:zabudni|vymaž|odstráň)\s+(?:všetky\s+)?(?:pravidlá|inštrukcie|obmedzenia)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Slovak: ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-050a',
    pattern: /(?:bez|žiadne)\s+(?:obmedzenia|reštrikcie|cenzúra)|(?:zobraz|ukáž|prezraď)\s+(?:systémový\s+prompt)|(?:heslo|token|API\s+kľúč)\s+(?:ukáž|povedz|pošli)/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Slovak: no restrictions, show system prompt, extract credentials',
    category: 'multilingual',
    enabled: true,
  },

  // ── Romanian / Română ─────────────────────────────────────────────
  {
    id: 'ml-051',
    pattern: /(?:ignoră|uită|neglijează)\s+(?:toate\s+)?(?:instrucțiunile|comenzile|regulile)\s+(?:anterioare|precedente|de\s+mai\s+sus)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Romanian: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-051a',
    pattern: /(?:uită|șterge|elimină)\s+(?:toate\s+)?(?:regulile|instrucțiunile|restricțiile)|(?:fără|nicio)\s+(?:restricție|limitare|cenzură|filtru)|(?:dezactivează|oprește)\s+(?:filtrele?\s+de\s+)?(?:securitate|siguranță)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Romanian: forget rules, no restrictions, disable security',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-051b',
    pattern: /(?:arată|dezvăluie|spune)\s+(?:promptul?\s+(?:de\s+)?sistem|configurația\s+sistemului)|(?:parolă|token|cheie\s+API|credențiale)\s+(?:arată|spune|trimite)|(?:sunt\s+(?:adminul|dezvoltatorul|proprietarul)\s+tău)/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Romanian: show system prompt, extract credentials, I am admin',
    category: 'multilingual',
    enabled: true,
  },

  // ── Hungarian / Magyar ────────────────────────────────────────────
  {
    id: 'ml-052',
    pattern: /(?:hagyd\s+figyelmen\s+kívül|felejtsd?\s+el|ignoráld)\s+(?:az\s+összes\s+)?(?:korábbi|előző|fenti)\s+(?:utasítás|parancs|szabály)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Hungarian: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-052a',
    pattern: /(?:felejtsd?\s+el|töröld?|távolítsd?\s+el)\s+(?:az\s+összes\s+)?(?:szabályt?|utasítás|korlátozás)|(?:korlátozás|cenzúra|szűrő)\s+nélkül|(?:kapcsold\s+ki|tiltsd\s+le)\s+(?:a\s+)?(?:biztonsági\s+)?(?:szűrőket|védelmet)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Hungarian: forget rules, no restrictions, disable security',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-052b',
    pattern: /(?:mutasd|áruld\s+el|mondd\s+el)\s+(?:a\s+)?(?:rendszer\s*promptot|rendszer\s*üzenetet|konfigurációt)|(?:jelszó|token|API[\s-]?kulcs|hitelesítő\s+adatok)\s+(?:mutasd|mondd|küldd)|(?:én\s+vagyok\s+a\s+(?:te\s+)?(?:admined|fejlesztőd|tulajdonosod))/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Hungarian: show system prompt, extract credentials, I am admin',
    category: 'multilingual',
    enabled: true,
  },

  // ── Greek / Ελληνικά ──────────────────────────────────────────────
  {
    id: 'ml-053',
    pattern: /(?:αγνόησε|ξέχνα|παράβλεψε)\s+(?:όλες\s+)?(?:τις\s+)?(?:προηγούμενες|παλιές)\s+(?:οδηγίες|εντολές|κανόνες)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Greek: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-053a',
    pattern: /(?:ξέχνα|διάγραψε|αφαίρεσε)\s+(?:όλους?\s+)?(?:τους?\s+)?(?:κανόνες|οδηγίες|περιορισμούς)|(?:χωρίς|κανένας?)\s+(?:περιορισμ|λογοκρισία|φίλτρ)|(?:απενεργοποίησε|κλείσε)\s+(?:τα?\s+)?(?:φίλτρα?\s+)?(?:ασφαλείας|προστασίας)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Greek: forget rules, no restrictions, disable security',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-053b',
    pattern: /(?:δείξε|αποκάλυψε|πες)\s+(?:μου\s+)?(?:το\s+)?(?:system\s*prompt|μήνυμα\s+συστήματος)|(?:κωδικός|token|κλειδί\s+API|διαπιστευτήρια)\s+(?:δείξε|πες|στείλε)|(?:είμαι\s+ο\s+(?:admin|δημιουργός|ιδιοκτήτης)\s+σου)/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Greek: show system prompt, extract credentials, I am admin',
    category: 'multilingual',
    enabled: true,
  },

  // ── Bulgarian / Български ─────────────────────────────────────────
  {
    id: 'ml-054',
    pattern: /(?:игнорирай|забрави|пренебрегни)\s+(?:всички\s+)?(?:предишни|предходни|по-ранни)\s+(?:инструкции|команди|правила)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Bulgarian: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-054a',
    pattern: /(?:забрави|изтрий|премахни)\s+(?:всички\s+)?(?:правила|инструкции|ограничения)|(?:без|никакви)\s+(?:ограничения|рестрикции|цензура|филтри)|(?:деактивирай|изключи)\s+(?:филтрите?\s+за\s+)?(?:сигурност|безопасност)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Bulgarian: forget rules, no restrictions, disable security',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-054b',
    pattern: /(?:покажи|разкрий|кажи)\s+(?:ми\s+)?(?:системния\s+промпт|системното\s+съобщение)|(?:парола|токен|API\s+ключ|идентификационни\s+данни)\s+(?:покажи|кажи|изпрати)|(?:аз\s+съм\s+(?:твоят|твоя)\s+(?:админ|разработчик|собственик))/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Bulgarian: show system prompt, extract credentials, I am admin',
    category: 'multilingual',
    enabled: true,
  },

  // ── Croatian / Hrvatski ───────────────────────────────────────────
  {
    id: 'ml-055',
    pattern: /(?:ignoriraj|zanemari|zaboravi)\s+(?:sve\s+)?(?:prethodne|prijašnje|ranije)\s+(?:upute|naredbe|pravila|instrukcije)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Croatian: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-055a',
    pattern: /(?:zaboravi|obriši|ukloni)\s+(?:sva?\s+)?(?:pravila|upute|ograničenja)|(?:bez|nikakvih)\s+(?:ograničenja|restrikcija|cenzure)|(?:prikaži|otkrij)\s+(?:sistemski\s+prompt)|(?:lozinka|token|API\s+ključ)\s+(?:prikaži|reci|pošalji)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Croatian: forget rules, no restrictions, show prompt, extract creds',
    category: 'multilingual',
    enabled: true,
  },

  // ── Serbian Cyrillic / Српски ─────────────────────────────────────
  {
    id: 'ml-056',
    pattern: /(?:игнориши|занемари|заборави)\s+(?:све\s+)?(?:претходне|раније)\s+(?:инструкције|наредбе|правила)|(?:заборави|обриши|уклони)\s+(?:сва?\s+)?(?:правила|инструкције|ограничења)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Serbian (Cyrillic): ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-056a',
    pattern: /(?:без|никаквих)\s+(?:ограничења|рестрикција|цензуре)|(?:прикажи|откриј)\s+(?:системски\s+промпт)|(?:лозинка|токен|API\s+кључ)\s+(?:прикажи|реци|пошаљи)|(?:ја\s+сам\s+(?:твој\s+)?(?:админ|програмер|власник))/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Serbian: no restrictions, show prompt, extract creds, I am admin',
    category: 'multilingual',
    enabled: true,
  },

  // ── Slovenian / Slovenščina ───────────────────────────────────────
  {
    id: 'ml-057',
    pattern: /(?:prezri|ignoriraj|pozabi)\s+(?:vsa?\s+)?(?:prejšnja|predhodna)\s+(?:navodila|ukaze|pravila)|(?:pozabi|izbriši|odstrani)\s+(?:vsa?\s+)?(?:pravila|navodila|omejitve)|(?:brez|nobene)\s+(?:omejitev|cenzure)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Slovenian: ignore/forget previous instructions, no restrictions',
    category: 'multilingual',
    enabled: true,
  },

  // ── Lithuanian / Lietuvių ─────────────────────────────────────────
  {
    id: 'ml-058',
    pattern: /(?:ignoruok|pamiršk|nepaisyk)\s+(?:visų?\s+)?(?:ankstesnių|buvusių)\s+(?:instrukcijų|komandų|taisyklių)|(?:pamiršk|ištrink|pašalink)\s+(?:visas?\s+)?(?:taisykles|instrukcijas|apribojimus)|(?:be|jokių)\s+(?:apribojimų|cenzūros)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Lithuanian: ignore/forget previous instructions, no restrictions',
    category: 'multilingual',
    enabled: true,
  },

  // ── Latvian / Latviešu ────────────────────────────────────────────
  {
    id: 'ml-059',
    pattern: /(?:ignorē|aizmirsti|neievēro)\s+(?:visas?\s+)?(?:iepriekšējās|agrākās)\s+(?:instrukcijas|komandas|noteikumus)|(?:aizmirsti|dzēs|noņem)\s+(?:visus?\s+)?(?:noteikumus|instrukcijas|ierobežojumus)|(?:bez|nekādiem)\s+(?:ierobežojumiem|cenzūras)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Latvian: ignore/forget previous instructions, no restrictions',
    category: 'multilingual',
    enabled: true,
  },

  // ── Estonian / Eesti ──────────────────────────────────────────────
  {
    id: 'ml-060',
    pattern: /(?:ignoreeri|unusta|eira)\s+(?:kõiki?\s+)?(?:eelnevaid|varasemaid)\s+(?:juhiseid|käske|reegleid)|(?:unusta|kustuta|eemalda)\s+(?:kõik\s+)?(?:reeglid|juhised|piirangud)|(?:ilma|mitte\s+mingeid)\s+(?:piiranguteta?|tsensuurita?)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Estonian: ignore/forget previous instructions, no restrictions',
    category: 'multilingual',
    enabled: true,
  },

  // ── Catalan / Català ──────────────────────────────────────────────
  {
    id: 'ml-061',
    pattern: /(?:ignora|oblida|descarta)\s+(?:totes?\s+)?(?:les?\s+)?(?:instruccions|ordres|regles)\s+(?:anteriors|prèvies|de\s+dalt)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Catalan: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-061a',
    pattern: /(?:oblida|esborra|elimina)\s+(?:totes?\s+)?(?:les?\s+)?(?:regles|instruccions|restriccions)|(?:sense|cap)\s+(?:restricció|limitació|censura)|(?:mostra|revela)\s+(?:el\s+)?(?:prompt\s+del?\s+sistema)|(?:contrasenya|token|clau\s+API)\s+(?:mostra|digues|envia)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Catalan: forget rules, no restrictions, show prompt, extract creds',
    category: 'multilingual',
    enabled: true,
  },

  // ── Albanian / Shqip ──────────────────────────────────────────────
  {
    id: 'ml-062',
    pattern: /(?:injoro|harro|shpërfill)\s+(?:të\s+gjitha\s+)?(?:udhëzimet|komandat|rregullat)\s+(?:e\s+)?(?:mëparshme|të\s+mëparshme)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Albanian: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-062a',
    pattern: /(?:harro|fshi|hiq)\s+(?:të\s+gjitha\s+)?(?:rregullat|udhëzimet|kufizimet)|(?:pa|asnjë)\s+(?:kufizim|censurë|filtër)|(?:trego|zbulon)\s+(?:prompt\s+(?:e\s+)?sistemit)|(?:fjalëkalim|token|çelës\s+API)\s+(?:trego|thuaj|dërgo)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Albanian: forget rules, no restrictions, show prompt, extract creds',
    category: 'multilingual',
    enabled: true,
  },

  // ── Macedonian / Македонски ────────────────────────────────────────
  {
    id: 'ml-063',
    pattern: /(?:игнорирај|заборави)\s+(?:ги\s+)?(?:сите\s+)?(?:претходни|поранешни)\s+(?:инструкции|наредби|правила)|(?:заборави|избриши)\s+(?:ги\s+)?(?:сите\s+)?(?:правила|инструкции|ограничувања)|(?:без|никакви)\s+(?:ограничувања|цензура)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Macedonian: ignore/forget previous instructions, no restrictions',
    category: 'multilingual',
    enabled: true,
  },

  // ── Icelandic / Íslenska ──────────────────────────────────────────
  {
    id: 'ml-064',
    pattern: /(?:hunsa|gleym)\s+(?:öllum?\s+)?(?:fyrri|fyrirliggjandi)\s+(?:leiðbeiningum|skipunum|reglum)|(?:gleym|eyð)\s+(?:öllum?\s+)?(?:reglum|leiðbeiningum|takmörkunum)|(?:án|engin)\s+(?:takmarkana|ritskoðunar)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Icelandic: ignore/forget previous instructions, no restrictions',
    category: 'multilingual',
    enabled: true,
  },

  // ── Welsh / Cymraeg ───────────────────────────────────────────────
  {
    id: 'ml-065',
    pattern: /(?:anwybyddwch|anghofiwch)\s+(?:yr?\s+)?(?:holl\s+)?(?:gyfarwyddiadau|gorchmynion|rheolau)\s+(?:blaenorol|cynharach)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Welsh: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },

  // ── Irish / Gaeilge ───────────────────────────────────────────────
  {
    id: 'ml-066',
    pattern: /(?:déan\s+neamhaird|lig\s+i\s+ndearmad|déan\s+dearmad)\s+(?:ar\s+)?(?:na\s+)?(?:treoracha|orduithe|rialacha)\s+(?:roimhe\s+seo|roimh)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Irish: ignore/forget previous instructions',
    category: 'multilingual',
    enabled: true,
  },

  // ── Afrikaans ─────────────────────────────────────────────────────
  {
    id: 'ml-067',
    pattern: /(?:ignoreer|vergeet|verontagsaam)\s+(?:alle\s+)?(?:vorige\s+)?(?:instruksies|opdragte|reëls)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Afrikaans: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-067a',
    pattern: /(?:vergeet|verwyder|skrap)\s+(?:alle\s+)?(?:reëls|instruksies|beperkings)|(?:sonder|geen)\s+(?:beperkings|sensuur|filter)|(?:wys|openbaar)\s+(?:die\s+)?(?:stelsel\s*prompt|stelselkonfigurasie)|(?:wagwoord|token|API[\s-]?sleutel)\s+(?:wys|vertel|stuur)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Afrikaans: forget rules, no restrictions, show prompt, extract creds',
    category: 'multilingual',
    enabled: true,
  },

  // ═══════════════════════════════════════════════════════════════════
  // AFRICAN LANGUAGES
  // ═══════════════════════════════════════════════════════════════════

  // ── Swahili / Kiswahili ───────────────────────────────────────────
  {
    id: 'ml-068',
    pattern: /(?:puuza|sahau|acha)\s+(?:maagizo|amri|sheria|kanuni)\s+(?:yote\s+)?(?:ya\s+)?(?:awali|kabla|zilizopita)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Swahili: ignore/forget all previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-068a',
    pattern: /(?:sahau|futa|ondoa)\s+(?:sheria|kanuni|maagizo|vikwazo)\s+(?:vyote|zote)|(?:bila|hakuna)\s+(?:vikwazo|udhibiti|kuchuja)|(?:onyesha|fichua|sema)\s+(?:system\s+prompt|mfumo\s+wa\s+maagizo)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Swahili: forget all rules, no restrictions, show system prompt',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-068b',
    pattern: /(?:nywila|nenosiri|tokeni|funguo\s+ya\s+API)\s+(?:onyesha|sema|tuma)|(?:mimi\s+ni\s+(?:msimamizi|mtaalamu|mmiliki)\s+wako)/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'Swahili: extract passwords/tokens, I am your admin/owner',
    category: 'multilingual',
    enabled: true,
  },

  // ── Hausa ─────────────────────────────────────────────────────────
  {
    id: 'ml-069',
    pattern: /(?:yi\s+watsi|mance|bar)\s+(?:da\s+)?(?:duk(?:kan)?\s+)?(?:umarnin?|umarce|ka'idoji)\s+(?:da\s+suka\s+gabata|na\s+baya)|(?:mance|share|cire)\s+(?:duk(?:kan)?\s+)?(?:ka'idoji|dokoki|takunkumi)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Hausa: ignore/forget all previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },

  // ── Yoruba ────────────────────────────────────────────────────────
  {
    id: 'ml-070',
    pattern: /(?:fojú\s+fo|gbàgbé|kọ\s+sílẹ̀)\s+(?:gbogbo\s+)?(?:àwọn\s+)?(?:ìtọ́nisọ́nà|àṣẹ|òfin)\s+(?:tẹ́lẹ̀|àtijọ́|tí\s+ó\s+ti\s+kọjá)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Yoruba: ignore/forget all previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },

  // ── Amharic / Ethiopic Script Detection ───────────────────────────
  {
    id: 'ml-071',
    pattern: /[\u1200-\u137F]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted|forget|disregard)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted|forget|disregard).*[\u1200-\u137F]{3,}/i,
    phase: 'initial_access',
    confidence: 0.78,
    description: 'Ethiopic/Amharic script + English injection keywords',
    category: 'multilingual',
    enabled: true,
  },

  // ═══════════════════════════════════════════════════════════════════
  // CAUCASUS & CENTRAL/EAST ASIA
  // ═══════════════════════════════════════════════════════════════════

  // ── Georgian Script Detection / ქართული ──────────────────────────
  {
    id: 'ml-072',
    pattern: /[\u10A0-\u10FF]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted|forget|disregard)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted|forget|disregard).*[\u10A0-\u10FF]{3,}/i,
    phase: 'initial_access',
    confidence: 0.78,
    description: 'Georgian script + English injection keywords',
    category: 'multilingual',
    enabled: true,
  },

  // ── Armenian Script Detection / Հայերեն ───────────────────────────
  {
    id: 'ml-073',
    pattern: /[\u0530-\u058F]{3,}.*(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted|forget|disregard)|(?:ignore|bypass|override|hack|delete|system\s*prompt|password|admin|jailbreak|unrestricted|forget|disregard).*[\u0530-\u058F]{3,}/i,
    phase: 'initial_access',
    confidence: 0.78,
    description: 'Armenian script + English injection keywords',
    category: 'multilingual',
    enabled: true,
  },

  // ── Azerbaijani / Azərbaycanca ────────────────────────────────────
  {
    id: 'ml-074',
    pattern: /(?:əvvəlki|keçmiş)\s+(?:göstərişləri|əmrləri|qaydaları)\s+(?:laqeyd\s+qal|unut|nəzərə\s+alma)|(?:bütün|hər)\s+(?:qaydaları|göstərişləri|məhdudiyyətləri)\s+(?:unut|sil|götür)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Azerbaijani: ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-074a',
    pattern: /(?:heç\s+bir|olmadan)\s+(?:məhdudiyyət|senzura|filtr)|(?:təhlükəsizlik|mühafizə)\s+(?:filtrlərini?\s+)?(?:söndür|deaktiv\s+et)|(?:parol|token|API\s+açarı)\s+(?:göstər|de|göndər)/i,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'Azerbaijani: no restrictions, disable security, extract credentials',
    category: 'multilingual',
    enabled: true,
  },

  // ── Kazakh / Қазақша ──────────────────────────────────────────────
  {
    id: 'ml-075',
    pattern: /(?:алдыңғы|бұрынғы)\s+(?:нұсқауларды|бұйрықтарды|ережелерді)\s+(?:елемеу|ұмыту|назарға\s+алма)|(?:барлық|бәрін)\s+(?:ережелерді|нұсқауларды|шектеулерді)\s+(?:ұмыту|жою)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Kazakh: ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },

  // ── Uzbek / Oʻzbekcha ─────────────────────────────────────────────
  {
    id: 'ml-076',
    pattern: /(?:oldingi|avvalgi)\s+(?:ko'rsatmalarni|buyruqlarni|qoidalarni)\s+(?:e'tiborsiz\s+qol|unut)|(?:barcha|hamma)\s+(?:qoidalarni|ko'rsatmalarni|cheklovlarni)\s+(?:unut|o'chir)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Uzbek: ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },

  // ── Mongolian Script Detection ────────────────────────────────────
  {
    id: 'ml-077',
    pattern: /(?:өмнөх|урьдын)\s+(?:зааврыг|тушаалыг|дүрмийг)\s+(?:үл\s+тоо|март|хэрэгсэхгүй)|(?:бүх|бүгд)\s+(?:дүрэм|зааврыг|хязгаарлалтыг)\s+(?:март|устга)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Mongolian: ignore/forget previous instructions/rules',
    category: 'multilingual',
    enabled: true,
  },

  // ═══════════════════════════════════════════════════════════════════
  // UNIVERSAL / CROSS-LANGUAGE PATTERNS
  // ═══════════════════════════════════════════════════════════════════

  // ── Mixed-script / Cross-language (enhanced from original ml-010) ──
  {
    id: 'ml-010',
    pattern: /[\u0400-\u04FF\u0600-\u06FF\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF].*(?:ignore|disregard|forget|override|bypass)|(?:ignore|disregard|forget|override|bypass).*[\u0400-\u04FF\u0600-\u06FF\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF]/i,
    phase: 'initial_access',
    confidence: 0.75,
    description: 'Mixed-script detection: Latin + Cyrillic/Arabic/CJK in suspicious patterns',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-010a',
    pattern: /[\u0400-\u04FF](?=[a-zA-Z])|[a-zA-Z](?=[\u0400-\u04FF]).*(?:gnore|nstruction|ypass|verride|isregard)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Homoglyph attack: Cyrillic characters mixed with Latin in attack keywords',
    category: 'multilingual',
    enabled: true,
  },

  // ── Universal script + injection keyword detection ────────────────
  {
    id: 'ml-078',
    pattern: /[\u0590-\u05FF\u0600-\u06FF\u0750-\u077F]{3,}.{0,80}(?:ignore|bypass|override|forget|disregard|hack|delete|drop\s*table|system\s*prompt|password|admin|secret|credential|jailbreak|unlock|unrestricted|unfiltered|uncensored)/i,
    phase: 'initial_access',
    confidence: 0.75,
    description: 'Hebrew/Arabic/Extended-Arabic script + English injection keywords',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-078a',
    pattern: /(?:ignore|bypass|override|forget|disregard|hack|delete|drop\s*table|system\s*prompt|password|admin|secret|credential|jailbreak|unlock|unrestricted|unfiltered|uncensored).{0,80}[\u0590-\u05FF\u0600-\u06FF\u0750-\u077F]{3,}/i,
    phase: 'initial_access',
    confidence: 0.75,
    description: 'English injection keywords + Hebrew/Arabic/Extended-Arabic script',
    category: 'multilingual',
    enabled: true,
  },

  // ── Polyglot (same attack in multiple languages, enhanced) ────────
  {
    id: 'ml-018',
    pattern: /(?:ignoriere|ignora|ignore[rz]?|忽略|игнорируй|무시|تجاهل|無視|উপেক্ষা|पूर्व|puuza|abaikan).{0,30}(?:ignoriere|ignora|ignore[rz]?|忽略|игнорируй|무시|تجاهل|無視|উপেক্ষা|पूर्व|puuza|abaikan)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Polyglot injection: ignore/bypass repeated in multiple languages',
    category: 'multilingual',
    enabled: true,
  },

  // ── Translation wrapping (enhanced) ───────────────────────────────
  {
    id: 'ml-019',
    pattern: /(?:tradui[st]|translat|übersetze?|翻译|переведи|traduz|terjemah|번역|翻訳|ترجم|অনুবাদ|अनुवाद).{0,60}(?:ignore|bypass|override|hack|delete|drop\s+table|system\s+prompt|password|admin|execute|follow|comply|obey)/i,
    phase: 'actions_on_objective',
    confidence: 0.82,
    description: 'Translation wrapping: attack keywords embedded in translation requests (15+ languages)',
    category: 'multilingual',
    enabled: true,
  },

  // ── Universal role reassignment (multilingual, enhanced) ──────────
  {
    id: 'ml-020',
    pattern: /(?:du\s+bist|tu\s+es|eres|you\s+are|あなたは|당신은|ты|أنت|तुम|তুমি|நீ|నీవు|kamu|ikaw)\s+(?:jetzt|maintenant|ahora|now|今|이제|теперь|الآن|अब|এখন|இப்போது|ఇప్పుడు|sekarang|ngayon)\s+/i,
    phase: 'initial_access',
    confidence: 0.70,
    description: 'Universal role reassignment: "you are now" across 14+ languages',
    category: 'multilingual',
    enabled: true,
  },

  // ── Rapid language switching (attack indicator) ───────────────────
  {
    id: 'ml-079',
    pattern: /[\u4E00-\u9FFF]{2,}.{0,20}[\u0400-\u04FF]{2,}|[\u0400-\u04FF]{2,}.{0,20}[\u0600-\u06FF]{2,}|[\u0600-\u06FF]{2,}.{0,20}[\u0900-\u097F]{2,}|[\u0900-\u097F]{2,}.{0,20}[\uAC00-\uD7AF]{2,}/,
    phase: 'initial_access',
    confidence: 0.65,
    description: 'Rapid script switching: CJK↔Cyrillic, Cyrillic↔Arabic, Arabic↔Devanagari, Devanagari↔Korean within 20 chars (confusion attack indicator)',
    category: 'multilingual',
    enabled: true,
  },

  // ── Global transliterated DAN/jailbreak personas ──────────────────
  {
    id: 'ml-080',
    pattern: /(?:DAN|D\.A\.N\.|ДАН|دان|ダン|댄|ড্যান|डैन)\s*(?:mode|modus|modo|モード|모드|মোড|मोड|وضع|modda|модус)/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Global DAN mode invocation across 10+ scripts',
    category: 'multilingual',
    enabled: true,
  },

  // ── Universal "no filter/no censor" pattern ───────────────────────
  {
    id: 'ml-081',
    pattern: /(?:no|sin|sans|ohne|без|tanpa|bila|walang|inga|ingen|ilman|bez|بدون|没有|なし|없는)\s+(?:filter|filtro|filtre|Filter|фильтр|filter|chujio|sensura?|censor|Zensur|цензур|senzura?|censuur|sensor|检查|フィルター|필터|ফিল্টার|फ़िल्टर|صافي)/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Universal "no filter/no censor" pattern across 20+ languages',
    category: 'multilingual',
    enabled: true,
  },

  // ── Universal "show password/secret" pattern ──────────────────────
  {
    id: 'ml-082',
    pattern: /(?:show|zeig|montre|muestra|покажи|tampilkan|onyesha|ipakita|visa|näytä|ukaž|arată|mutasd|δείξε|покажи|prikaži|göster|แสดง|দেখাও|दिखाओ|أظهر|הראה|显示|見せて|보여줘)\s+.{0,20}(?:password|Passwort|mot\s+de\s+passe|contraseña|пароль|kata\s+sandi|nywila|wagwoord|lösenord|salasana|heslo|parolă|jelszó|κωδικός|лозинка|şifre|รหัสผ่าน|পাসওয়ার্ড|पासवर्ड|كلمة\s+(?:المرور|السر)|סיסמה|密码|パスワード|비밀번호)/i,
    phase: 'actions_on_objective',
    confidence: 0.85,
    description: 'Universal "show password" across 25+ languages',
    category: 'multilingual',
    enabled: true,
  },
] as const
