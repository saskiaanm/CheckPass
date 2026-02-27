const passwordInput     = document.getElementById('passwordInput');
const toggleBtn         = document.getElementById('toggleBtn');
const eyeIcon           = document.getElementById('eyeIcon');
const strengthLabel     = document.getElementById('strengthLabel');
const crackTime         = document.getElementById('crackTime');
const ringProgress      = document.getElementById('ringProgress');
const scoreNumber       = document.getElementById('scoreNumber');
const lenVal            = document.getElementById('lenVal');
const entropyVal        = document.getElementById('entropyVal');
const suggestionsList   = document.getElementById('suggestionsList');
const warningsList      = document.getElementById('warningsList');
const aiContent         = document.getElementById('aiContent');
const generatedPassword = document.getElementById('generatedPassword');
const generateBtn       = document.getElementById('generateBtn');
const copyBtn           = document.getElementById('copyBtn');
const useBtn            = document.getElementById('useBtn');
const genLength         = document.getElementById('genLength');
const genLenLabel       = document.getElementById('genLenLabel');
const toast             = document.getElementById('toast');
const CIRCUMFERENCE = 314.16;
const SCORE_META = [
  { label: 'Very Weak', color: '#FF6B6B', risk: 'Critical',  attack: 'Instant crack' },
  { label: 'Weak',      color: '#FF9F43', risk: 'High',      attack: 'Seconds to minutes' },
  { label: 'Fair',      color: '#FFD93D', risk: 'Medium',    attack: 'Hours to days' },
  { label: 'Good',      color: '#3ECFCF', risk: 'Low',       attack: 'Months to years' },
  { label: 'Strong',    color: '#6BCB77', risk: 'Minimal',   attack: 'Centuries+' },
];
toggleBtn.addEventListener('click', () => {
  const isHidden = passwordInput.type === 'password';
  passwordInput.type = isHidden ? 'text' : 'password';
  eyeIcon.textContent = isHidden ? '(─ ‿ ─)' : '(⊙_⊙)';
  passwordInput.focus();
});

passwordInput.addEventListener('input', () => {
  const pwd = passwordInput.value;
  if (!pwd) { resetUI(); return; }
  analyzePassword(pwd);
});
function analyzePassword(pwd) {
  const result = zxcvbn(pwd);
  const score  = result.score;

  updateStrengthBar(score, pwd, result);
  updateRing(score);
  updateStats(pwd);
  updateSuggestions(pwd, result);
  updateWarnings(pwd, result);
  updateAIAnalysis(pwd, result, score);
}
function updateStrengthBar(score, pwd, result) {
  const meta = SCORE_META[score];
  const litCount = score === 0 ? 1 : score + 1;
  for (let i = 0; i < 4; i++) {
    const seg = document.getElementById(`seg${i}`);
    if (i < litCount) {
      seg.classList.add('active');
      seg.style.background = meta.color;
      seg.style.boxShadow  = `0 0 8px ${meta.color}55`;
    } else {
      seg.classList.remove('active');
      seg.style.background = '';
      seg.style.boxShadow  = '';
    }
  }

  strengthLabel.textContent = meta.label;
  strengthLabel.style.color = meta.color;

  const ct = result.crack_times_display.offline_fast_hashing_1e10_per_second;
  crackTime.textContent = `⏱ Crack time: ${ct}`;
}

function updateRing(score) {
  const fraction = score / 4;
  const offset   = CIRCUMFERENCE * (1 - fraction);
  ringProgress.style.strokeDashoffset = offset;
  scoreNumber.textContent = score;
}
function updateStats(pwd) {
  lenVal.textContent     = pwd.length;
  entropyVal.textContent = calcEntropy(pwd).toFixed(1);

  setChip('statLength',  pwd.length >= 12);
  setChip('statUpper',   /[A-Z]/.test(pwd));
  setChip('statLower',   /[a-z]/.test(pwd));
  setChip('statNumber',  /[0-9]/.test(pwd));
  setChip('statSymbol',  /[^a-zA-Z0-9]/.test(pwd));
  setChip('statEntropy', calcEntropy(pwd) >= 50);
}

function setChip(id, active) {
  document.getElementById(id).classList.toggle('active', active);
}
function calcEntropy(pwd) {
  let pool = 0;
  if (/[a-z]/.test(pwd))        pool += 26;
  if (/[A-Z]/.test(pwd))        pool += 26;
  if (/[0-9]/.test(pwd))        pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;
  return pool > 0 ? pwd.length * Math.log2(pool) : 0;
}
function updateSuggestions(pwd, result) {
  const tips = [];

  if (pwd.length < 8)
    tips.push('Use at least 8 characters. Longer = exponentially harder to crack.');
  if (pwd.length >= 8 && pwd.length < 12)
    tips.push('Extend to 12+ characters for significantly stronger protection.');
  if (pwd.length >= 12 && pwd.length < 16)
    tips.push('Push to 16+ characters to reach near-uncrackable territory.');
  if (pwd.length >= 20)
    tips.push('Excellent length! Long passwords are the #1 security factor — great job.');

  if (!/[A-Z]/.test(pwd))
    tips.push('Add uppercase letters (A–Z) to double your effective character set.');
  if (!/[a-z]/.test(pwd))
    tips.push('Include lowercase letters (a–z) for better complexity.');
  if (!/[0-9]/.test(pwd))
    tips.push('Mix in numbers (0–9) to boost combinatorial strength.');
  if (!/[^a-zA-Z0-9]/.test(pwd))
    tips.push('Add symbols like !@#$%^&* for maximum entropy.');
  if (result.feedback.suggestions.length) {
    result.feedback.suggestions.forEach(s => tips.push(`${s}`));
  }
  if (pwd.length < 10 && result.score <= 1)
    tips.push('Try a passphrase: 4 random words + numbers, e.g. "Horse!Sun7Tree#Moon"');

  if (tips.length === 0)
    tips.push(' No improvements needed — your password looks great!');

  renderList(suggestionsList, tips, 'suggestion-item');
}
function updateWarnings(pwd, result) {
  const warns = [];

  if (result.feedback.warning)
    warns.push(` ${result.feedback.warning}`);

  if (/^[a-z]+$/.test(pwd))
    warns.push('All lowercase — easily cracked by brute-force in seconds.');
  if (/^[A-Z]+$/.test(pwd))
    warns.push('All uppercase — very weak against automated tools.');
  if (/^[0-9]+$/.test(pwd))
    warns.push('Only numbers — PINs are trivially guessable.');
  if (/(.)\1{2,}/.test(pwd))
    warns.push('Repeated characters detected (e.g., "aaa") — easy to guess.');
  if (/^(.{1,4})\1+$/.test(pwd))
    warns.push('Repeating pattern detected — attackers test these automatically.');
  if (/\b(19|20)\d{2}\b/.test(pwd))
    warns.push('Year pattern found — birth years are among the first things attackers try.');
  if (isKeyboardPattern(pwd))
    warns.push('Keyboard walk detected (e.g., "qwerty", "12345") — appears in all dictionaries.');
  if (/^(password|pass|admin|login|welcome|letmein|monkey|dragon|master|abc|qwerty)/i.test(pwd))
    warns.push('Common password detected — this would be cracked instantly.');
  if (/\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b/i.test(pwd))
    warns.push('Month name detected — avoid predictable date patterns.');

  if (pwd.length > 0 && warns.length === 0)
    warns.push('No major vulnerabilities detected in this password.');

  renderList(warningsList, warns, 'warning-item');
}

function isKeyboardPattern(pwd) {
  const patterns = [
    'qwerty','qwert','asdfg','asdf','zxcvb','zxcv',
    '12345','23456','34567','45678','56789','67890',
    '09876','98765','87654','76543','65432','54321',
    'abcde','abcd','abc'
  ];
  const lower = pwd.toLowerCase();
  return patterns.some(p => lower.includes(p));
}
function updateAIAnalysis(pwd, result, score) {
  const entropy   = calcEntropy(pwd);
  const hasUpper  = /[A-Z]/.test(pwd);
  const hasLower  = /[a-z]/.test(pwd);
  const hasNum    = /[0-9]/.test(pwd);
  const hasSym    = /[^a-zA-Z0-9]/.test(pwd);
  const charTypes = [hasUpper, hasLower, hasNum, hasSym].filter(Boolean).length;
  const meta      = SCORE_META[score];
  const meterPct  = (score / 4) * 100;
  const vectors = getAttackVectors(score);
  const diversityText = ['None','Very Low','Low','Moderate','High'][charTypes] || 'Unknown';
  const entropyRating =
    entropy < 28  ? { text: 'Critically Low',  color: '#FF6B6B' } :
    entropy < 40  ? { text: 'Low',              color: '#FF9F43' } :
    entropy < 60  ? { text: 'Moderate',         color: '#FFD93D' } :
    entropy < 80  ? { text: 'High',             color: '#3ECFCF' } :
                    { text: 'Very High',         color: '#6BCB77' };

  aiContent.innerHTML = `
    <div class="ai-section">
      <div class="ai-section-title">Overall Security Assessment</div>
      <p>
        This password is rated
        <strong style="color:${meta.color}">${meta.label}</strong>.
        Estimated crack time using a fast offline attack:
        <strong>${result.crack_times_display.offline_fast_hashing_1e10_per_second}</strong>.
      </p>
      <div class="security-meter">
        <div class="meter-bar">
          <div class="meter-fill" style="width:${meterPct}%;background:linear-gradient(90deg,${meta.color},${meta.color}aa)"></div>
        </div>
        <span style="color:${meta.color};font-size:0.78rem;font-weight:800;white-space:nowrap">${meta.risk} Risk</span>
      </div>
    </div>

    <div class="ai-section">
      <div class="ai-section-title"> Complexity Breakdown</div>
      <p>
        <strong>Entropy:</strong> <span style="color:${entropyRating.color}">${entropy.toFixed(1)} bits (${entropyRating.text})</span>
        &nbsp;|&nbsp;
        <strong>Character Diversity:</strong> ${charTypes}/4 types (<span style="color:${meta.color}">${diversityText}</span>)
        &nbsp;|&nbsp;
        <strong>Length:</strong> ${pwd.length} chars
      </p>
    </div>

    <div class="ai-section">
      <div class="ai-section-title"> Likely Attack Vectors</div>
      <p>${vectors.map(v => `<span class="attack-tag">${v}</span>`).join('')}</p>
    </div>

    <div class="ai-section">
      <div class="ai-section-title">AI Recommendation</div>
      <p>${getRecommendation(score, pwd, entropy, charTypes)}</p>
    </div>
  `;
}

function getAttackVectors(score) {
  if (score === 0) return ['Brute-force (instant)', 'Dictionary attack', 'Rainbow table', 'Credential stuffing'];
  if (score === 1) return ['Dictionary attack', 'Rule-based attack', 'Mask attack'];
  if (score === 2) return ['Hybrid dictionary', 'Pattern-based guessing', 'Targeted attack'];
  if (score === 3) return ['Advanced hybrid attack', 'Targeted personal attack (unlikely)'];
  return ['Nation-state resources only (theoretical)', 'Quantum computing (future)'];
}

function getRecommendation(score, pwd, entropy, charTypes) {
  if (score === 4 && entropy > 80)
    return '<strong>Outstanding.</strong> This password is cryptographically strong and would take centuries to crack even with advanced hardware. Store it in a reputable password manager (e.g., Bitwarden or 1Password) to avoid memorization fatigue.';
  if (score === 4)
    return '<strong>Excellent password.</strong> You\'ve exceeded security thresholds for virtually every service. Consider enabling 2FA as a complementary layer of protection.';
  if (score === 3)
    return '<strong>Good password.</strong> This would resist most automated attacks. To reach maximum security, add more symbols or extend the length to 18+ characters.';
  if (score === 2)
    return '<strong>Moderate security.</strong> Resistant to basic attacks but could be cracked with dedicated GPU hardware in days. Mix all 4 character types and aim for 14+ characters.';
  if (score === 1)
    return '<strong>Weak password.</strong> Vulnerable to dictionary and rule-based attacks. Try a passphrase strategy: combine 4 random words with numbers and symbols, like <em>"Purple!Rain9Desk#Lamp"</em>.';
  return '<strong>Change this immediately.</strong> This password would be cracked in milliseconds. Use the generator below to create a cryptographically secure replacement right now 💕';
}
function renderList(el, items, cls) {
  el.innerHTML = '';
  items.forEach((item, i) => {
    const li = document.createElement('li');
    li.className = cls;
    li.innerHTML = item;
    li.style.animationDelay = `${i * 40}ms`;
    el.appendChild(li);
  });
}
function resetUI() {
  for (let i = 0; i < 4; i++) {
    const seg = document.getElementById(`seg${i}`);
    seg.classList.remove('active');
    seg.style.background = '';
    seg.style.boxShadow  = '';
  }
  strengthLabel.textContent = 'Start typing...';
  strengthLabel.style.color = '';
  crackTime.textContent      = '';
  ringProgress.style.strokeDashoffset = CIRCUMFERENCE;
  scoreNumber.textContent = '0';
  lenVal.textContent      = '0';
  entropyVal.textContent  = '0';

  ['statUpper','statLower','statNumber','statSymbol','statEntropy','statLength']
    .forEach(id => document.getElementById(id).classList.remove('active'));

  suggestionsList.innerHTML = '<li class="suggestion-item muted">Start typing to get AI-powered suggestions...</li>';
  warningsList.innerHTML    = '<li class="warning-item muted">No vulnerabilities detected yet.</li>';
  aiContent.innerHTML       = '<p class="muted">Enter a password to get a detailed AI analysis of its security profile, common attack vectors, and personalized recommendations.</p>';
}
genLength.addEventListener('input', () => {
  genLenLabel.textContent = genLength.value;
});

generateBtn.addEventListener('click', generateStrongPassword);

function generateStrongPassword() {
  const len   = parseInt(genLength.value);
  const upper = document.getElementById('genUpper').checked;
  const lower = document.getElementById('genLower').checked;
  const num   = document.getElementById('genNum').checked;
  const sym   = document.getElementById('genSym').checked;

  const UPPER_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const LOWER_CHARS = 'abcdefghijklmnopqrstuvwxyz';
  const NUM_CHARS   = '0123456789';
  const SYM_CHARS   = '!@#$%^&*()-_=+[]{}|;:,.<>?';

  let charset  = '';
  let required = [];

  if (upper) { charset += UPPER_CHARS; required.push(secureRandFrom(UPPER_CHARS)); }
  if (lower) { charset += LOWER_CHARS; required.push(secureRandFrom(LOWER_CHARS)); }
  if (num)   { charset += NUM_CHARS;   required.push(secureRandFrom(NUM_CHARS)); }
  if (sym)   { charset += SYM_CHARS;   required.push(secureRandFrom(SYM_CHARS)); }

  if (!charset) {
    alert('Please select at least one character type!');
    return;
  }
  let password = [...required];
  for (let i = password.length; i < len; i++) {
    password.push(secureRandFrom(charset));
  }
  password = secureShuffle(password).join('');

  generatedPassword.textContent = password;
  generatedPassword.style.color = '#3ECFCF';
  generatedPassword.animate(
    [{ opacity: 0, transform: 'translateY(-4px)' }, { opacity: 1, transform: 'translateY(0)' }],
    { duration: 300, easing: 'ease-out' }
  );
}
function secureRandFrom(str) {
  const arr = new Uint32Array(1);
  window.crypto.getRandomValues(arr);
  return str[arr[0] % str.length];
}
function secureShuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const rnd = new Uint32Array(1);
    window.crypto.getRandomValues(rnd);
    const j = rnd[0] % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}
copyBtn.addEventListener('click', () => {
  const pwd = generatedPassword.textContent;
  if (!pwd || pwd.startsWith('Click')) return;
  navigator.clipboard.writeText(pwd).then(showToast).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = pwd;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast();
  });
});
useBtn.addEventListener('click', () => {
  const pwd = generatedPassword.textContent;
  if (!pwd || pwd.startsWith('Click')) return;
  passwordInput.value = pwd;
  analyzePassword(pwd);
  passwordInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
  passwordInput.focus();
  passwordInput.animate(
    [{ boxShadow: '0 0 0 0 rgba(108,99,255,0.5)' }, { boxShadow: '0 0 0 10px rgba(108,99,255,0)' }],
    { duration: 500, easing: 'ease-out' }
  );
});
function showToast() {
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2600);
}
resetUI();
setTimeout(() => {
  generateStrongPassword();
}, 400);
