const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
// 프록시 환경일 경우 필요시 주석 해제
// app.set('trust proxy', true);

const SESSION_TTL_MS = 60 * 60 * 1000; // 1시간 (60분)
// email -> { profileId, sessionId, ip, last }
const activeSessions = new Map();

const nowKR = () => new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });
const clientIP = (req) => {
  const xff = req.headers['x-forwarded-for'] || '';
  return (xff.split(',')[0] || '').trim() || req.connection.remoteAddress || '';
};
function pruneExpired(email) {
  const s = activeSessions.get(email);
  if (!s) return;
  if (Date.now() - s.last > SESSION_TTL_MS) activeSessions.delete(email);
}

app.get('/', (_, res) => res.send('🚀 인증 서버가 실행 중입니다.'));

// ✅ 로그인: 중복 로그인 시 기존 세션 자동 로그아웃 후 새 로그인 허용
app.all('/auth', (req, res) => {
  const usersPath = path.join(__dirname, 'users.json');
  const users = JSON.parse(fs.readFileSync(usersPath, 'utf-8'));

  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const code = String(q.code || '').trim();
  const profileId = String(q.profileId || '').trim();
  const ip = clientIP(req);
  const time = nowKR();

  if (!email || !code || !profileId)
    return res.json({ ok: false, msg: 'email, code, profileId 필요' });
  if (!users[email] || users[email] !== code) {
    console.log(`[실패] 🔴 ${time} | ${email} | IP:${ip}`);
    return res.json({ ok: false, msg: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  }

  pruneExpired(email);
  const cur = activeSessions.get(email);

  // ✅ 이미 다른 프로필이 로그인 중이면 기존 세션 종료 후 새 로그인 허용
  if (cur && (Date.now() - cur.last) <= SESSION_TTL_MS && cur.profileId !== profileId) {
    console.log(`[중복로그인 교체] 🔄 ${time} | ${email} | 기존:${cur.profileId} → 신규:${profileId}`);
    activeSessions.delete(email); // 기존 세션 강제 로그아웃
  }

  // 통과: 신규 로그인 또는 같은 프로필의 재로그인
  const sessionId = 'sess_' + crypto.randomBytes(8).toString('hex');
  activeSessions.set(email, { profileId, sessionId, ip, last: Date.now() });
  console.log(`[로그인] 🟢 ${time} | ${email} | 프로필:${profileId} | IP:${ip}`);
  return res.json({ ok: true, sessionId, profileId, ttlMs: SESSION_TTL_MS });
});

// ✅ 세션 확인
app.get('/check', (req, res) => {
  const email = String(req.query.email || '').trim();
  const profileId = String(req.query.profileId || '').trim();
  if (!email || !profileId)
    return res.json({ ok: false, msg: 'email, profileId 필요' });

  pruneExpired(email);
  const cur = activeSessions.get(email);
  if (!cur) return res.json({ ok: false, expired: true });

  const valid = Date.now() - cur.last <= SESSION_TTL_MS;
  if (!valid) {
    activeSessions.delete(email);
    return res.json({ ok: false, expired: true });
  }

  const sameProfile = cur.profileId === profileId;
  return res.json({
    ok: valid && sameProfile,
    sameProfile,
    sessionId: cur.sessionId,
    expiresInMs: SESSION_TTL_MS - (Date.now() - cur.last)
  });
});

// ✅ 하트비트(세션 유지)
app.post('/touch', (req, res) => {
  const { email, profileId } = req.body || {};
  if (!email || !profileId)
    return res.json({ ok: false, msg: 'email, profileId 필요' });
  const cur = activeSessions.get(email);
  if (!cur) return res.json({ ok: false, expired: true });
  if (cur.profileId !== profileId)
    return res.json({ ok: false, msg: '다른 프로필로 인계됨' });
  cur.last = Date.now();
  return res.json({ ok: true });
});

// ✅ 로그아웃 (같은 프로필만 허용)
app.all('/logout', (req, res) => {
  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const profileId = String(q.profileId || '').trim();
  if (!email || !profileId)
    return res.json({ ok: false, msg: 'email, profileId 필요' });

  const cur = activeSessions.get(email);
  if (cur && cur.profileId === profileId) {
    activeSessions.delete(email);
    console.log(`[로그아웃] 🔓 ${nowKR()} | ${email} | 프로필:${profileId}`);
    return res.json({ ok: true, msg: '로그아웃 완료' });
  }
  return res.json({ ok: false, msg: '로그인 상태가 아니거나 다른 프로필' });
});

app.listen(PORT, () =>
  console.log(`✅ 서버가 포트 ${PORT}에서 실행 중입니다`)
);
