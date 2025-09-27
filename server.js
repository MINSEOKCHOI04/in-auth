const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
// 프록시 뒤면 주석 해제
// app.set('trust proxy', true);

const SESSION_TTL_MS = 30 * 60 * 1000; // 30분
// email -> { profileId, sessionId, ip, last }
const activeSessions = new Map();

const nowKR = () => new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });
const clientIP = (req) => {
  const xff = req.headers['x-forwarded-for'] || '';
  return (xff.split(',')[0] || '').trim() || req.connection.remoteAddress || '';
};
function pruneExpired(email){
  const s = activeSessions.get(email);
  if (!s) return;
  if (Date.now() - s.last > SESSION_TTL_MS) activeSessions.delete(email);
}

app.get('/', (_, res) => res.send('🚀 인증 서버가 실행 중입니다.'));

// 로그인: 다른 프로필이 활성 중이어도 **강제 인계(기존 세션 종료 후 대체)**
app.all('/auth', (req, res) => {
  const usersPath = path.join(__dirname, 'users.json');
  const users = JSON.parse(fs.readFileSync(usersPath, 'utf-8'));

  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const code  = String(q.code  || '').trim();
  const profileId = String(q.profileId || '').trim(); // 필수
  const ip = clientIP(req);
  const time = nowKR();

  if (!email || !code || !profileId) return res.json({ ok:false, msg:'email, code, profileId 필요' });
  if (!users[email] || users[email] !== code) {
    console.log(`[실패] 🔴 ${time} | ${email} | IP:${ip}`);
    return res.json({ ok:false, msg:'아이디 또는 비밀번호가 올바르지 않습니다.' });
  }

  pruneExpired(email);
  const cur = activeSessions.get(email);
  let takeover = false;
  let previous = null;

  if (cur && (Date.now() - cur.last) <= SESSION_TTL_MS) {
    if (cur.profileId !== profileId) {
      // ✅ 강제 인계: 기존 세션 폐기 후 새 프로필로 교체
      takeover = true;
      previous = { profileId: cur.profileId, ip: cur.ip, last: cur.last };
      console.log(`[강제인계] 🔁 ${time} | ${email} | 기존:${cur.profileId} → 새:${profileId} | IP:${ip}`);
    } else {
      console.log(`[재접속] 🟡 ${time} | ${email} | 프로필:${profileId} | IP:${ip}`);
    }
  } else {
    console.log(`[신규로그인] 🟢 ${time} | ${email} | 프로필:${profileId} | IP:${ip}`);
  }

  const sessionId = 'sess_' + crypto.randomBytes(8).toString('hex');
  activeSessions.set(email, { profileId, sessionId, ip, last: Date.now() });

  return res.json({ ok:true, msg: takeover ? '기존 프로필을 로그아웃하고 로그인했습니다' : '로그인 성공', sessionId, profileId, ttlMs: SESSION_TTL_MS, takeover, previous });
});

// 세션 확인
app.get('/check', (req, res) => {
  const email = String(req.query.email || '').trim();
  const profileId = String(req.query.profileId || '').trim();
  if (!email || !profileId) return res.json({ ok:false, msg:'email, profileId 필요' });

  pruneExpired(email);
  const cur = activeSessions.get(email);
  if (!cur) return res.json({ ok:false, expired:true });

  const valid = (Date.now() - cur.last) <= SESSION_TTL_MS;
  if (!valid) {
    activeSessions.delete(email);
    return res.json({ ok:false, expired:true });
  }
  const sameProfile = cur.profileId === profileId;
  // 다른 프로필로 인계되었으면 즉시 실패 반환 → 클라이언트가 강제 로그아웃 처리
  return res.json({ ok: valid && sameProfile, sameProfile, sessionId: cur.sessionId, expiresInMs: SESSION_TTL_MS - (Date.now()-cur.last) });
});

// 하트비트(활동 연장)
app.post('/touch', (req, res) => {
  const { email, profileId } = req.body || {};
  if (!email || !profileId) return res.json({ ok:false, msg:'email, profileId 필요' });
  const cur = activeSessions.get(email);
  if (!cur) return res.json({ ok:false, expired:true });
  if (cur.profileId !== profileId) return res.json({ ok:false, msg:'다른 프로필로 인계됨' });
  cur.last = Date.now();
  return res.json({ ok:true });
});

// 로그아웃(같은 프로필만 종료 허용)
app.all('/logout', (req, res) => {
  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const profileId = String(q.profileId || '').trim();
  if (!email || !profileId) return res.json({ ok:false, msg:'email, profileId 필요' });

  const cur = activeSessions.get(email);
  if (cur && cur.profileId === profileId) {
    activeSessions.delete(email);
    console.log(`[로그아웃] 🔓 ${nowKR()} | ${email} | 프로필:${profileId}`);
    return res.json({ ok:true, msg:'로그아웃 완료' });
  }
  return res.json({ ok:false, msg:'로그인 상태가 아니거나 다른 프로필' });
});

app.listen(PORT, () => console.log(`✅ 서버가 포트 ${PORT}에서 실행 중입니다`));
