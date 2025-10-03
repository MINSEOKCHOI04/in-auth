const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
// 프록시 뒤면 필요시 주석 해제
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

// ✅ 로그인: 새 로그인이 기존 세션을 대체 (기존 세션 무효화)
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

  // ✅ 기존 세션이 있으면 로그 남기고 덮어쓰기
  if (cur && (Date.now() - cur.last) <= SESSION_TTL_MS) {
    console.log(`[세션 교체] 🔄 ${time} | ${email} | 기존:${cur.profileId} → 신규:${profileId} | 기존IP:${cur.ip} → 신규IP:${ip}`);
  }

  // 새 세션으로 덮어쓰기 (기존 세션은 자동 무효화)
  const sessionId = 'sess_' + crypto.randomBytes(8).toString('hex');
  activeSessions.set(email, { profileId, sessionId, ip, last: Date.now() });
  console.log(`[로그인] 🟢 ${time} | ${email} | 프로필:${profileId} | IP:${ip}`);
  
  return res.json({ 
    ok: true, 
    sessionId, 
    profileId, 
    ttlMs: SESSION_TTL_MS,
    message: cur ? '기존 세션이 종료되고 새로 로그인되었습니다.' : '로그인 성공'
  });
});

// ✅ 세션 확인 (sessionId 검증 추가)
app.get('/check', (req, res) => {
  const email = String(req.query.email || '').trim();
  const profileId = String(req.query.profileId || '').trim();
  const sessionId = String(req.query.sessionId || '').trim();
  
  if (!email || !profileId || !sessionId) {
    return res.json({ ok:false, msg:'email, profileId, sessionId 필요' });
  }

  pruneExpired(email);
  const cur = activeSessions.get(email);
  if (!cur) return res.json({ ok:false, expired:true, msg:'세션이 존재하지 않습니다' });

  const valid = (Date.now() - cur.last) <= SESSION_TTL_MS;
  if (!valid) {
    activeSessions.delete(email);
    return res.json({ ok:false, expired:true, msg:'세션이 만료되었습니다' });
  }

  // sessionId와 profileId 모두 일치해야 유효
  const sessionValid = cur.sessionId === sessionId && cur.profileId === profileId;
  
  if (!sessionValid) {
    return res.json({ 
      ok: false, 
      expired: false,
      replaced: cur.sessionId !== sessionId, // 세션이 교체되었는지 표시
      msg: cur.sessionId !== sessionId ? '다른 곳에서 로그인되어 세션이 종료되었습니다.' : '프로필 정보가 일치하지 않습니다'
    });
  }

  return res.json({ 
    ok: true, 
    sessionId: cur.sessionId, 
    profileId: cur.profileId,
    expiresInMs: SESSION_TTL_MS - (Date.now() - cur.last) 
  });
});

// ✅ 하트비트(활동 연장) - sessionId 검증 추가
app.post('/touch', (req, res) => {
  const { email, profileId, sessionId } = req.body || {};
  
  if (!email || !profileId || !sessionId) {
    return res.json({ ok:false, msg:'email, profileId, sessionId 필요' });
  }
  
  const cur = activeSessions.get(email);
  if (!cur) return res.json({ ok:false, expired:true, msg:'세션이 존재하지 않습니다' });
  
  // sessionId와 profileId 모두 검증
  if (cur.sessionId !== sessionId) {
    return res.json({ 
      ok: false, 
      replaced: true,
      msg: '다른 곳에서 로그인되어 현재 세션이 무효화되었습니다' 
    });
  }
  
  if (cur.profileId !== profileId) {
    return res.json({ ok:false, msg:'프로필 정보가 일치하지 않습니다' });
  }
  
  cur.last = Date.now();
  return res.json({ 
    ok: true,
    expiresInMs: SESSION_TTL_MS 
  });
});

// ✅ 로그아웃 (직접 로그아웃 시 세션 즉시 삭제)
app.all('/logout', (req, res) => {
  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const profileId = String(q.profileId || '').trim();
  const sessionId = String(q.sessionId || '').trim();
  
  if (!email) {
    return res.json({ ok:false, msg:'email 필요' });
  }

  const cur = activeSessions.get(email);
  
  // 세션이 없는 경우
  if (!cur) {
    console.log(`[로그아웃 시도] ⚠️ ${nowKR()} | ${email} | 세션 없음`);
    return res.json({ ok:true, msg:'이미 로그아웃 상태입니다' });
  }
  
  // sessionId가 제공된 경우: 정확한 세션 매칭 확인 (보안 강화)
  if (sessionId) {
    if (cur.sessionId === sessionId) {
      // sessionId가 일치하면 profileId 관계없이 로그아웃
      activeSessions.delete(email);
      console.log(`[로그아웃] 🔓 ${nowKR()} | ${email} | 프로필:${cur.profileId} | 세션ID 일치`);
      return res.json({ ok:true, msg:'로그아웃 완료' });
    } else {
      // sessionId 불일치 - 이미 다른 세션으로 교체됨
      return res.json({ 
        ok: true, 
        msg: '이미 다른 곳에서 로그인되어 현재 세션은 무효화되었습니다' 
      });
    }
  }
  
  // sessionId 없이 profileId만으로 로그아웃 (하위 호환성)
  if (profileId) {
    if (cur.profileId === profileId) {
      activeSessions.delete(email);
      console.log(`[로그아웃] 🔓 ${nowKR()} | ${email} | 프로필:${profileId}`);
      return res.json({ ok:true, msg:'로그아웃 완료' });
    } else {
      // 다른 프로필이 로그인 중 - 현재 세션은 이미 무효
      return res.json({ 
        ok: true, 
        msg: '다른 프로필로 로그인되어 있어 현재 세션은 이미 무효화되었습니다' 
      });
    }
  }
  
  // email만 제공된 경우: 무조건 세션 삭제 (간편 로그아웃)
  activeSessions.delete(email);
  console.log(`[로그아웃] 🔓 ${nowKR()} | ${email} | 강제 로그아웃`);
  return res.json({ ok:true, msg:'로그아웃 완료' });
});

// ✅ 관리자용: 현재 활성 세션 조회 (개발/디버깅용)
app.get('/admin/sessions', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  
  // 간단한 관리자 인증 (프로덕션에서는 더 강력한 인증 필요)
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  const sessions = [];
  activeSessions.forEach((session, email) => {
    sessions.push({
      email: email.substring(0, 3) + '***', // 이메일 일부 마스킹
      profileId: session.profileId,
      ip: session.ip,
      lastActivity: new Date(session.last).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' }),
      remainingMs: SESSION_TTL_MS - (Date.now() - session.last)
    });
  });
  
  return res.json({
    totalSessions: sessions.length,
    sessions: sessions
  });
});

app.listen(PORT, () => console.log(`✅ 서버가 포트 ${PORT}에서 실행 중입니다`));