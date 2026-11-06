// Render.com версия на WrittenWorkDashboard.gs backend-а (виж пълната
// бележка в gwfe-provisioning/cloud-function/index.js за ПЪЛНАТА история
// защо изобщо съществува - накратко: Apps Script не може да impersonate
// ученик за истинско Classroom "предаване", само service account с
// domain-wide delegation може (същият, който вече ползва inject-control-
// work.js) - тази логика живее тук, извиквана от dashboard-а през HTTP.
//
// ЗАЩО RENDER, А НЕ GOOGLE CLOUD FUNCTIONS - 2026-11-07, по изрично искане
// на потребителя, след като Google Cloud версията заседна на организационна
// политика "Domain Restricted Sharing" (блокира allUsers/публичен достъп),
// а никой наличен акаунт (нито admin@, нито ai.automation@) не се оказа
// Organization Administrator, за да я override-не. Render е ИЗЦЯЛО извън
// Google Cloud - няма такава политика, затова проста споделена тайна
// (X-Shared-Secret) стига като защита, без да ни трябва Google IAM/identity
// token изобщо.
//
// Логиката на handleCreateAssignment/handleSubmitWork е ИДЕНТИЧНА на
// Cloud Functions версията - само обвивката (plain Express сървър вместо
// Cloud Functions handler подпис) е различна.

const express = require('express');
const { google } = require('googleapis');
const { Readable } = require('stream');

const DOMAIN = 'dobri-chintulov-varna.bg';
const ADMIN_EMAIL = 'admin@' + DOMAIN;
const SHARED_SECRET = process.env.SHARED_SECRET;
const key = JSON.parse(process.env.SERVICE_ACCOUNT_KEY_JSON);
const PORT = process.env.PORT || 3000;

function teacherCourseworkAuth(email) {
  return new google.auth.JWT({
    email: key.client_email, key: key.private_key, subject: email,
    scopes: ['https://www.googleapis.com/auth/classroom.coursework.students'],
  });
}

function rosterAuth(email) {
  return new google.auth.JWT({
    email: key.client_email, key: key.private_key, subject: email,
    scopes: ['https://www.googleapis.com/auth/classroom.rosters'],
  });
}

function studentAuth(email) {
  return new google.auth.JWT({
    email: key.client_email, key: key.private_key, subject: email,
    scopes: ['https://www.googleapis.com/auth/classroom.coursework.me', 'https://www.googleapis.com/auth/drive'],
  });
}

// Записва ученика директно в курса (байпас на поканата) - СЪЩАТА логика
// като ensureEnrolled() в inject-control-work.js, пренесена буквално.
async function ensureEnrolled(classroomTeacher, courseId, studentEmail) {
  try {
    await classroomTeacher.courses.students.create({ courseId, requestBody: { userId: studentEmail } });
    return 'записан сега';
  } catch (e) {
    const msg = (e && e.errors && e.errors[0] && e.errors[0].message) || e.message || '';
    if (/already exists|ALREADY_EXISTS/i.test(msg)) return 'вече записан';
    throw e;
  }
}

async function findOwnSubmission(classroom, courseId, courseWorkId) {
  const res = await classroom.courses.courseWork.studentSubmissions.list({ courseId, courseWorkId, userId: 'me' });
  return (res.data.studentSubmissions || [])[0] || null;
}

async function handleCreateAssignment(body) {
  const { teacherEmail, courseId, title, description } = body;
  if (!teacherEmail || !courseId || !title) return { error: 'Липсва teacherEmail/courseId/title.' };
  const classroom = google.classroom({ version: 'v1', auth: teacherCourseworkAuth(teacherEmail) });
  const result = await classroom.courses.courseWork.create({
    courseId,
    requestBody: { title, description: description || undefined, workType: 'ASSIGNMENT', state: 'PUBLISHED' },
  });
  return { ok: true, courseWorkId: result.data.id };
}

// Google API грешките носят полезни детайли в e.errors[] (reason/domain),
// не само e.message - логваме и двете, за да личи ТОЧНО кой API call и
// защо е гръмнал, вместо generic "permission" без контекст.
function describeApiError_(e) {
  const detail = (e && e.errors && e.errors[0]) || {};
  return (e && e.message) + (detail.reason ? ' [reason=' + detail.reason + ', domain=' + detail.domain + ']' : '');
}

async function handleSubmitWork(body) {
  const { courseId, courseWorkId, studentEmail, fileName, mimeType, base64Data, teacherEmail } = body;
  const tag = '[submitWork ' + studentEmail + ' / ' + fileName + ']';
  if (!courseId || !courseWorkId || !studentEmail || !fileName || !base64Data) {
    return { error: 'Липсват задължителни полета за ' + (fileName || studentEmail || '(непознат)') + '.' };
  }

  let enrollNote;
  try {
    const classroomTeacher = google.classroom({ version: 'v1', auth: rosterAuth(teacherEmail || ADMIN_EMAIL) });
    enrollNote = await ensureEnrolled(classroomTeacher, courseId, studentEmail);
    console.log(tag, 'enroll:', enrollNote);
  } catch (e) {
    console.error(tag, 'ГРЕШКА при записване в курса:', describeApiError_(e));
    return { error: 'Грешка при записване в курса: ' + describeApiError_(e) };
  }

  const auth = studentAuth(studentEmail);
  const classroom = google.classroom({ version: 'v1', auth });
  const drive = google.drive({ version: 'v3', auth });

  let submission;
  try {
    // Токущо записаният ученик понякога получава submission записа си със
    // закъснение - изчакваме кратко и препроверяваме (СЪЩАТА логика като в
    // inject-control-work.js).
    submission = await findOwnSubmission(classroom, courseId, courseWorkId);
    if (!submission && enrollNote === 'записан сега') {
      for (let i = 0; i < 3 && !submission; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        submission = await findOwnSubmission(classroom, courseId, courseWorkId);
      }
    }
  } catch (e) {
    console.error(tag, 'ГРЕШКА при четене на submission:', describeApiError_(e));
    return { error: 'Грешка при четене на submission: ' + describeApiError_(e) };
  }
  if (!submission) return { error: 'Няма submission запис за ' + studentEmail + ' (' + enrollNote + ').' };
  if (!['NEW', 'CREATED', 'RECLAIMED_BY_STUDENT'].includes(submission.state)) {
    return { error: 'submission вече е в статус "' + submission.state + '" - пропуснато.' };
  }

  try {
    const buffer = Buffer.from(base64Data, 'base64');
    const uploaded = await drive.files.create({
      requestBody: { name: fileName },
      media: { mimeType: mimeType || 'application/octet-stream', body: Readable.from(buffer) },
      fields: 'id',
    });

    await classroom.courses.courseWork.studentSubmissions.modifyAttachments({
      courseId, courseWorkId, id: submission.id,
      requestBody: { addAttachments: [{ driveFile: { id: uploaded.data.id } }] },
    });
    await classroom.courses.courseWork.studentSubmissions.turnIn({ courseId, courseWorkId, id: submission.id });
  } catch (e) {
    console.error(tag, 'ГРЕШКА при качване/предаване:', describeApiError_(e));
    return { error: 'Грешка при качване/предаване: ' + describeApiError_(e) };
  }

  console.log(tag, 'ПРЕДАДЕНО успешно.');
  return { ok: true, note: enrollNote };
}

const app = express();
app.use(express.json({ limit: '15mb' })); // снимки/PDF-и като base64 могат да са няколко MB

app.get('/', (req, res) => { res.send('writtenWorkBackend е жив.'); }); // здравна проверка за Render

app.post('/', async (req, res) => {
  if (!SHARED_SECRET || req.get('X-Shared-Secret') !== SHARED_SECRET) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  try {
    const body = req.body || {};
    if (body.action === 'createAssignment') { res.json(await handleCreateAssignment(body)); return; }
    if (body.action === 'submitWork') { res.json(await handleSubmitWork(body)); return; }
    res.status(400).json({ error: 'непознато action: ' + body.action });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => { console.log('writtenWorkBackend слуша на порт ' + PORT); });
