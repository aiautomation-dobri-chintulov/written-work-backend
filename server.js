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

// За прикачане на ПРОВЕРЕНИ/оценени копия към ВЕЧЕ предадена работа - СЛЕД
// turnIn() Classroom отнема писателски Drive права на ученика и прави
// учителя собственик, затова тук учителят (не ученикът) качва и прикача -
// пренесено буквално от upload-checked-control-work.js (доказан скрипт).
function teacherDriveAuth(email) {
  return new google.auth.JWT({
    email: key.client_email, key: key.private_key, subject: email,
    scopes: ['https://www.googleapis.com/auth/classroom.coursework.students', 'https://www.googleapis.com/auth/drive'],
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

// Всяко Classroom API извикване с userId=ИМЕЙЛ (studentSubmissions.list,
// ДОРИ courses.students.get) връща "failedPrecondition", когато викащият е
// service account (не истинска потребителска сесия) - документацията
// твърди, че приема имейл, но емпирично (2026-11-07, открито при реален
// тест на редактора за анотиране) това не важи за service account
// impersonation. Единственият НАДЕЖДЕН начин (потвърден директно през API) -
// courses.students.list БЕЗ fields mask (с fields mask имейлът изчезва от
// отговора по непонятна причина) + съвпадение по ПЪЛНО ИМЕ (вече уникално
// проверено при самото съпоставяне на файловете - виж matchStudent_).
async function resolveStudentId_(classroom, courseId, studentName) {
  const res = await classroom.courses.students.list({ courseId });
  const match = (res.data.students || []).find((s) => s.profile && s.profile.name && s.profile.name.fullName === studentName);
  if (!match) throw new Error('Ученикът "' + studentName + '" не е намерен в курса.');
  return match.userId;
}

// Намира (по точно, нечувствително към регистър име) или създава Classroom
// "Тема" (courses.topics) - 2026-11-07, по изрична идея на потребителя
// ("работите могат да са разделени на теми - домашни/контролни/работа в
// клас"): ползваме РОДНАТА Classroom функция "Теми" (същата, която учителят
// вижда в приложението при ръчно създаване на задание), вместо да
// изобретяваме отделна категоризация - остава синхронизирана с това, което
// учителят вижда директно в Classroom. Скоупът classroom.coursework.students
// (вече ползван от teacherCourseworkAuth) покрива courses.topics API-то -
// не е нужен нов service-account scope.
async function resolveTopicId_(classroom, courseId, topicName) {
  const clean = (topicName || '').trim();
  if (!clean) return null;
  const list = await classroom.courses.topics.list({ courseId });
  const existing = (list.data.topic || []).find((t) => t.name && t.name.toLowerCase() === clean.toLowerCase());
  if (existing) return existing.topicId;
  const created = await classroom.courses.topics.create({ courseId, requestBody: { name: clean } });
  return created.data.topicId;
}

async function handleCreateAssignment(body) {
  const { teacherEmail, courseId, title, description, topicName } = body;
  if (!teacherEmail || !courseId || !title) return { error: 'Липсва teacherEmail/courseId/title.' };
  const classroom = google.classroom({ version: 'v1', auth: teacherCourseworkAuth(teacherEmail) });
  let topicId = null;
  try {
    topicId = await resolveTopicId_(classroom, courseId, topicName);
  } catch (e) {
    return { error: 'Грешка при темата "' + topicName + '": ' + describeApiError_(e) };
  }
  const result = await classroom.courses.courseWork.create({
    courseId,
    requestBody: { title, description: description || undefined, workType: 'ASSIGNMENT', state: 'PUBLISHED', topicId: topicId || undefined },
  });
  return { ok: true, courseWorkId: result.data.id, topicId: topicId, topicName: topicId ? (topicName || '').trim() : null };
}

// Връща темите, вече създадени в курса - за падащото меню "Тема" при ново
// задание (free-form избор измежду вече съществуващите, виж резюмето по-горе).
async function handleListTopics(body) {
  const { teacherEmail, courseId } = body;
  if (!teacherEmail || !courseId) return { error: 'Липсва teacherEmail/courseId.' };
  const classroom = google.classroom({ version: 'v1', auth: teacherCourseworkAuth(teacherEmail) });
  const list = await classroom.courses.topics.list({ courseId });
  const topics = (list.data.topic || []).map((t) => ({ topicId: t.topicId, name: t.name }));
  return { ok: true, topics: topics };
}

// Google API грешките носят полезни детайли в e.errors[] (reason/domain),
// не само e.message - логваме и двете, за да личи ТОЧНО кой API call и
// защо е гръмнал, вместо generic "permission" без контекст.
function describeApiError_(e) {
  const detail = (e && e.errors && e.errors[0]) || {};
  return (e && e.message) + (detail.reason ? ' [reason=' + detail.reason + ', domain=' + detail.domain + ']' : '');
}

async function handleSubmitWork(body) {
  const { courseId, courseWorkId, studentEmail, fileName, mimeType, base64Data } = body;
  const tag = '[submitWork ' + studentEmail + ' / ' + fileName + ']';
  if (!courseId || !courseWorkId || !studentEmail || !fileName || !base64Data) {
    return { error: 'Липсват задължителни полета за ' + (fileName || studentEmail || '(непознат)') + '.' };
  }

  let enrollNote;
  try {
    // ВИНАГИ admin@ тук, НЕ учителският имейл - courses.students.create
    // (директно добавяне без покана) изисква домейн-администраторски
    // права, не просто "учител/собственик на курса" - потвърдено емпирично
    // 2026-11-07 (виж inject-control-work.js:282, доказаният скрипт прави
    // точно същото - teacherAuth(ADMIN_EMAIL), никога действителния учител).
    const classroomTeacher = google.classroom({ version: 'v1', auth: rosterAuth(ADMIN_EMAIL) });
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

// Прикачва проверено/оценено копие към ВЕЧЕ turned-in предаване - НЕ пипа
// оригинала/черновите, ученикът вижда и двете. Намира submission по
// ЧИСЛОВИЯ ID на ученика (виж resolveStudentId_ - имейл директно в
// studentSubmissions.list дава "failedPrecondition" за service account).
async function handleAttachGraded(body) {
  const { teacherEmail, courseId, courseWorkId, studentEmail, studentName, fileName, mimeType, base64Data } = body;
  const tag = '[attachGraded ' + studentEmail + ' / ' + fileName + ']';
  if (!teacherEmail || !courseId || !courseWorkId || !studentEmail || !studentName || !fileName || !base64Data) {
    return { error: 'Липсват задължителни полета за ' + (fileName || studentEmail || '(непознат)') + '.' };
  }

  const auth = teacherDriveAuth(teacherEmail);
  const classroom = google.classroom({ version: 'v1', auth });
  const drive = google.drive({ version: 'v3', auth });

  let submission;
  try {
    const studentId = await resolveStudentId_(google.classroom({ version: 'v1', auth: rosterAuth(teacherEmail) }), courseId, studentName);
    const res = await classroom.courses.courseWork.studentSubmissions.list({ courseId, courseWorkId, userId: studentId });
    submission = (res.data.studentSubmissions || [])[0] || null;
  } catch (e) {
    console.error(tag, 'ГРЕШКА при четене на submission:', describeApiError_(e));
    return { error: 'Грешка при четене на submission: ' + describeApiError_(e) };
  }
  if (!submission) return { error: 'Няма предаване за ' + studentEmail + ' в тази задача - ученикът не е предал работа.' };

  let uploaded;
  try {
    const buffer = Buffer.from(base64Data, 'base64');
    uploaded = await drive.files.create({
      requestBody: { name: fileName },
      media: { mimeType: mimeType || 'application/octet-stream', body: Readable.from(buffer) },
      fields: 'id',
    });
    await classroom.courses.courseWork.studentSubmissions.modifyAttachments({
      courseId, courseWorkId, id: submission.id,
      requestBody: { addAttachments: [{ driveFile: { id: uploaded.data.id } }] },
    });
  } catch (e) {
    console.error(tag, 'ГРЕШКА при прикачане:', describeApiError_(e));
    return { error: 'Грешка при прикачане: ' + describeApiError_(e) };
  }

  console.log(tag, 'ПРИКАЧЕНО успешно.');
  return { ok: true, driveFileId: uploaded.data.id };
}

// Изтегля оригинално предадения файл обратно от Classroom (за редактора за
// анотиране - учителят анотира ТОВА, не презаписва нищо) - 2026-11-07, по
// изрично искане на потребителя (Път 3: "учителя директно да анотира
// работата... оригиналната работа трябва да остане непипана"). Чете
// ПЪРВИЯ Drive файл от прикачените в предаването (оригиналът, предаден от
// ученика в Stage 1 - по-късно прикачени проверени копия идват след него).
// Импersonating учителя (СЪЩИЯТ auth като attachGraded - само той има
// право да чете прикаченото след turnIn).
async function handleGetOriginal(body) {
  const { teacherEmail, courseId, courseWorkId, studentEmail, studentName } = body;
  const tag = '[getOriginal ' + studentEmail + ']';
  if (!teacherEmail || !courseId || !courseWorkId || !studentEmail || !studentName) {
    return { error: 'Липсват задължителни полета.' };
  }

  const auth = teacherDriveAuth(teacherEmail);
  const classroom = google.classroom({ version: 'v1', auth });
  const drive = google.drive({ version: 'v3', auth });

  let submission;
  try {
    const studentId = await resolveStudentId_(google.classroom({ version: 'v1', auth: rosterAuth(teacherEmail) }), courseId, studentName);
    const res = await classroom.courses.courseWork.studentSubmissions.list({ courseId, courseWorkId, userId: studentId });
    submission = (res.data.studentSubmissions || [])[0] || null;
  } catch (e) {
    console.error(tag, 'ГРЕШКА при четене на submission:', describeApiError_(e));
    return { error: 'Грешка при четене на submission: ' + describeApiError_(e) };
  }
  if (!submission) return { error: 'Няма предаване за ' + studentEmail + ' в тази задача.' };

  const attachments = (submission.assignmentSubmission && submission.assignmentSubmission.attachments) || [];
  const driveAttachments = attachments.filter((a) => a.driveFile);
  if (driveAttachments.length === 0) return { error: 'Предаването няма прикачени файлове.' };
  // ПОСЛЕДНИЯТ прикачен файл - 2026-11-07, по изрично искане на потребителя
  // ("ще може ли анотирана работа повторно да се анотира"): оригиналът е
  // attachments[0] (от Stage 1), всяко следващо "Запази анотираното копие"
  // (attachGraded) ДОБАВЯ нов файл в края - затова последният елемент е
  // ВИНАГИ най-актуалната версия (оригинал, ако още няма анотации; иначе
  // последното анотирано копие) - учителят продължава откъдето е спрял,
  // вместо винаги да вижда чист оригинал.
  //
  // ПАДАНЕ НАЗАД при счупена връзка - 2026-11-07, по изрично искане на
  // потребителя ("ако изтрия грешно анотирана работа в класрум, ще се
  // отвори ли оригиналната работа"): ако последният файл е изтрит/преместен
  // в кошчето В Drive (без да е detach-нат от Classroom - detach-ването
  // само по себе си вече се вижда коректно, защото просто смалява
  // driveAttachments), опитваме по-ранните прикачвания един по един, до
  // оригинала - учителят никога не остава без работещ файл само защото
  // едно НЕПРАВИЛНО копие е счупено.
  for (let i = driveAttachments.length - 1; i >= 0; i--) {
    const fileId = driveAttachments[i].driveFile.id;
    const isOriginal = i === 0;
    try {
      const meta = await drive.files.get({ fileId, fields: 'name,mimeType,trashed' });
      if (meta.data.trashed) throw new Error('файлът е в кошчето');
      const content = await drive.files.get({ fileId, alt: 'media' }, { responseType: 'arraybuffer' });
      const base64Data = Buffer.from(content.data).toString('base64');
      return { ok: true, fileName: meta.data.name, mimeType: meta.data.mimeType, base64Data, driveFileId: fileId, isOriginal: isOriginal };
    } catch (e) {
      console.error(tag, 'прескачам счупено копие (' + fileId + '):', describeApiError_(e));
      if (i === 0) return { error: 'Грешка при изтегляне на файла: ' + describeApiError_(e) };
      // иначе - продължава към предишното (по-старо) прикачване
    }
  }
}

// Презаписва СЪЩИЯ вече прикачен файл (анотирано копие от предишна сесия) -
// за разлика от handleAttachGraded (който ДОБАВЯ нов файл), тук е просто
// Drive files.update върху известен fileId - не пипа Classroom
// attachments изобщо, защото файлът вече Е прикачен. Предотвратява
// трупане на безкраен брой копия (анотирано-v1, v2, v3...) при всяка нова
// сесия на анотиране - учителят вижда само оригинала + ЕДНО, непрекъснато
// обновявано анотирано копие.
async function handleUpdateAnnotated(body) {
  const { teacherEmail, driveFileId, base64Data, mimeType } = body;
  const tag = '[updateAnnotated ' + driveFileId + ']';
  if (!teacherEmail || !driveFileId || !base64Data) {
    return { error: 'Липсват задължителни полета.' };
  }
  const drive = google.drive({ version: 'v3', auth: teacherDriveAuth(teacherEmail) });
  try {
    const buffer = Buffer.from(base64Data, 'base64');
    await drive.files.update({
      fileId: driveFileId,
      media: { mimeType: mimeType || 'image/png', body: Readable.from(buffer) },
    });
  } catch (e) {
    console.error(tag, 'ГРЕШКА при презаписване:', describeApiError_(e));
    return { error: 'Грешка при презаписване: ' + describeApiError_(e) };
  }
  console.log(tag, 'ПРЕЗАПИСАНО успешно.');
  return { ok: true };
}

// Списък на РЕАЛНИТЕ Classroom задания в курса, групирани по тема - 2026-11-07
// вечерта, ЗАМЕНЯ по-ранния подход (четене на written-work-jobs manifest
// история в Drive, виж handleCheckCourseWorks - премахнат оттук). Открито при
// реален случай: "при домашна работа се показва само 'без тема', има и
// домашна работа за 6б, която изобщо не се показва" - домашните (за разлика
// от писмените/контролните) обикновено се създават ДИРЕКТНО в Classroom от
// учителя, не през този дашборд, затова нямат manifest файл в историята и
// никога не са се появявали в по-ранните падащи менюта (четяха САМО нашата
// история, не самия Classroom). Четенето директно от Classroom API
// (courses.courseWork.list + courses.topics.list) е единственият ВЯРЕН
// източник - показва ВСЯКО задание в курса с РЕАЛНАТА му Classroom тема, и
// елиминира от корен старите проблеми с дублирани/изтрити записи (Classroom
// пази всяко задание точно веднъж - няма нужда от дедупликация/филтриране).
async function handleListCourseWork(body) {
  const { teacherEmail, courseId } = body;
  if (!teacherEmail || !courseId) return { error: 'Липсва teacherEmail/courseId.' };
  const classroom = google.classroom({ version: 'v1', auth: teacherCourseworkAuth(teacherEmail) });
  const [topicsRes, courseWorkRes] = await Promise.all([
    classroom.courses.topics.list({ courseId }),
    classroom.courses.courseWork.list({ courseId, courseWorkStates: ['PUBLISHED'] }),
  ]);
  const topicNameById = {};
  (topicsRes.data.topic || []).forEach((t) => { topicNameById[t.topicId] = t.name; });
  const items = (courseWorkRes.data.courseWork || []).map((cw) => ({
    courseWorkId: cw.id,
    title: cw.title,
    topicId: cw.topicId || null,
    topicName: cw.topicId ? (topicNameById[cw.topicId] || null) : null,
    createdAt: cw.creationTime,
  }));
  items.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  return { ok: true, items: items };
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
    if (body.action === 'listTopics') { res.json(await handleListTopics(body)); return; }
    if (body.action === 'submitWork') { res.json(await handleSubmitWork(body)); return; }
    if (body.action === 'attachGraded') { res.json(await handleAttachGraded(body)); return; }
    if (body.action === 'getOriginal') { res.json(await handleGetOriginal(body)); return; }
    if (body.action === 'listCourseWork') { res.json(await handleListCourseWork(body)); return; }
    if (body.action === 'updateAnnotated') { res.json(await handleUpdateAnnotated(body)); return; }
    res.status(400).json({ error: 'непознато action: ' + body.action });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => { console.log('writtenWorkBackend слуша на порт ' + PORT); });
