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
const path = require('path');
const PDFDocument = require('pdfkit');
const sharp = require('sharp');

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
  let resolvedTopicName = null;
  if ((topicName || '').trim()) {
    try {
      topicId = await resolveTopicId_(classroom, courseId, topicName);
      resolvedTopicName = (topicName || '').trim();
    } catch (e) {
      // Темата е "по избор" - 2026-11-07, открито при реален тест
      // ("Insufficient Permission" на courses.topics.* с неизяснена точна
      // причина, въпреки че Classroom API документацията изброява СЪЩИЯ
      // scope като за courseWork.create/list) - не искаме да провалим
      // ЦЯЛОТО създаване на заданието заради проблем само с темата -
      // създаваме БЕЗ тема вместо да спрем всичко.
      console.error('[createAssignment] неуспешно задаване на тема (продължавам без тема):', describeApiError_(e));
    }
  }
  const result = await classroom.courses.courseWork.create({
    courseId,
    requestBody: { title, description: description || undefined, workType: 'ASSIGNMENT', state: 'PUBLISHED', topicId: topicId || undefined },
  });
  return { ok: true, courseWorkId: result.data.id, topicId: topicId, topicName: topicId ? resolvedTopicName : null };
}

// Връща темите, вече създадени в курса - за падащото меню "Тема" при ново
// задание (free-form избор измежду вече съществуващите, виж резюмето по-горе).
// Деградира тихо до празен списък при грешка (виж бележката в
// handleCreateAssignment защо) - учителят пак може да въведе "+ нова тема...",
// просто без списък от съществуващи за избор.
async function handleListTopics(body) {
  const { teacherEmail, courseId } = body;
  if (!teacherEmail || !courseId) return { error: 'Липсва teacherEmail/courseId.' };
  const classroom = google.classroom({ version: 'v1', auth: teacherCourseworkAuth(teacherEmail) });
  try {
    const list = await classroom.courses.topics.list({ courseId });
    const topics = (list.data.topic || []).map((t) => ({ topicId: t.topicId, name: t.name }));
    return { ok: true, topics: topics };
  } catch (e) {
    console.error('[listTopics] неуспешно четене на теми:', describeApiError_(e));
    return { ok: true, topics: [] };
  }
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

  let courseWorkRes;
  try {
    courseWorkRes = await classroom.courses.courseWork.list({ courseId, courseWorkStates: ['PUBLISHED'] });
  } catch (e) {
    return { error: 'Грешка при четене на заданията: ' + describeApiError_(e) };
  }

  // Темите са само за ГРУПИРАНЕ в менюто - 2026-11-07, открито при реален
  // тест ("Insufficient Permission" на courses.topics.list, причината не е
  // напълно изяснена - виж бележката в handleCreateAssignment). Ако тази
  // заявка гръмне, показваме ЗАДАНИЯТА БЕЗ теми (всички в "Без тема"),
  // вместо да провалим ЦЯЛОТО меню заради проблем само с групирането.
  let topicNameById = {};
  try {
    const topicsRes = await classroom.courses.topics.list({ courseId });
    (topicsRes.data.topic || []).forEach((t) => { topicNameById[t.topicId] = t.name; });
  } catch (e) {
    console.error('[listCourseWork] неуспешно четене на теми (продължавам без групиране):', describeApiError_(e));
  }

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

// --- Анализ на домашни работи с AI (Gemini) - "Анализ възложени задачи",
// 2026-11-07. Classroom НЕ носи готов ключ с верни отговори за задачите
// (title/description тук обикновено е само "Снимате и прилагате към
// задачата" - условието идва от учебник/тест извън Classroom) - затова AI
// преценява коректността директно от снимката (условие + решение на
// ученика са на самия лист), а title/description/тема служат само като
// КОНТЕКСТ (предмет/клас/тема), не като сверовъчен ключ.
//
// ПСЕВДОНИМИЗАЦИЯ ПРЕДИ ИЗПРАЩАНЕ КЪМ GEMINI - по изрично решение на
// потребителя, след обсъждане на [[feedback_pseudonymize_external]]: Gemini
// API е ОТДЕЛЕН от Google Workspace for Education data protections (платен
// API ключ, друг договор), затова снимките (ръкописни домашни, може да имат
// име на ученика написано горе на листа) се зачерняват в горната си част
// ПРЕДИ изпращане. Реалната самоличност на ученика идва ОТДЕЛНО, от
// Classroom roster (courses.students.list) по userId от самото предаване -
// Gemini никога не научава кой е ученикът, само вижда зачернена снимка.
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
// gemini-2.0-flash е изтеглен от Google (потвърдено на живо 2026-11-07 -
// грешка "is no longer available" по време на реален тест) - заменен с
// текущия препоръчан наследник.
const GEMINI_MODEL = 'gemini-3.8-flash';
const NAME_BAND_FRACTION = 0.14; // горна част от снимката, зачернява се - там обичайно се пише ръкописно име/клас

// Маскира снимка, която Е ВЕЧЕ малка (Drive thumbnail, виж fetchSubmissionImage_
// по-долу защо не декодираме оригинала) - sharp decode+composite+encode на
// снимка от този размер е безопасно евтино (потвърдено на ръка: <1MB heap
// delta на тестова 1200x900 снимка), за разлика от decode на пълна
// телефонна резолюция (12+ MPx), което на реален тест с цял клас (20+
// ученика) катастрофира Render инстанцията по памет.
async function maskNameBand_(buffer) {
  const meta = await sharp(buffer).metadata();
  const bandHeight = Math.round((meta.height || 900) * NAME_BAND_FRACTION);
  const band = await sharp({
    create: { width: meta.width, height: bandHeight, channels: 3, background: { r: 0, g: 0, b: 0 } },
  }).png().toBuffer();
  return sharp(buffer).composite([{ input: band, top: 0, left: 0 }]).jpeg({ quality: 85 }).toBuffer();
}

// Изтегля ЧЕТИМА за Gemini версия на предадена снимка - 2026-11-07, по
// реален тест на цял клас: (1) студентски снимки от телефон идват ЧЕСТО
// като HEIC (iPhone по подразбиране) - НИТО Jimp, НИТО стандартният sharp
// prebuilt binary (липсва HEVC декодер libde265, патентни причини) могат да
// декодират HEIC съдържание, само метаданните; (2) декодиране на ПЪЛНАТА
// телефонна резолюция (12+ MPx = 40-50MB суров bitmap В ПАМЕТТА за ЕДНА
// снимка) за 20+ ученика с 4-паралелна обработка катастрофира Render
// инстанцията с OOM, потвърдено на живо (502, инстанцията рестартира).
// РЕШЕНИЕ - Google Drive вече генерира JPEG thumbnail за ВСЯКА снимка,
// независимо от оригиналния формат (thumbnailLink, нормално =s220, но
// суфиксът приема произволен размер) - заменя `=s220` с по-голям размер,
// изтегля ГОТОВИЯ JPEG директно (HEIC проблемът изчезва - Drive е свършил
// конверсията вместо нас), малък по дизайн (без риск от OOM). Четливост
// потвърдена на ръка с реална ученическа снимка на 1200px - напълно четим
// ръкописен текст, дори дребен.
async function fetchSubmissionImage_(drive, accessToken, fileId) {
  const meta = await drive.files.get({ fileId, fields: 'trashed,thumbnailLink' });
  if (meta.data.trashed || !meta.data.thumbnailLink) return null;
  const url = meta.data.thumbnailLink.replace(/=s\d+$/, '=s1200');
  const res = await fetch(url, { headers: { Authorization: 'Bearer ' + accessToken } });
  if (!res.ok) throw new Error('thumbnail HTTP ' + res.status);
  return Buffer.from(await res.arrayBuffer());
}

// Прост concurrency pool - 2026-11-07, по реален тест на цял клас: последователна
// (един по един) обработка на ученици е прекалено бавна за синхронна HTTP
// заявка (виж бележката при startAnalyzeHomeworkJob_ за пълната история защо
// изобщо има job/poll модел). Ограничен паралелизъм (не "всички наведнъж") -
// пести и Gemini rate limits, и паметта на Render free tier.
async function withConcurrency_(items, limit, worker) {
  let idx = 0;
  const results = new Array(items.length);
  async function runner() {
    while (idx < items.length) {
      const current = idx++;
      results[current] = await worker(items[current], current);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, runner));
  return results;
}

async function callGemini_(parts, generationConfig) {
  if (!GEMINI_API_KEY) throw new Error('GEMINI_API_KEY не е зададен на Render (Environment variables).');
  const res = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + GEMINI_MODEL + ':generateContent?key=' + GEMINI_API_KEY, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts }], generationConfig: generationConfig || {} }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error((data.error && data.error.message) || ('Gemini грешка ' + res.status));
  const text = data.candidates && data.candidates[0] && data.candidates[0].content.parts[0].text;
  if (!text) throw new Error('Gemini не върна съдържание.');
  return text;
}

const STUDENT_ANALYSIS_SCHEMA = {
  type: 'OBJECT',
  properties: {
    errors: { type: 'ARRAY', items: { type: 'STRING' } },
    summary: { type: 'STRING' },
  },
  required: ['errors', 'summary'],
};

async function analyzeStudentSubmission_(ctx, images) {
  const promptText = 'Ти си учител по "' + ctx.subject + '" в ' + ctx.className + ' клас. ' +
    'Ученик е предал снимки на домашна работа по следната задача:\n' +
    'Заглавие: ' + ctx.title + '\n' +
    (ctx.topicName ? ('Тема: ' + ctx.topicName + '\n') : '') +
    (ctx.description ? ('Указания: ' + ctx.description + '\n') : '') +
    '\nПрегледай снимките (условието на задачата и решението на ученика са на самите снимки) и провери дали решението е вярно. ' +
    'В полето "errors" изброй КОНКРЕТНИ грешки - кратко, по една точка на елемент (ако няма грешки, върни празен списък []). ' +
    'В "summary" напиши 1-2 изречения обща оценка на представянето. Пиши на български.\n' +
    'ВАЖНО: горната част на всяка снимка е умишлено зачернена (скрито е името на ученика) - това НЕ Е част от решението, игнорирай я напълно.';
  const parts = [{ text: promptText }];
  images.forEach((img) => { parts.push({ inlineData: { mimeType: img.mimeType, data: img.base64 } }); });
  const text = await callGemini_(parts, { responseMimeType: 'application/json', responseSchema: STUDENT_ANALYSIS_SCHEMA });
  return JSON.parse(text);
}

// Обобщението за класа е ВТОРО, отделно извикване - само текст (никакви
// снимки, никакви имена - само "Ученик 1/2/3" по РЕДА на обхождане),
// допълнителна предпазна мярка towards [[feedback_pseudonymize_external]].
async function summarizeClassWithGemini_(ctx, results) {
  const analyzed = results.filter((r) => r.submitted && !r.failed);
  if (analyzed.length === 0) return 'Няма достатъчно успешно анализирани предавания за обобщение.';
  const lines = analyzed.map((r, i) => 'Ученик ' + (i + 1) + ': ' + (r.summary || '') + (r.errors.length ? (' Грешки: ' + r.errors.join('; ')) : ' Без грешки.'));
  const promptText = 'По-долу са индивидуални AI оценки на домашна работа по "' + ctx.subject + '", ' + ctx.className + ' клас, ' +
    'задача "' + ctx.title + '"' + (ctx.topicName ? (' (тема: ' + ctx.topicName + ')') : '') + ':\n\n' + lines.join('\n') +
    '\n\nНаправи КРАТКО обобщение за класа (до 120 думи, на български): кои грешки/затруднения се повтарят най-често, ' +
    'обща оценка на представянето, и какво си заслужава да се повтори в час. Не споменавай номерата на учениците поотделно.';
  return callGemini_([{ text: promptText }], {});
}

// DejaVu Sans (пълен TTF файл, НЕ web-subset - виж server.js README/коментар
// при изтеглянето) - вградените в pdfkit стандартни шрифтове (Helvetica и
// т.н.) НЯМАТ кирилски глифи изобщо, потвърдено на ръка преди да се гради
// тази функция (празен/грешен текст без собствен TTF).
const CYRILLIC_FONT_PATH = path.join(__dirname, 'fonts', 'DejaVuSans.ttf');

function buildHomeworkReportPdf_({ subject, className, title, topicName, results, classSummary }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    doc.font(CYRILLIC_FONT_PATH);
    doc.fontSize(18).fillColor('#000').text('Анализ възложени задачи');
    doc.moveDown(0.3);
    doc.fontSize(11).fillColor('#555')
      .text('Предмет: ' + subject + '   Клас: ' + className)
      .text('Задание: ' + title + (topicName ? ('   Тема: ' + topicName) : ''))
      .text('Генерирано на: ' + new Date().toLocaleDateString('bg'));
    doc.fillColor('#000');
    doc.moveDown(1);

    doc.fontSize(14).text('Обобщение за класа');
    doc.moveDown(0.2);
    doc.fontSize(11).text(classSummary || '(няма)');
    doc.moveDown(1);

    const submittedCount = results.filter((r) => r.submitted).length;
    doc.fontSize(14).text('По ученици (' + submittedCount + ' от ' + results.length + ' предадени)');

    results.slice().sort((a, b) => a.name.localeCompare(b.name, 'bg')).forEach((r) => {
      doc.moveDown(0.6);
      doc.fontSize(12).fillColor('#000').text(r.name + (r.late ? ' (закъсняло)' : ''));
      if (!r.submitted) {
        doc.fontSize(10.5).fillColor('#b71c1c').text('Не е предадено.');
      } else if (r.failed) {
        doc.fontSize(10.5).fillColor('#b71c1c').text('Грешка при анализа: ' + r.failReason);
      } else if (r.errors.length === 0) {
        doc.fontSize(10.5).fillColor('#2e7d32').text('Без забелязани грешки. ' + (r.summary || ''));
      } else {
        doc.fontSize(10.5).fillColor('#444').text(r.summary || '');
        r.errors.forEach((e) => doc.fontSize(10.5).fillColor('#b71c1c').text('• ' + e));
      }
      doc.fillColor('#000');
    });

    doc.end();
  });
}

// Job/poll модел ВМЕСТО една синхронна заявка - 2026-11-07, по реален тест
// на цял клас (Математика ИУЧ/6б, 20+ ученика): свалянето+маскирането на
// снимките само по себе си отне над 3 минути на пълна резолюция (оправено
// отделно чрез по-ранен ресайз, виж maskNameBand_), а с реални Gemini
// извиквания отгоре (вместо незабавния 403 без billing) общото време за цял
// клас реалистично минава границите на единична синхронна HTTP заявка
// (Apps Script UrlFetchApp/Render proxy timeout). Решение: 'startHomeworkAnalysis'
// връща jobId ВЕДНАГА (след бързата метаданни проверка), реалната обработка
// тече във фонов async без да се чака, 'getHomeworkAnalysisStatus' се пита
// на интервали от dashboard-а. In-memory Map е достатъчен - еднопотребителски
// вътрешен инструмент, Render процесът остава буден докато обработва.
const analysisJobs = new Map();
const ANALYSIS_CONCURRENCY = 4;

function makeJobId_() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

async function handleStartAnalyzeHomework(body) {
  const { teacherEmail, subject, className, courseId, courseWorkId } = body;
  if (!teacherEmail || !courseId || !courseWorkId) return { error: 'Липсват задължителни данни.' };
  if (!GEMINI_API_KEY) return { error: 'GEMINI_API_KEY не е зададен на Render backend-а (Environment variables) - анализът не може да работи без него.' };

  const classroomWork = google.classroom({ version: 'v1', auth: teacherCourseworkAuth(teacherEmail) });
  const classroomRoster = google.classroom({ version: 'v1', auth: rosterAuth(teacherEmail) });
  const driveAuthClient = teacherDriveAuth(teacherEmail);
  const drive = google.drive({ version: 'v3', auth: driveAuthClient });
  const { token: driveAccessToken } = await driveAuthClient.getAccessToken(); // за директния fetch() на thumbnailLink по-долу - googleapis клиентът не го ползва за суров HTTP

  let courseWork;
  try {
    const res = await classroomWork.courses.courseWork.get({ courseId, id: courseWorkId });
    courseWork = res.data;
  } catch (e) {
    return { error: 'Грешка при четене на заданието: ' + describeApiError_(e) };
  }

  let topicName = '';
  if (courseWork.topicId) {
    try {
      const topicsRes = await classroomWork.courses.topics.list({ courseId });
      const t = (topicsRes.data.topic || []).find((x) => x.topicId === courseWork.topicId);
      topicName = (t && t.name) || '';
    } catch (e) {
      console.error('[analyzeHomework] неуспешно четене на теми (продължавам без тема):', describeApiError_(e));
    }
  }

  let roster;
  try {
    const res = await classroomRoster.courses.students.list({ courseId });
    roster = res.data.students || [];
  } catch (e) {
    return { error: 'Грешка при четене на списъка с ученици: ' + describeApiError_(e) };
  }
  const nameById = {};
  roster.forEach((s) => { nameById[s.userId] = (s.profile && s.profile.name && s.profile.name.fullName) || s.userId; });

  let submissions;
  try {
    const res = await classroomWork.courses.courseWork.studentSubmissions.list({ courseId, courseWorkId });
    submissions = res.data.studentSubmissions || [];
  } catch (e) {
    return { error: 'Грешка при четене на предаванията: ' + describeApiError_(e) };
  }

  const ctx = { subject: subject || '', className: className || '', title: courseWork.title || '', topicName, description: courseWork.description || '' };
  const jobId = makeJobId_();
  analysisJobs.set(jobId, { status: 'running', done: 0, total: submissions.length, createdAt: Date.now() });

  // НЕ се изчаква (umишлено липсва await) - заявката връща jobId веднага,
  // реалната работа продължава във фонов режим, прогресът се пише в analysisJobs.
  (async () => {
    try {
      const results = await withConcurrency_(submissions, ANALYSIS_CONCURRENCY, async (sub) => {
        const name = nameById[sub.userId] || sub.userId;
        const submitted = sub.state === 'TURNED_IN' || sub.state === 'RETURNED';
        let result;
        if (!submitted) {
          result = { name, submitted: false, late: !!sub.late, errors: [] };
        } else {
          const attachments = ((sub.assignmentSubmission || {}).attachments || []).filter((a) => a.driveFile);
          const images = [];
          for (const att of attachments) {
            try {
              const thumbBuffer = await fetchSubmissionImage_(drive, driveAccessToken, att.driveFile.id);
              if (!thumbBuffer) continue; // изтрит файл или Drive няма preview за него (напр. не-изображение)
              const masked = await maskNameBand_(thumbBuffer);
              images.push({ mimeType: 'image/jpeg', base64: masked.toString('base64') });
            } catch (e) {
              console.error('[analyzeHomework] неуспешно изтегляне на прикачен файл ' + att.driveFile.id + ':', describeApiError_(e));
            }
          }
          if (images.length === 0) {
            result = { name, submitted: true, late: !!sub.late, failed: true, failReason: 'няма четими снимки в прикачените файлове', errors: [] };
          } else {
            try {
              const analysis = await analyzeStudentSubmission_(ctx, images);
              result = { name, submitted: true, late: !!sub.late, errors: analysis.errors || [], summary: analysis.summary || '' };
            } catch (e) {
              console.error('[analyzeHomework] Gemini грешка за ' + name + ':', e.message);
              result = { name, submitted: true, late: !!sub.late, failed: true, failReason: e.message, errors: [] };
            }
          }
        }
        const job = analysisJobs.get(jobId);
        if (job) job.done += 1;
        return result;
      });

      let classSummary = '';
      try {
        classSummary = await summarizeClassWithGemini_(ctx, results);
      } catch (e) {
        console.error('[analyzeHomework] неуспешно обобщение за класа:', e.message);
        classSummary = '(неуспешно генериране на обобщение: ' + e.message + ')';
      }

      const pdfBuffer = await buildHomeworkReportPdf_({ subject: subject || '', className: className || '', title: courseWork.title || '', topicName, results, classSummary });
      analysisJobs.set(jobId, {
        status: 'done', done: submissions.length, total: submissions.length,
        fileName: 'Анализ - ' + (courseWork.title || courseWorkId) + '.pdf',
        pdfBase64: pdfBuffer.toString('base64'),
      });
    } catch (e) {
      console.error('[analyzeHomework] job ' + jobId + ' гръмна:', e.message);
      analysisJobs.set(jobId, { status: 'error', error: e.message });
    }
    // почистване след 30 минути - jobId вече ще е изтеглен от dashboard-а
    setTimeout(() => analysisJobs.delete(jobId), 30 * 60 * 1000).unref();
  })();

  return { ok: true, jobId, total: submissions.length };
}

function handleGetAnalyzeHomeworkStatus(body) {
  const job = analysisJobs.get(body.jobId);
  if (!job) return { error: 'Няма такава задача (изтекла или невалидна).' };
  return { ok: true, status: job.status, done: job.done || 0, total: job.total || 0, fileName: job.fileName, pdfBase64: job.pdfBase64, error: job.error };
}

// --- AI проверка с анотация ("Проверени работи" -> AI режим) - 2026-11-07,
// по изрично искане на потребителя: вместо само текстов анализ, AI да
// ОЦЕНИ всяка задача по отпечатаните точки, да маркира (✓/✗/▲ + X/Y т.)
// ДИРЕКТНО върху снимката на точното място на решението, и учителят да
// прегледа/качи резултата в Classroom (НЕ автоматично - виж бележката при
// handleConfirmUploadGradedWork).
//
// РИСК, признат изрично пред потребителя преди да се гради: за разлика от
// дигитално генериран PDF (известни координати), тук Gemini трябва да
// "познае" нормализирани bounding box координати (0-1000) на снимка от
// телефон с произволен ъгъл/изрязване - НЕ Е жив тествано (Gemini billing
// беше изчерпан по време на изграждането, потребителят избра "продължи без
// тест"). Механиката на РИСУВАНЕ е потвърдена на ръка (sharp SVG composite,
// виж теста с фиктивни кутии върху реална снимка - маркировките се
// изчертаха коректно). Точността на САМИТЕ координати от Gemini остава за
// проверка при първо живо пускане - ако се окаже системно неточна, лесно
// се сваля до по-надежден "печат" (общ резултат в ъгъла, без opit за
// позициониране по задача).
const gradeJobs = new Map();
const GRADE_CONCURRENCY = 3; // по-нисък от анализа (4) - всяка страница е 2 Gemini извиквания (grading) + повече sharp обработка (overlay)

const GRADE_TASK_SCHEMA = {
  type: 'OBJECT',
  properties: {
    tasks: {
      type: 'ARRAY',
      items: {
        type: 'OBJECT',
        properties: {
          taskNumber: { type: 'STRING' },
          maxPoints: { type: 'NUMBER' },
          awardedPoints: { type: 'NUMBER' },
          note: { type: 'STRING' },
          box: { type: 'ARRAY', items: { type: 'NUMBER' } },
        },
        required: ['taskNumber', 'maxPoints', 'awardedPoints', 'box'],
      },
    },
    gradeScaleText: { type: 'STRING' },
    // "Получени точки" РЕД на обобщителната таблица (Задача 1 2 3... Общо) -
    // ЕДНА кутия за целия ред, не по кутия на клетка (твърде рисковано да
    // познае 9 отделни клетки точно) - ние после делим на равни колони по
    // брой задачи, виж drawSummaryTable_. null, ако страницата няма такава
    // таблица (типично - ако отговорите са на друга страница от решението).
    summaryPointsRowBox: { type: 'ARRAY', items: { type: 'NUMBER' } },
    // Празния ред "Оценка: ______" (само реда, не цялата таблица).
    summaryGradeBox: { type: 'ARRAY', items: { type: 'NUMBER' } },
  },
  required: ['tasks'],
};

// Проверява ЕДНА страница - връща точки+бележка+bounding box за всяка
// отпечатана задача на тази страница (bounding box = мястото на РЕШЕНИЕТО
// на ученика, не на отпечатаното условие, за да сложим маркировката до
// неговия отговор). gradeScaleText - ако на тази страница има отпечатана
// таблица "точки -> оценка", преписва я като свободен текст (за показване
// на учителя, не за автоматично парсене - различните тестове форматират
// скалата различно).
async function gradeImageWithGemini_(ctx, imageBase64) {
  const promptText = 'Ти си учител по "' + ctx.subject + '" в ' + ctx.className + ' клас, проверяваш писмена/контролна работа. ' +
    'На снимката има ОТПЕЧАТАНИ задачи, всяка с посочен максимален брой точки до условието (напр. "2 т.", "4 т."), и РЪКОПИСНО решение на ученика.\n\n' +
    'За ВСЯКА отпечатана задача на СТРАНИЦАТА:\n' +
    '1. Номер на задачата точно както е отпечатан (напр. "1", "4а", "7").\n' +
    '2. Максимален брой точки - прочети го от отпечатаното "N т." до условието.\n' +
    '3. Прецени ръкописното решение на ученика и присъди точки от 0 до максимума (може и половин точки), според това колко е вярно/пълно.\n' +
    '4. Ако НЕ е присъдена пълната оценка, кратка бележка (до 10 думи) защо.\n' +
    '5. "box" - нормализирани координати [y_min, x_min, y_max, x_max] в скала 0-1000 спрямо ЦЯЛОТО изображение, сочещи мястото на РЪКОПИСНИЯ ОТГОВОР на ученика за тази задача (не отпечатаното условие).\n\n' +
    'Ако в долната част на страницата има таблица, превръщаща общ брой точки в оценка (напр. "0-8 Слаб2, 9-14 Среден3..."), препиши я като свободен текст в "gradeScaleText".\n' +
    'Ако на страницата има обобщителна таблица с редове "Задача / Максимум точки / Получени точки" (празен ред "Получени точки" за попълване) - посочи "summaryPointsRowBox": нормализирани координати [y_min, x_min, y_max, x_max] на ЦЕЛИЯ празен ред "Получени точки" (от първата до последната клетка на реда, включително клетката "Общо"), НЕ на отделна клетка.\n' +
    'Ако има отделен празен ред/поле "Оценка: ______" за попълване - посочи "summaryGradeBox": нормализирани координати само на празното място след "Оценка:".\n' +
    'Ако задача няма решение изобщо (празно поле), присъди 0 точки и отбележи "няма решение".\n' +
    'Пиши бележките на български.';
  const text = await callGemini_(
    [{ text: promptText }, { inlineData: { mimeType: 'image/jpeg', data: imageBase64 } }],
    { responseMimeType: 'application/json', responseSchema: GRADE_TASK_SCHEMA }
  );
  return JSON.parse(text);
}

// Рисува маркировките (✓ зелено/✗ червено/▲ оранжево + "X/Y") ДИРЕКТНО
// върху снимката, на мястото, посочено от Gemini - sharp SVG composite,
// потвърдено на ръка с фиктивни координати преди да се вгради тук (виж
// бележката по-горе). Работи върху НЕМАСКИРАНАТА снимка (тази, която
// реално отива в Classroom - за разлика от writtenWork-анализа, тук НЯМА
// нужда от псевдонимизация на изхода, само на входа към Gemini, виж
// handleStartGradeWork).
async function drawGradingOverlay_(imageBuffer, tasks) {
  const meta = await sharp(imageBuffer).metadata();
  const W = meta.width, H = meta.height;
  const toPx = (box) => ({
    y0: Math.round((box[0] / 1000) * H), x0: Math.round((box[1] / 1000) * W),
    y1: Math.round((box[2] / 1000) * H), x1: Math.round((box[3] / 1000) * W),
  });
  const esc = (s) => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;');
  const marks = (tasks || []).map((t) => {
    if (!Array.isArray(t.box) || t.box.length !== 4) return '';
    const p = toPx(t.box);
    const full = t.awardedPoints >= t.maxPoints;
    const zero = t.awardedPoints <= 0;
    const color = full ? '#2e7d32' : zero ? '#c62828' : '#e65100';
    const symbol = full ? '✓' : zero ? '✗' : '▲';
    const cx = p.x1 + 14, cy = p.y0 + 4;
    return '<g>' +
      '<circle cx="' + cx + '" cy="' + cy + '" r="16" fill="white" stroke="' + color + '" stroke-width="2.5" />' +
      '<text x="' + cx + '" y="' + (cy + 7) + '" font-size="20" font-weight="bold" fill="' + color + '" text-anchor="middle">' + symbol + '</text>' +
      '<text x="' + (cx + 22) + '" y="' + (cy + 6) + '" font-size="15" font-weight="bold" fill="' + color + '">' + esc(t.awardedPoints) + '/' + esc(t.maxPoints) + '</text>' +
      (t.note ? '<text x="' + (cx + 22) + '" y="' + (cy + 24) + '" font-size="11" fill="' + color + '">' + esc(t.note).slice(0, 40) + '</text>' : '') +
      '</g>';
  }).join('\n');
  const svg = '<svg width="' + W + '" height="' + H + '" xmlns="http://www.w3.org/2000/svg">' + marks + '</svg>';
  return sharp(imageBuffer).composite([{ input: Buffer.from(svg), top: 0, left: 0 }]).jpeg({ quality: 90 }).toBuffer();
}

// Добавя обобщителен "печат" (общо точки + оценка) в горния десен ъгъл -
// FALLBACK, само когато НИТО една страница не показа печатна таблица
// "Получени точки"/"Оценка" (drawSummaryTable_ по-долу не е приложимо) - по-
// надеждно от опит да се познае таблица, която не съществува на снимката.
async function drawSummaryStamp_(imageBuffer, totalAwarded, maxTotal, gradeLabel) {
  const meta = await sharp(imageBuffer).metadata();
  const W = meta.width;
  const text = totalAwarded + ' / ' + maxTotal + (gradeLabel ? ('  (' + gradeLabel + ')') : '');
  const boxW = Math.min(W - 20, 40 + text.length * 11);
  const svg = '<svg width="' + W + '" height="60" xmlns="http://www.w3.org/2000/svg">' +
    '<rect x="' + (W - boxW - 10) + '" y="8" width="' + boxW + '" height="40" rx="6" fill="white" stroke="#1a3a5c" stroke-width="2" />' +
    '<text x="' + (W - boxW + 10) + '" y="34" font-size="22" font-weight="bold" fill="#1a3a5c">' + text.replace(/&/g, '&amp;').replace(/</g, '&lt;') + '</text>' +
    '</svg>';
  return sharp(imageBuffer).composite([{ input: Buffer.from(svg), top: 0, left: 0 }]).jpeg({ quality: 90 }).toBuffer();
}

// Попълва ДИРЕКТНО печатната таблица "Получени точки"/"Оценка" на листа -
// 2026-11-07, по изрично искане на потребителя (показа реален пример на
// ръчно анотирана работа - учителят пише точките В самите клетки на
// таблицата, не отделен печат). pointsRowBox е КУТИЯТА НА ЦЕЛИЯ ред
// (поискано от Gemini заради риска да познае 9 отделни клетки поотделно) -
// тук се дели програмно на равни колони по БРОЯ ЗАДАЧИ + 1 (за "Общо"),
// което е надеждно само ако таблицата има еднакви по широчина колони
// (потвърдено на реалните тестове, виж примера на потребителя) - ако
// бъдещ тест има различен формат, най-лошото е леко разминати цифри, не
// грешни стойности.
async function drawSummaryTable_(imageBuffer, tasksOrdered, totalAwarded, maxTotal, pointsRowBox, gradeBox, gradeLabel) {
  const meta = await sharp(imageBuffer).metadata();
  const W = meta.width, H = meta.height;
  const toPx = (box) => ({
    y0: Math.round((box[0] / 1000) * H), x0: Math.round((box[1] / 1000) * W),
    y1: Math.round((box[2] / 1000) * H), x1: Math.round((box[3] / 1000) * W),
  });
  const fmt = (n) => (Math.round(n * 10) / 10).toString();
  let parts = '';

  if (Array.isArray(pointsRowBox) && pointsRowBox.length === 4 && tasksOrdered.length > 0) {
    const p = toPx(pointsRowBox);
    const cols = tasksOrdered.length + 1; // +1 за "Общо"
    const colW = (p.x1 - p.x0) / cols;
    const cy = Math.round((p.y0 + p.y1) / 2) + 6;
    const fontSize = Math.max(12, Math.min(22, Math.round((p.y1 - p.y0) * 0.6)));
    tasksOrdered.forEach((t, i) => {
      const cx = Math.round(p.x0 + colW * (i + 0.5));
      parts += '<text x="' + cx + '" y="' + cy + '" font-size="' + fontSize + '" font-weight="bold" fill="#c62828" text-anchor="middle">' + fmt(t.awardedPoints) + '</text>';
    });
    const cxTotal = Math.round(p.x0 + colW * (cols - 0.5));
    parts += '<text x="' + cxTotal + '" y="' + cy + '" font-size="' + fontSize + '" font-weight="bold" fill="#c62828" text-anchor="middle">' + fmt(totalAwarded) + '</text>';
  }

  if (Array.isArray(gradeBox) && gradeBox.length === 4 && gradeLabel) {
    const p = toPx(gradeBox);
    const fontSize = Math.max(14, Math.min(24, Math.round((p.y1 - p.y0) * 0.75)));
    const cy = Math.round((p.y0 + p.y1) / 2) + Math.round(fontSize * 0.35);
    parts += '<text x="' + (p.x0 + 4) + '" y="' + cy + '" font-size="' + fontSize + '" font-weight="bold" fill="#c62828">' + gradeLabel.replace(/&/g, '&amp;').replace(/</g, '&lt;') + '</text>';
  }

  if (!parts) return imageBuffer;
  const svg = '<svg width="' + W + '" height="' + H + '" xmlns="http://www.w3.org/2000/svg">' + parts + '</svg>';
  return sharp(imageBuffer).composite([{ input: Buffer.from(svg), top: 0, left: 0 }]).jpeg({ quality: 90 }).toBuffer();
}

// Пресмята "Име (Число)" (напр. "Среден (3)") от свободния текст на
// отпечатаната скала - 2026-11-07, по изрично искане на потребителя (реален
// пример показа точно този формат, ръчно написан от учител). Regex търси
// повтарящи се "мин – макс Име Число" групи; връща ПЪРВОТО съвпадение, в
// чийто диапазон (вкл. границите) пада totalAwarded. Връща null при
// непарсируем текст - по-добре празно поле, отколкото грешно познат номер.
function parseGradeScaleLabel_(scaleText, totalAwarded) {
  if (!scaleText) return null;
  const re = /(\d+(?:[.,]\d+)?)\s*[-–—]\s*(\d+(?:[.,]\d+)?)\s*([^\d,;]+?)\s*(\d)(?=\s|[,;]|$)/gu;
  let m;
  while ((m = re.exec(scaleText)) !== null) {
    const lo = parseFloat(m[1].replace(',', '.')), hi = parseFloat(m[2].replace(',', '.'));
    if (totalAwarded >= lo && totalAwarded <= hi) {
      return m[3].trim() + ' (' + m[4] + ')';
    }
  }
  return null;
}

function makeGradeJobId_() { return 'g' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }

async function handleStartGradeWork(body) {
  const { teacherEmail, subject, className, courseId, courseWorkId } = body;
  if (!teacherEmail || !courseId || !courseWorkId) return { error: 'Липсват задължителни данни.' };
  if (!GEMINI_API_KEY) return { error: 'GEMINI_API_KEY не е зададен на Render backend-а.' };

  const classroomWork = google.classroom({ version: 'v1', auth: teacherCourseworkAuth(teacherEmail) });
  const classroomRoster = google.classroom({ version: 'v1', auth: rosterAuth(teacherEmail) });
  const driveAuthClient = teacherDriveAuth(teacherEmail);
  const drive = google.drive({ version: 'v3', auth: driveAuthClient });
  const { token: driveAccessToken } = await driveAuthClient.getAccessToken();

  let roster;
  try {
    const res = await classroomRoster.courses.students.list({ courseId });
    roster = res.data.students || [];
  } catch (e) {
    return { error: 'Грешка при четене на списъка с ученици: ' + describeApiError_(e) };
  }
  const nameById = {};
  roster.forEach((s) => {
    nameById[s.userId] = (s.profile && s.profile.name && s.profile.name.fullName) || s.userId;
  });

  let submissions;
  try {
    const res = await classroomWork.courses.courseWork.studentSubmissions.list({ courseId, courseWorkId });
    submissions = (res.data.studentSubmissions || []).filter((s) => s.state === 'TURNED_IN' || s.state === 'RETURNED');
  } catch (e) {
    return { error: 'Грешка при четене на предаванията: ' + describeApiError_(e) };
  }

  const ctx = { subject: subject || '', className: className || '' };
  const jobId = makeGradeJobId_();
  gradeJobs.set(jobId, { status: 'running', done: 0, total: submissions.length, createdAt: Date.now(), teacherEmail, courseId, courseWorkId, results: [] });

  (async () => {
    try {
      const results = await withConcurrency_(submissions, GRADE_CONCURRENCY, async (sub) => {
        const name = nameById[sub.userId] || sub.userId;
        const attachments = ((sub.assignmentSubmission || {}).attachments || []).filter((a) => a.driveFile);

        // Етап 1 - събира grading резултат за ВСЯКА страница ПРЕДИ да
        // рисуваме каквото и да е - таблицата "Получени точки" (ако я има)
        // трябва общия сбор от ВСИЧКИ страници, не само от своята собствена
        // (виж бележката при GRADE_TASK_SCHEMA: в реалните тестове отговорите
        // са на стр.1, таблицата - на стр.2).
        const pageData = [];
        let totalAwarded = 0, maxTotal = 0, gradeScaleText = '';
        const allTasksOrdered = [];
        for (const att of attachments) {
          try {
            const unmaskedBuf = await fetchSubmissionImage_(drive, driveAccessToken, att.driveFile.id);
            if (!unmaskedBuf) continue;
            const masked = await maskNameBand_(unmaskedBuf);
            const grading = await gradeImageWithGemini_(ctx, masked.toString('base64'));
            (grading.tasks || []).forEach((t) => {
              totalAwarded += Number(t.awardedPoints) || 0;
              maxTotal += Number(t.maxPoints) || 0;
              allTasksOrdered.push(t);
            });
            if (grading.gradeScaleText) gradeScaleText = grading.gradeScaleText;
            pageData.push({ unmaskedBuf, grading });
          } catch (e) {
            console.error('[gradeWork] грешка на страница за ' + name + ':', e.message);
            pageData.push({ error: e.message });
          }
        }
        const gradeLabel = parseGradeScaleLabel_(gradeScaleText, totalAwarded);

        // Етап 2 - вече знаем общия сбор, рисуваме: маркировка по задача на
        // всяка страница + попълване на печатната таблица (ако е открита на
        // която и да е страница).
        const pages = [];
        let summaryDrawn = false;
        for (const pd of pageData) {
          if (pd.error) { pages.push({ fileName: 'стр-' + (pages.length + 1) + '.jpg', error: pd.error }); continue; }
          try {
            let buf = await drawGradingOverlay_(pd.unmaskedBuf, pd.grading.tasks || []);
            if (pd.grading.summaryPointsRowBox || pd.grading.summaryGradeBox) {
              buf = await drawSummaryTable_(buf, allTasksOrdered, totalAwarded, maxTotal, pd.grading.summaryPointsRowBox, pd.grading.summaryGradeBox, gradeLabel);
              summaryDrawn = true;
            }
            pages.push({ fileName: 'стр-' + (pages.length + 1) + '.jpg', buffer: buf, tasks: pd.grading.tasks || [] });
          } catch (e) {
            console.error('[gradeWork] грешка при рисуване за ' + name + ':', e.message);
            pages.push({ fileName: 'стр-' + (pages.length + 1) + '.jpg', error: e.message });
          }
        }
        // Fallback - НИТО една страница няма печатна таблица (различен
        // формат на теста) - общ печат в ъгъла на последната успешна страница,
        // поне резултатът да се вижда някъде.
        if (!summaryDrawn) {
          for (let i = pages.length - 1; i >= 0; i--) {
            if (!pages[i].buffer) continue;
            try { pages[i].buffer = await drawSummaryStamp_(pages[i].buffer, totalAwarded, maxTotal, gradeLabel); } catch (e) { /* не е фатално */ }
            break;
          }
        }

        const job = gradeJobs.get(jobId);
        if (job) job.done += 1;
        return { name, userId: sub.userId, totalAwarded, maxTotal, gradeScaleText, gradeLabel, pages, uploaded: false };
      });

      const job = gradeJobs.get(jobId);
      if (job) { job.results = results; job.status = 'done'; }
    } catch (e) {
      console.error('[gradeWork] job ' + jobId + ' гръмна:', e.message);
      gradeJobs.set(jobId, { status: 'error', error: e.message });
    }
    setTimeout(() => gradeJobs.delete(jobId), 30 * 60 * 1000).unref();
  })();

  return { ok: true, jobId, total: submissions.length };
}

function handleGetGradeWorkStatus(body) {
  const job = gradeJobs.get(body.jobId);
  if (!job) return { error: 'Няма такава задача (изтекла или невалидна).' };
  return { ok: true, status: job.status, done: job.done || 0, total: job.total || 0, error: job.error };
}

// Връща ЛЕКА преглед-версия (малки, компресирани снимки, само ПЪРВАТА
// страница на всеки ученик) - пълните страници се теглят поотделно при
// нужда (getGradeWorkPage), за да не блъскаме google.script.run лимита за
// размер на еднократен отговор с 20+ пълноразмерни анотирани снимки накуп.
async function handleListGradeWorkResults(body) {
  const job = gradeJobs.get(body.jobId);
  if (!job) return { error: 'Няма такава задача (изтекла или невалидна).' };
  if (job.status !== 'done') return { error: 'Задачата още не е готова (статус: ' + job.status + ').' };
  const students = await Promise.all((job.results || []).map(async (r) => {
    let previewBase64 = null;
    const firstOkPage = (r.pages || []).find((p) => p.buffer);
    if (firstOkPage) {
      try {
        const small = await sharp(firstOkPage.buffer).resize({ width: 500, withoutEnlargement: true }).jpeg({ quality: 70 }).toBuffer();
        previewBase64 = small.toString('base64');
      } catch (e) { /* без преглед, не е фатално */ }
    }
    return {
      userId: r.userId, name: r.name, totalAwarded: r.totalAwarded, maxTotal: r.maxTotal,
      gradeScaleText: r.gradeScaleText, gradeLabel: r.gradeLabel, pageCount: (r.pages || []).length, uploaded: !!r.uploaded, previewBase64,
    };
  }));
  return { ok: true, students };
}

function handleGetGradeWorkPage(body) {
  const job = gradeJobs.get(body.jobId);
  if (!job) return { error: 'Няма такава задача (изтекла или невалидна).' };
  const r = (job.results || []).find((x) => x.userId === body.userId);
  if (!r) return { error: 'Няма резултат за този ученик.' };
  const page = (r.pages || [])[body.pageIndex || 0];
  if (!page) return { error: 'Няма такава страница.' };
  if (!page.buffer) return { error: page.error ? ('Грешка при тази страница: ' + page.error) : 'Няма такава страница.' };
  return { ok: true, base64: page.buffer.toString('base64'), pageCount: r.pages.length };
}

// Качва ВСИЧКИ анотирани страници на ЕДИН ученик в Classroom - учителят е
// прегледал преди това (виж 'Учителят преглежда преди изпращане' избора
// при изграждането - AI НИКОГА не качва само̀ без този бутон). Преизползва
// СЪЩАТА Drive+Classroom логика като handleAttachGraded (ръчното качване),
// само източникът на байтовете е кешираната AI-анотирана снимка, не файл
// от диска на учителя. Идентифицира ученика по НУМЕРИЧНИЯ userId, вече
// наличен от самото предаване (studentSubmissions.list) - НЕ по email
// (Classroom roster API емпирично НЕ връща profile.emailAddress за този
// домейн/service account, потвърдено на живо 2026-11-07) и НЕ по name-match
// (resolveStudentId_ съществува за друг случай - тук userId вече го имаме).
async function handleConfirmUploadGradedWork(body) {
  const job = gradeJobs.get(body.jobId);
  if (!job) return { error: 'Няма такава задача (изтекла или невалидна).' };
  const r = (job.results || []).find((x) => x.userId === body.userId);
  if (!r) return { error: 'Няма резултат за този ученик.' };

  const auth = teacherDriveAuth(job.teacherEmail);
  const classroom = google.classroom({ version: 'v1', auth });
  const drive = google.drive({ version: 'v3', auth });

  let submission;
  try {
    const res = await classroom.courses.courseWork.studentSubmissions.list({ courseId: job.courseId, courseWorkId: job.courseWorkId, userId: r.userId });
    submission = (res.data.studentSubmissions || [])[0] || null;
  } catch (e) {
    return { error: 'Грешка при четене на submission: ' + describeApiError_(e) };
  }
  if (!submission) return { error: 'Няма предаване за ' + r.name + '.' };

  const okPages = (r.pages || []).filter((p) => p.buffer);
  if (okPages.length === 0) return { error: 'Няма успешно анотирани страници за ' + r.name + '.' };

  try {
    for (const page of okPages) {
      const uploaded = await drive.files.create({
        requestBody: { name: 'AI проверка - ' + page.fileName },
        media: { mimeType: 'image/jpeg', body: Readable.from(page.buffer) },
        fields: 'id',
      });
      await classroom.courses.courseWork.studentSubmissions.modifyAttachments({
        courseId: job.courseId, courseWorkId: job.courseWorkId, id: submission.id,
        requestBody: { addAttachments: [{ driveFile: { id: uploaded.data.id } }] },
      });
    }
  } catch (e) {
    console.error('[confirmUploadGradedWork]', r.name, describeApiError_(e));
    return { error: 'Грешка при качване: ' + describeApiError_(e) };
  }

  r.uploaded = true;
  return { ok: true, note: 'Качени ' + okPages.length + ' страница(и) за ' + r.name + '.' };
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
    if (body.action === 'startHomeworkAnalysis') { res.json(await handleStartAnalyzeHomework(body)); return; }
    if (body.action === 'getHomeworkAnalysisStatus') { res.json(handleGetAnalyzeHomeworkStatus(body)); return; }
    if (body.action === 'startGradeWork') { res.json(await handleStartGradeWork(body)); return; }
    if (body.action === 'getGradeWorkStatus') { res.json(handleGetGradeWorkStatus(body)); return; }
    if (body.action === 'listGradeWorkResults') { res.json(await handleListGradeWorkResults(body)); return; }
    if (body.action === 'getGradeWorkPage') { res.json(handleGetGradeWorkPage(body)); return; }
    if (body.action === 'confirmUploadGradedWork') { res.json(await handleConfirmUploadGradedWork(body)); return; }
    res.status(400).json({ error: 'непознато action: ' + body.action });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => { console.log('writtenWorkBackend слуша на порт ' + PORT); });
