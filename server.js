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
const GEMINI_MODEL = 'gemini-2.0-flash';
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
    res.status(400).json({ error: 'непознато action: ' + body.action });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => { console.log('writtenWorkBackend слуша на порт ' + PORT); });
