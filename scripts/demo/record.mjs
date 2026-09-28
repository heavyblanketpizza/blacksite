// Record a genuine local-model investigation through the Blacksite UI.
// serve.py supplies synthetic inputs and disposable accounts; it does not mock inference.
// No subtitles, voiceover, title cards, or changes to application source.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const runtime = process.env.BLACKSITE_NODE_MODULES || path.join(os.homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules');
process.env.PLAYWRIGHT_BROWSERS_PATH ||= '/private/tmp/blacksite-video-runtime';
const { chromium } = require(path.join(runtime, 'playwright'));
const work = process.env.BLACKSITE_VIDEO_WORK_DIR;
if (!work) throw new Error('Set BLACKSITE_VIDEO_WORK_DIR to an ignored capture directory under var/video-real/.');
const resume = process.argv.includes('--resume');
const timeoutMs = Number(process.env.BLACKSITE_INVESTIGATION_TIMEOUT_MS || 45 * 60 * 1000);
if (!Number.isFinite(timeoutMs) || timeoutMs < 1000) throw new Error('Invalid investigation timeout.');
const credentialsPath = process.argv[2];
if (!credentialsPath) throw new Error('Pass the temporary synthetic credentials JSON path.');
const demo = JSON.parse(fs.readFileSync(credentialsPath, 'utf8'));
const base = demo.url || 'http://127.0.0.1:18768';
const username = demo.username || demo.admin?.username || 'demo';
const password = demo.password || demo.admin?.password;
const secret = demo.totp_secret || demo.secret || demo.admin?.totp_secret;
if (!password || !demo.synthetic) throw new Error('Disposable synthetic demo credentials are required.');
const out = path.join(work, 'capture');
const qa = path.join(work, 'qa');
if (fs.existsSync(path.join(out, 'flow.webm'))) {
  throw new Error('This capture already has flow.webm. Choose a new BLACKSITE_VIDEO_WORK_DIR, including when using --resume.');
}
fs.mkdirSync(out, {recursive: true});
fs.mkdirSync(qa, {recursive: true});

function totp(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bits = [...base32.replace(/=|\s/g, '').toUpperCase()].map(c => alphabet.indexOf(c).toString(2).padStart(5, '0')).join('');
  const bytes = Buffer.from((bits.match(/.{8}/g) || []).map(b => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = crypto.createHmac('sha1', bytes).update(counter).digest();
  const offset = digest[19] & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.BLACKSITE_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  args: ['--force-device-scale-factor=1'],
});
const context = await browser.newContext({
  viewport: {width: 1920, height: 1080},
  recordVideo: {dir: out, size: {width: 1920, height: 1080}},
  locale: 'en-US', timezoneId: 'UTC', colorScheme: 'dark',
  acceptDownloads: true,
});
await context.route('**/*', route => {
  const url = new URL(route.request().url());
  return ['127.0.0.1', 'localhost'].includes(url.hostname) || ['data:', 'blob:'].includes(url.protocol) ? route.continue() : route.abort();
});
await context.addInitScript(() => {
  localStorage.setItem('blacksite.lang', 'en');
  localStorage.setItem('blacksite.theme', 'dark');
  // Make the real pointer visible in a headless browser recording.
  addEventListener('DOMContentLoaded', () => {
    const pointer = document.createElement('div');
    pointer.id = 'demo-recording-pointer';
    pointer.style.cssText = 'position:fixed;left:0;top:0;width:29px;height:35px;pointer-events:none;z-index:2147483647;display:none;filter:drop-shadow(0 2px 3px #0008)';
    pointer.innerHTML = '<svg width="29" height="35" viewBox="0 0 29 35"><path d="M3 2 L3 27 L9 21 L14 32 L19 30 L14 19 L24 19 Z" fill="white" stroke="#172033" stroke-width="1.8" stroke-linejoin="round"/></svg>';
    document.body.append(pointer);
    addEventListener('mousemove', event => {
      pointer.style.display = 'block';
      pointer.style.transform = `translate(${event.clientX - 3}px,${event.clientY - 2}px)`;
    }, true);
    addEventListener('mousedown', event => {
      const ring = document.createElement('div');
      ring.style.cssText = `position:fixed;left:${event.clientX - 18}px;top:${event.clientY - 18}px;width:36px;height:36px;border-radius:50%;border:2px solid #9badff;background:#7b94ff25;z-index:2147483646;pointer-events:none;box-sizing:border-box`;
      document.body.append(ring);
      ring.animate([{transform:'scale(.45)',opacity:1},{transform:'scale(1.35)',opacity:0}], {duration:650,easing:'ease-out'}).finished.then(()=>ring.remove());
    }, true);
  });
});

const page = await context.newPage();
const errors = [];
page.on('pageerror', error => errors.push(error.message));
const marks = [];
const start = Date.now();
const pause = ms => page.waitForTimeout(ms);
let last = {x: 1680, y: 935};
const metadata = {
  width:1920, height:1080, language:'en', subtitle:false, voiceover:false, music:false,
  source:'Actual Blacksite UI and local Ollama inference, using synthetic incident logs and disposable demo accounts. No model responses, investigation events, or generated guides are scripted.',
  mode:resume ? 'resume-existing-investigation' : 'new-investigation',
  started_at:new Date(start).toISOString(), status:'recording', marks, errors, progress:[],
};

function saveMetadata() {
  metadata.duration_seconds = +((Date.now() - start) / 1000).toFixed(2);
  fs.writeFileSync(path.join(work, 'capture-metadata.json'), JSON.stringify(metadata, null, 2)+'\n');
}
saveMetadata();

async function mark(name, screenshot = true) {
  marks.push({name, seconds: +((Date.now() - start) / 1000).toFixed(2)});
  console.log(`${marks.at(-1).seconds}s ${name}`);
  saveMetadata();
  if (screenshot) await page.screenshot({path: path.join(qa, `${String(marks.length).padStart(2,'0')}-${name}.png`)});
}
async function moveTo(locator, delay = 550) {
  await locator.waitFor({state:'visible', timeout:15000});
  const initial = await locator.boundingBox();
  if (!initial || initial.y < 64 || initial.y + initial.height > 1030) {
    await locator.evaluate(el => el.scrollIntoView({block:'center', behavior:'smooth'}));
    await pause(900);
  }
  const box = await locator.boundingBox();
  if (!box) throw new Error('No target bounds');
  const target = {x:box.x + box.width/2,y:box.y + box.height/2};
  const initialPointer = {...last};
  for (let i=1;i<=28;i++) {
    const t=i/28, eased=t*t*(3-2*t);
    await page.mouse.move(initialPointer.x+(target.x-initialPointer.x)*eased,initialPointer.y+(target.y-initialPointer.y)*eased);
    await pause(delay/28);
  }
  last=target;
}
async function click(locator, after=1100) {
  await moveTo(locator);
  await pause(230);
  await page.mouse.click(last.x,last.y);
  await pause(after);
}
async function type(locator, text, delay=75) {
  await click(locator, 180);
  await locator.pressSequentially(text,{delay});
  await pause(450);
}
async function center(locator, after=1700) {
  await locator.evaluate(el=>el.scrollIntoView({block:'center',behavior:'smooth'}));
  await pause(after);
}

async function waitForInvestigation() {
  const waitingSince = Date.now();
  let nextProgress = 0;
  const guide = page.locator('.guide .prov.ok').last();
  while (Date.now() - waitingSince < timeoutMs) {
    if (await guide.isVisible()) {
      metadata.investigation_wait_seconds = +((Date.now()-waitingSince)/1000).toFixed(2);
      metadata.recorded_model_and_settings = await page.locator('.turn .work-head .features').last().innerText();
      metadata.recorded_run_summary = await page.locator('.turn .work-head').last().innerText();
      metadata.guide_title = await page.locator('.guide h2').last().innerText();
      const guideText = await page.locator('.guide').last().innerText();
      metadata.guide_contains_korean = /[\uac00-\ud7af]/u.test(guideText);
      saveMetadata();
      return;
    }
    const latestTurn = page.locator('.turn').last();
    const failures = await latestTurn.locator('.log > .note.error').allTextContents();
    if (failures.length) throw new Error(`The actual investigation stopped: ${failures.join('; ')}`);
    if (await page.locator('input[name="username"]').isVisible()) {
      throw new Error('The authenticated session expired during investigation. Resume after signing in again.');
    }
    if (Date.now() >= nextProgress) {
      const status = await latestTurn.locator('.work-head').innerText().catch(() => 'Waiting for the investigation to start');
      const item = {
        seconds:+((Date.now()-start)/1000).toFixed(2),
        waiting_seconds:+((Date.now()-waitingSince)/1000).toFixed(2),
        status:status.replace(/\s+/g, ' ').trim(),
      };
      metadata.progress.push(item);
      console.log(`INVESTIGATION ${JSON.stringify(item)}`);
      saveMetadata();
      nextProgress = Date.now()+30000;
    }
    // A completed turn without a guide needs attention; it must not be disguised
    // as a successful run or left waiting for 45 minutes.
    if (Date.now()-waitingSince > 15000 && await page.locator('#send').isEnabled()) {
      const workStatus = await latestTurn.locator('.work-head b').innerText().catch(() => '');
      if (/Stopped|Needs more information/i.test(workStatus)) {
        throw new Error(`The actual investigation ended without a signed guide: ${workStatus}`);
      }
      const invalidProvenance = latestTurn.locator('.guide .prov.error, .guide .prov.warn');
      if (await invalidProvenance.count()) {
        throw new Error(`The actual guide did not pass provenance verification: ${await invalidProvenance.innerText()}`);
      }
    }
    await pause(1000);
  }
  throw new Error(`The actual investigation did not produce a signed guide within ${Math.round(timeoutMs/60000)} minutes. The server-side investigation may still be running; use --resume to continue recording it.`);
}

try {
  await page.goto(base, {waitUntil:'networkidle'});
  await page.locator('input[name="username"]').waitFor();
  await pause(1500);
  await mark('login');
  await type(page.locator('input[name="username"]'),username,135);
  await type(page.locator('input[name="password"]'),password,55);
  await click(page.getByRole('button',{name:'Sign in',exact:true}),1600);
  const codeField = page.locator('input[autocomplete="one-time-code"]');
  if (await codeField.isVisible()) {
    if (!secret) throw new Error('Two-step sign-in is enabled but no disposable authenticator was supplied.');
    await pause(1200);
    await mark('two-step');
    const enrollmentStep = demo.enrolled_step || 0;
    if (Math.floor(Date.now()/30000) <= enrollmentStep) await pause((enrollmentStep+1)*30000-Date.now()+150);
    await type(codeField,totp(secret),120);
    await click(page.getByRole('button',{name:'Verify',exact:true}),2500);
  }
  await page.locator('#view-dashboard:not([hidden]) .kpis').waitFor();
  await mark('dashboard');
  await pause(2500);

  await click(page.locator('.nav a[data-view="incidents"]'),1800);
  const incident = page.locator('#incident-list .incident-item').filter({hasText:'502'}).first();
  await click(incident,2200);
  await mark('incident');
  await click(page.locator('#model-pill'),1800);
  await mark('model');
  await pause(1000);
  await click(page.locator('#model-pill'),800);
  await click(page.locator('#evidence-body .file').filter({hasText:'kern.log'}),2500);
  await mark('evidence');
  await click(page.locator('[data-tab="overview"]'),1200);
  if (resume) {
    if (!await page.locator('.turn').count()) throw new Error('--resume requires an existing investigation. No new turn was started.');
    await mark('resume-existing-investigation');
  } else {
    if (await page.locator('.turn').count()) throw new Error('A fresh recording requires a blank conversation. Use --resume to record the existing actual result without rerunning inference.');
    await click(page.locator('#send'),600);
    await mark('investigation-start',false);
    await pause(2200);
    await mark('investigating');
  }
  await waitForInvestigation();
  await mark('investigation-complete',false);
  await center(page.locator('.guide-head').last(),2500);
  await mark('guide');
  await pause(2000);
  const citations = page.locator('.guide').last().locator('.evidence-list button');
  const kernelCitation = citations.filter({hasText:/kern\.log:\d/}).first();
  const citation = await kernelCitation.count() ? kernelCitation : citations.first();
  metadata.opened_citation = await citation.innerText();
  await click(citation,2400);
  await mark('citation');
  await pause(1200);
  await click(page.locator('.guide .prov.ok').last(),2500);
  await mark('provenance');
  await pause(2100);
  await click(page.locator('.prov-modal').getByRole('button',{name:'Close',exact:true}),900);
  if (await page.locator('#evidence-toggle').getAttribute('aria-pressed') === 'true') {
    await click(page.locator('#evidence-toggle'),850);
  }
  await center(page.locator('.guide .steps').last(),2300);
  await mark('recovery-steps');
  await pause(1800);
  await center(page.locator('.guide-actions').last(),1900);
  await mark('download');
  const downloadWait = page.waitForEvent('download');
  await click(page.getByRole('link',{name:'Download .md',exact:true}),1600);
  const download = await downloadWait;
  await download.saveAs(path.join(out, download.suggestedFilename()));
  metadata.download = download.suggestedFilename();
  saveMetadata();
  await pause(1000);

  await center(page.locator('.incident-head'),1400);
  await click(page.locator('.incident-head').getByRole('button',{name:/^(Share|Shared with \d+)$/}),1200);
  const sharedRow = page.locator('.share-row').filter({has:page.getByRole('button',{name:'Share',exact:true})}).first();
  await click(sharedRow.getByRole('button',{name:'Share',exact:true}),1500);
  await mark('sharing');
  await click(page.getByRole('button',{name:'Done',exact:true}),800);

  await click(page.locator('.nav a[data-view="admin"]'),1500);
  await mark('members');
  await click(page.getByRole('link',{name:'Incidents & access',exact:true}),2200);
  await mark('access');
  await click(page.getByRole('link',{name:'Audit log',exact:true}),1500);
  await click(page.getByRole('button',{name:'Verify chain',exact:true}),1900);
  await mark('audit');
  await pause(1800);
  await click(page.locator('.nav a[data-view="dashboard"]'),2400);
  await mark('dashboard-finish');
  await moveTo(page.locator('.kpis'),750);
  await pause(2200);
  if (errors.length) throw new Error(`Browser errors: ${errors.join('; ')}`);
  metadata.status = 'complete';
  metadata.finished_at = new Date().toISOString();
  saveMetadata();
} catch(error) {
  metadata.status = 'failed';
  metadata.failure = error.stack;
  metadata.finished_at = new Date().toISOString();
  saveMetadata();
  await page.screenshot({path:path.join(qa,'recording-error.png')}).catch(()=>{});
  fs.writeFileSync(path.join(qa,'recording-error.txt'),`${error.stack}\n\n${await page.locator('body').innerText().catch(()=>'')}\n`);
  console.error('Recording stopped. The real server-side investigation and saved guide were not reset. Use a new BLACKSITE_VIDEO_WORK_DIR with --resume to continue recording the actual run.');
  throw error;
} finally {
  const video=page.video();
  await context.close();
  if(video) await video.saveAs(path.join(out,'flow.webm'));
  await browser.close();
  saveMetadata();
}
