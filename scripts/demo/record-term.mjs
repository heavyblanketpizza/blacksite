// Capture the production terminal UI against a genuine local-model investigation.
// Inputs and accounts come from serve.py; no responses or application content are injected.
// The raw recording preserves all inference time. Use the timestamp marks to make an
// explicitly time-compressed edit; --resume visibly replays an existing genuine run.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);
const runtime = process.env.BLACKSITE_NODE_MODULES || path.join(os.homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules');
process.env.PLAYWRIGHT_BROWSERS_PATH ||= '/private/tmp/blacksite-video-runtime';
const {chromium} = require(path.join(runtime, 'playwright'));
const credentialArg = process.argv.slice(2).find(arg => !arg.startsWith('--'));
if (!credentialArg) throw new Error('Pass the private synthetic credentials JSON from scripts/demo/serve.py.');
const demo = JSON.parse(fs.readFileSync(credentialArg, 'utf8'));
if (demo.synthetic !== true || !demo.username || !demo.password) {
  throw new Error('Only disposable synthetic demo credentials are accepted.');
}
const backendNames = {ollama:'Ollama', llamacpp:'llama.cpp'};
if (!Object.hasOwn(backendNames, demo.provider) || typeof demo.model !== 'string' || !demo.model.trim()) {
  throw new Error('Synthetic credentials must identify the supported model provider and model name.');
}
const backendName = backendNames[demo.provider];
const base = new URL(demo.url || 'http://127.0.0.1:18768');
if (!['127.0.0.1', 'localhost'].includes(base.hostname)) throw new Error('The demo must use a local app.');
const work = process.env.BLACKSITE_VIDEO_WORK_DIR;
if (!work) throw new Error('Set BLACKSITE_VIDEO_WORK_DIR to a new ignored capture directory under var/video-real/.');
const resume = process.argv.includes('--resume');
const timeoutMs = Number(process.env.BLACKSITE_INVESTIGATION_TIMEOUT_MS || 45 * 60 * 1000);
if (!Number.isFinite(timeoutMs) || timeoutMs < 1000) throw new Error('Invalid investigation timeout.');
const out = path.join(work, 'capture');
const qa = path.join(work, 'qa');
if (fs.existsSync(path.join(out, 'flow.webm')) || fs.existsSync(path.join(work, 'capture-metadata.json'))) {
  throw new Error('Choose a new capture directory, including when using --resume.');
}
fs.mkdirSync(out, {recursive:true});
fs.mkdirSync(qa, {recursive:true});

const browser = await chromium.launch({
  headless:true,
  executablePath:process.env.BLACKSITE_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  args:['--force-device-scale-factor=1'],
});
const context = await browser.newContext({
  viewport:{width:1600, height:900},
  recordVideo:{dir:out, size:{width:1600, height:900}},
  locale:'en-US', timezoneId:'UTC', colorScheme:'dark', acceptDownloads:true,
});
await context.route('**/*', route => {
  const url = new URL(route.request().url());
  return ['127.0.0.1', 'localhost'].includes(url.hostname) || ['data:', 'blob:'].includes(url.protocol)
    ? route.continue() : route.abort();
});
await context.addInitScript(() => {
  localStorage.setItem('blacksite.lang', 'en');
  localStorage.setItem('blacksite.theme', 'dark');
  localStorage.setItem('blacksite.term.idle', 'off');
});
const page = await context.newPage();
const errors = [];
page.on('pageerror', error => errors.push(error.message));
const start = Date.now();
const marks = [];
const metadata = {
  width:1600, height:900, language:'en', interface:'term',
  subtitle:false, voiceover:false, music:false,
  source:`Actual production Blacksite terminal UI, synthetic sample evidence and disposable accounts, genuine local ${backendName} inference with ${demo.model}. No investigation events, model responses, or guides are scripted.`,
  expected_model:{provider:demo.provider, name:demo.model, base_url:demo.model_base_url},
  mode:resume ? 'resume-existing-investigation' : 'new-investigation',
  started_at:new Date(start).toISOString(), status:'recording', marks, errors, progress:[],
};
const seconds = () => +((Date.now()-start)/1000).toFixed(2);
const pause = ms => page.waitForTimeout(ms);
function save() {
  metadata.duration_seconds = seconds();
  fs.writeFileSync(path.join(work, 'capture-metadata.json'), JSON.stringify(metadata, null, 2)+'\n');
}
async function mark(name, screenshot=true) {
  marks.push({name, seconds:seconds()});
  save();
  console.log(`${marks.at(-1).seconds}s ${name}`);
  if (screenshot) await page.screenshot({path:path.join(qa, `${String(marks.length).padStart(2,'0')}-${name}.png`)});
}
async function checkCommandErrors(previous) {
  const failures = await page.locator('#log .ln.err .m').allTextContents();
  if (failures.length > previous) throw new Error(`Terminal command failed: ${failures.slice(previous).join('; ')}`);
}
async function command(text, after=1600) {
  const previous = await page.locator('#log .ln.err').count();
  const input = page.locator('#cmd');
  await input.waitFor({state:'visible'});
  await input.fill('');
  await input.pressSequentially(text, {delay:65});
  await pause(220);
  await input.press('Enter');
  // Await the production console's serialized command queue without changing it.
  // A run command only dispatches inference; waitForInvestigation handles its stream.
  await page.evaluate(() => queue);
  if (after) await pause(after);
  await checkCommandErrors(previous);
}
async function show(locator, after=2300) {
  await locator.waitFor({state:'visible'});
  await locator.evaluate(node => node.scrollIntoView({block:'start', behavior:'smooth'}));
  await pause(after);
}
async function currentIncident() {
  const id = (await page.locator('#ps-path').innerText()).replace(/^~\/cases\//, '');
  const response = await page.request.get(new URL(`/api/incidents/${encodeURIComponent(id)}`, base).href);
  if (!response.ok()) throw new Error(`Cannot inspect the recorded incident (${response.status()}).`);
  return response.json();
}
async function assertBackend() {
  const response = await page.request.get(new URL('/api/status', base).href);
  if (!response.ok()) throw new Error(`Cannot verify the configured backend (${response.status()}).`);
  const status = await response.json();
  if (status.provider !== demo.provider || status.model !== demo.model
      || (demo.model_base_url && status.base_url !== demo.model_base_url)) {
    throw new Error('The active model backend does not match the synthetic demo configuration.');
  }
  if (!status.reachable || !status.loaded) throw new Error('The expected local model is not loaded and ready.');
  const prefix = `${demo.model}@${backendName.toLowerCase()}:`;
  await page.waitForFunction(expected => document.querySelector('#st-model')?.textContent.startsWith(expected), prefix, {timeout:15000});
  metadata.backend_status = {
    provider:status.provider, name:status.model, base_url:status.base_url,
    reachable:status.reachable, loaded:status.loaded,
    displayed:await page.locator('#st-model').innerText(),
  };
  save();
}
async function assertProvenance() {
  const incident = await currentIncident();
  const turn = incident.turns.length;
  const response = await page.request.get(new URL(`/api/incidents/${encodeURIComponent(incident.id)}/provenance?turn=${turn}`, base).href);
  if (!response.ok()) throw new Error(`Cannot verify recorded model provenance (${response.status()}).`);
  const {manifest, check} = await response.json();
  if (check.signature !== true || check.guide !== true || check.evidence !== 'unchanged') {
    throw new Error('The actual signed provenance did not verify successfully.');
  }
  if (manifest.model?.provider !== demo.provider || manifest.model?.name !== demo.model
      || (demo.model_base_url && manifest.model?.base_url !== demo.model_base_url)) {
    throw new Error('The signed investigation used a different model backend from the requested demo.');
  }
  if (metadata.model_start?.model !== demo.model) throw new Error('The recorded start event identifies a different model.');
  const displayed = await page.locator('#log').innerText();
  if (!displayed.includes(`${demo.provider}/${demo.model}`)) throw new Error('The requested model backend was not displayed in provenance.');
  metadata.provenance = {
    turn, model:manifest.model, signature_valid:check.signature,
    guide_unchanged:check.guide, evidence:check.evidence,
    citations:manifest.checks,
  };
  save();
}
async function waitForInvestigation() {
  const waitingSince = Date.now();
  let nextProgress = 0;
  while (Date.now()-waitingSince < timeoutMs) {
    if (await page.locator('#auth:not([hidden])').isVisible()) throw new Error('The demo session expired. Resume in a new capture directory.');
    const failures = await page.locator('#log .ln.err .m').allTextContents();
    if (failures.length) throw new Error(`The actual investigation stopped: ${failures.join('; ')}`);
    const busy = (await page.locator('#prompt').getAttribute('class') || '').split(/\s+/).includes('busy');
    if (!busy && await page.locator('#log .k-done').count()) {
      if (!await page.locator('#log .brief h3').count()) throw new Error('The actual investigation ended without a guide.');
      // The stream-end handler reloads the incident; read its persisted results.
      const incident = await currentIncident();
      const turn = incident.turns.at(-1);
      const events = turn?.events || [];
      const done = events.find(event => event.type === 'done');
      const guide = events.find(event => event.type === 'guide');
      if (!guide || !done) throw new Error('The investigation did not persist a completed guide.');
      metadata.investigation_wait_seconds = +((Date.now()-waitingSince)/1000).toFixed(2);
      metadata.model_start = events.find(event => event.type === 'start');
      metadata.run_result = done;
      metadata.guide_title = guide.guide.title;
      metadata.guide_contains_korean = /[\uac00-\ud7af]/u.test(JSON.stringify(guide.guide));
      save();
      return;
    }
    if (Date.now() >= nextProgress) {
      const progress = {
        seconds:seconds(), waiting_seconds:+((Date.now()-waitingSince)/1000).toFixed(2),
        state:await page.locator('#ops-state').innerText(),
        tool_calls:await page.locator('#log .k-call').count(),
        tool_results:await page.locator('#log .k-ret').count(),
        draft_visible:await page.locator('#log .m.draft').count() > 0,
      };
      metadata.progress.push(progress);
      save();
      console.log(`INVESTIGATION ${JSON.stringify(progress)}`);
      nextProgress=Date.now()+30000;
    }
    await pause(1000);
  }
  throw new Error('The real investigation exceeded the recording timeout. Its server-side work is preserved; use --resume in a new capture directory.');
}

save();
try {
  await page.goto(new URL('/term', base).href, {waitUntil:'networkidle'});
  await page.locator('input[name="username"]').waitFor();
  await pause(1800);
  await mark('login');
  await page.locator('input[name="username"]').pressSequentially(demo.username, {delay:140});
  await page.locator('input[name="username"]').press('Enter');
  await page.locator('input[name="password"]').pressSequentially(demo.password, {delay:45});
  await pause(300);
  await page.locator('input[name="password"]').press('Enter');
  await page.locator('#console:not([hidden])').waitFor({timeout:15000});
  await page.locator('#cmd').waitFor();
  if (await page.locator('input[autocomplete="one-time-code"]').count()) throw new Error('Two-step authentication is still active for the demo.');
  await pause(1400);
  await assertBackend();
  await mark('console');
  await command('ls', 1300);
  await command('open 1', 2200);
  await mark('incident');
  const initial = await currentIncident();
  metadata.incident = initial.id;
  if (!resume && initial.turns.length) throw new Error('A fresh recording requires a blank conversation. Use --resume to visibly replay genuine saved results.');
  if (resume && !initial.turns.length && !initial.running) throw new Error('--resume requires an existing genuine investigation.');
  await command('files', 1300);
  await mark('files');
  await command('cat kern.log:2', 2200);
  await mark('evidence');
  await command('grep -m 5 "killed|oom"', 2000);
  await mark('search');

  if (resume && !initial.running) {
    await mark('resume-replay-start', false);
    await command(`replay ${initial.turns.length} 8`, 0);
    await page.waitForFunction(() => !document.querySelector('#ops-state').textContent.includes('replay'), null, {timeout:timeoutMs});
    await mark('resume-replay-end', false);
    const events = initial.turns.at(-1).events;
    metadata.run_result = events.find(event => event.type === 'done');
    metadata.model_start = events.find(event => event.type === 'start');
    metadata.guide_title = events.find(event => event.type === 'guide')?.guide.title;
  } else {
    await mark(resume ? 'resume-investigation-start' : 'investigation-start', false);
    if (!resume) await command('run', 0);
    else if (!(await page.locator('#prompt').getAttribute('class') || '').includes('busy')) throw new Error('The saved investigation is no longer running. Resume again to replay it.');
    await pause(1000);
    await mark('investigating');
    await waitForInvestigation();
    await mark('investigation-complete', false);
  }
  await page.waitForFunction(() => !document.querySelector('#prompt').classList.contains('busy'));
  await command('brief', 300);
  const brief = page.locator('#log .brief').last();
  await show(brief.locator('.brief-head'), 4800);
  await mark('guide');
  const rootCause = brief.locator('section').filter({has:page.getByRole('heading', {name:'root cause', exact:true})});
  await show(rootCause, 4000);
  await mark('root-cause');
  const citations = brief.locator('.ref');
  const kernel = citations.filter({hasText:/kern\.log:\d/}).first();
  const citation = await kernel.count() ? kernel : citations.first();
  metadata.opened_citation = await citation.innerText();
  await citation.click();
  await page.evaluate(() => queue);
  await pause(3500);
  await mark('citation');
  await show(brief.locator('section').filter({has:page.getByRole('heading', {name:'procedure', exact:true})}), 5800);
  await mark('procedure');
  await command('prov', 4000);
  const logText = await page.locator('#log').innerText();
  if (!logText.includes('valid · key') || !logText.includes('matches what was signed') || !logText.includes('unchanged')) {
    throw new Error('The recorded provenance did not verify successfully.');
  }
  await assertProvenance();
  await mark('provenance');
  const downloading = page.waitForEvent('download');
  await command('dl', 1300);
  const download = await downloading;
  await download.saveAs(path.join(out, path.basename(download.suggestedFilename())));
  metadata.download = download.suggestedFilename();
  await mark('download');
  await command('share minseo', 1800);
  await mark('sharing');
  await command('audit verify', 3500);
  metadata.audit_result = await page.locator('#log .ln').last().innerText();
  await mark('audit');
  await command('brief', 300);
  await show(page.locator('#log .brief').last().locator('.brief-head'), 3800);
  await mark('final-guide');
  await command('cmatrix', 2800);
  await mark('finish');
  if (errors.length) throw new Error(`Browser errors: ${errors.join('; ')}`);
  metadata.status='complete';
  metadata.finished_at=new Date().toISOString();
  save();
} catch(error) {
  metadata.status='failed';
  metadata.failure=error.stack;
  metadata.finished_at=new Date().toISOString();
  save();
  await page.screenshot({path:path.join(qa,'recording-error.png')}).catch(()=>{});
  fs.writeFileSync(path.join(qa,'recording-error.txt'), `${error.stack}\n\n${await page.locator('body').innerText().catch(()=>'')}\n`);
  console.error('Recording stopped. The actual investigation remains on the server. Use --resume with a new capture directory to recover it.');
  throw error;
} finally {
  const video=page.video();
  await context.close();
  if(video) await video.saveAs(path.join(out,'flow.webm'));
  await browser.close();
  save();
}
