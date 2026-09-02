import readline from 'node:readline';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const supported = new Set(['rdp', 'vnc', 'web', 'mysql']);
const mysqlReadOnlyQuery = 'SELECT CURRENT_TIMESTAMP AS pam_loadtest_time';

export function redact(value) {
  return String(value)
    .replace(/(password\s*[=:]\s*)\S+/gi, '$1[REDACTED]')
    .replace(/(x-auth-token\s*[=:]\s*)\S+/gi, '$1[REDACTED]')
    .replace(/([?&]emmPamPamdbRecordingContext=)[^&\s]+/gi, '$1[REDACTED]')
    .replace(/([?&](?:assetId|accountId)=)[^&#\s]+/gi, '$1[REDACTED]')
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '{uuid}');
}

export async function openMySQLGUI(context, page, assetId, accountId, timeoutMs = 30000, now = Date.now) {
  if (!assetId || !accountId) throw new Error('mysql GUI requires bound asset and account');
  const assetName = await page.evaluate(async id => {
    const response = await fetch(`/assets/${encodeURIComponent(id)}`, {credentials:'same-origin'});
    if (!response.ok) throw new Error(`mysql GUI asset lookup returned ${response.status}`);
    const body = await response.json();
    const asset = body?.data ?? body;
    if (!asset || typeof asset.name !== 'string' || !asset.name) throw new Error('mysql GUI asset lookup returned no name');
    return asset.name;
  }, assetId);
  const search = page.getByPlaceholder('请输入查询内容');
  await search.fill(assetName);
  await search.press('Enter');
  const assetLink = page.locator(`a[href="#/asset/${assetId}"]`);
  await assetLink.waitFor({state:'visible', timeout:timeoutMs});
  const row = assetLink.locator('xpath=ancestor::tr');
  await row.getByRole('button', {name:'desktop'}).click();
  const account = page.locator(`[data-menu-id$="account-${accountId}"]`);
  await account.waitFor({state:'visible', timeout:timeoutMs});
  await account.hover();
  const opened = context.waitForEvent('page', {timeout:timeoutMs});
  const clickStartedAt = now();
  await page.getByRole('menuitem', {name:'图形化GUI'}).click();
  const guiPage = await opened;
  await guiPage.waitForLoadState('domcontentloaded', {timeout:timeoutMs});
  return {page:guiPage, clickStartedAt};
}

export async function prepareMySQLGUI(context, page, assetId, accountId, timeoutMs = 30000) {
  return (await openMySQLGUI(context, page, assetId, accountId, timeoutMs)).page;
}

export async function waitForMySQLConnected(page, timeoutMs = 30000) {
  await page.getByText('Connected', {exact:true}).waitFor({state:'visible', timeout:timeoutMs});
}

export async function waitForMySQLEditor(page, timeoutMs = 30000) {
  const newQuery = page.locator('[title="New query"]');
  if (await newQuery.count()) await newQuery.click({force:true});
  const queryChoice = page.locator('.new-object-button').filter({hasText:'SQL 查询编辑器'});
  await queryChoice.evaluate(element => element.click());
  await page.locator('.ace_text-input').waitFor({state:'visible', timeout:timeoutMs});
  await page.locator('[title^="查询: 执行"]').waitFor({state:'visible', timeout:timeoutMs});
}

export async function waitForMySQLGUI(page, timeoutMs = 30000) {
  await waitForMySQLConnected(page, timeoutMs);
  await waitForMySQLEditor(page, timeoutMs);
}

async function runMySQLReadOnlyQuery(page) {
  const tables = page.locator('table');
  const beforeTables = await tables.count();
  const beforeResult = beforeTables > 0 ? await tables.last().innerText().catch(() => '') : '';
  await page.locator('.ace_content').first().click({force:true});
  await page.keyboard.press('Control+A');
  await page.keyboard.insertText(mysqlReadOnlyQuery);
  await page.locator('[title^="查询: 执行"]').first().click({force:true});
  await page.waitForFunction(({count, result}) => {
    const current = [...document.querySelectorAll('table')];
    const last = current.at(-1);
    const aliasVisible = document.body?.innerText?.includes('pam_loadtest_time');
    return Boolean(aliasVisible && last && (current.length > count || last.innerText !== result));
  }, {count:beforeTables, result:beforeResult}, {timeout:30000});
}

export async function activityFor(protocol, page, sequence) {
  if (protocol === 'rdp' || protocol === 'vnc') {
    await page.mouse.move(80 + sequence % 500, 80 + (sequence * 7) % 300);
    await page.mouse.click(100 + sequence % 400, 100 + sequence % 200);
    await page.keyboard.press(sequence % 2 ? 'ArrowLeft' : 'ArrowRight');
    return;
  }
  if (protocol === 'web') {
    await page.mouse.wheel(0, sequence % 2 ? 320 : -320);
    await page.mouse.click(100 + sequence % 300, 100 + sequence % 200);
    try {
      await page.evaluate(() => window.dispatchEvent(new Event('resize')));
    } catch (error) {
      if (!isNavigationInterruption(error)) throw error;
    }
    if (sequence % 10 === 0) await page.reload({waitUntil:'domcontentloaded'});
    return;
  }
  if (protocol === 'mysql') {
    await runMySQLReadOnlyQuery(page);
    return;
  }
  throw new Error(`unsupported protocol ${protocol}`);
}

function isNavigationInterruption(error) {
  const message=String(error?.message??error);
  return message.includes('Execution context was destroyed') || message.includes('because of a navigation');
}

export async function loginPage(page,baseUrl,username,password){
  await page.goto(baseUrl,{waitUntil:'domcontentloaded'});
  const user=page.locator('input[name="username"], input[autocomplete="username"], input[type="text"]').first();
  const pass=page.locator('input[name="password"], input[autocomplete="current-password"], input[type="password"]').first();
  await user.fill(username);await pass.fill(password);
  const submit=page.locator('button[type="submit"], input[type="submit"], button').first();
  const [response]=await Promise.all([
    page.waitForResponse(candidate=>{
      try{return new URL(candidate.url()).pathname==='/login'&&candidate.request().method()==='POST'}catch{return false}
    },{timeout:30000}),
    submit.click()
  ]);
  if(!response.ok())throw new Error(`PAM login returned ${response.status()}`);
}

export function launchOptions(message, env=process.env) {
  const options={headless:message.headless!==false};
  if (env.PAM_BROWSER_EXECUTABLE_PATH) options.executablePath=env.PAM_BROWSER_EXECUTABLE_PATH;
  return options;
}

export async function waitForGraphicalConnection(page, protocol, timeoutMs = 30000) {
  await page.waitForFunction(kind => {
    const canvasReady=[...document.querySelectorAll('canvas')].some(canvas=>canvas.width>0&&canvas.height>0);
    if(kind==='rdp'||kind==='vnc')return canvasReady;
    const videoReady=[...document.querySelectorAll('video')].some(video=>video.readyState>=2&&video.videoWidth>0&&video.videoHeight>0);
    return canvasReady||videoReady;
  },protocol,{timeout:timeoutMs});
}

export function createSessionManager(launch, output, now = Date.now) {
  const sessions = new Map(); let browserPromise;
  async function browserFor(message) { if (!browserPromise) browserPromise=launch(message); return browserPromise; }
  return {
    async start(message) {
      if (!supported.has(message.protocol)) throw new Error(`unsupported protocol ${message.protocol}`);
      if (!message.id || !message.url) throw new Error('id and url are required');
      if (sessions.has(message.id)) throw new Error('session already exists');
      const taskStartedAt=now();
      const browser=await browserFor(message);const context=await browser.newContext({viewport:message.viewport??{width:1280,height:720}});
      if(message.cookies?.length){await context.addCookies(message.cookies)}
      const page=await context.newPage();if(!message.cookies?.length&&message.username&&message.password){await loginPage(page,message.loginUrl??new URL(message.url).origin,message.username,message.password)};await page.goto(message.url,{waitUntil:'domcontentloaded',timeout:message.navigationTimeoutMs??30000});let activePage=page;let started={type:'started',id:message.id,protocol:message.protocol};if(message.protocol==='mysql'){const gui=await openMySQLGUI(context,page,message.assetId,message.accountId,message.connectionTimeoutMs??30000,now);activePage=gui.page;await waitForMySQLConnected(activePage,message.connectionTimeoutMs??30000);const connectedAt=now();await waitForMySQLEditor(activePage,message.connectionTimeoutMs??30000);const editorReadyAt=now();started={...started,connectLatencyMs:Math.max(1,connectedAt-gui.clickStartedAt),prepareMs:Math.max(0,gui.clickStartedAt-taskStartedAt),editorReadyMs:Math.max(0,editorReadyAt-connectedAt)}}else{await waitForGraphicalConnection(page,message.protocol,message.connectionTimeoutMs??30000)}let sequence=0,running=false;
      const interval=setInterval(async()=>{if(running)return;running=true;try{await activityFor(message.protocol,activePage,++sequence);output({type:'heartbeat',id:message.id,protocol:message.protocol,sequence})}catch(error){output({type:'error',id:message.id,error:redact(error?.message??error)})}finally{running=false}},message.intervalMs??1000);
      sessions.set(message.id,{context,interval});return started;
    },
    async stop(id) { const current=sessions.get(id);if(!current)return{type:'stopped',id};clearInterval(current.interval);sessions.delete(id);await current.context.close();return{type:'stopped',id}; },
    async shutdown() { for(const id of [...sessions.keys()])await this.stop(id);if(browserPromise){const browser=await browserPromise;await browser.close();browserPromise=undefined}return{type:'shutdown'}; }
  };
}

const manager=createSessionManager(async message=>{const {chromium}=await import('playwright-core');return chromium.launch(launchOptions(message))},emit);

export async function handleMessage(message) {
	if (!message || typeof message !== 'object') throw new Error('message must be an object');
  if (message.type === 'start') return manager.start(message);
  if (message.type === 'stop') return manager.stop(message.id);
  if (message.type === 'shutdown') return manager.shutdown();
  throw new Error(`unsupported message type ${message.type}`);
}

function emit(message) { process.stdout.write(`${JSON.stringify(message)}\n`); }

async function main() {
  const rl = readline.createInterface({input:process.stdin, crlfDelay:Infinity});
  for await (const line of rl) {
    if (!line.trim()) continue;
    try { emit(await handleMessage(JSON.parse(line))); }
    catch (error) { emit({type:'error', error:redact(error?.message ?? error)}); }
  }
  await handleMessage({type:'shutdown'});
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch(error => { emit({type:'fatal', error:redact(error?.message ?? error)}); process.exitCode=1; });
}
