import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {activityFor, redact, handleMessage, createSessionManager, loginPage, launchOptions, prepareMySQLGUI, waitForGraphicalConnection, waitForMySQLGUI} from './worker.mjs';

function fakePage() {
  const calls = [];
  return {
    calls,
    mouse: {move: async (...x)=>calls.push(['move', ...x]), click: async (...x)=>calls.push(['click', ...x]), wheel: async (...x)=>calls.push(['wheel', ...x])},
    keyboard: {press: async (...x)=>calls.push(['press', ...x])},
    reload: async ()=>calls.push(['reload']),
    evaluate: async ()=>calls.push(['evaluate']),
    waitForFunction: async ()=>calls.push(['waitForFunction'])
  };
}

test('RDP and VNC activity sends pointer and keyboard input', async () => {
  for (const protocol of ['rdp', 'vnc']) {
    const page = fakePage(); await activityFor(protocol, page, 3);
    assert(page.calls.some(x=>x[0] === 'move'));
    assert(page.calls.some(x=>x[0] === 'press'));
  }
});

test('web activity scrolls, clicks, and periodically refreshes', async () => {
  const page = fakePage(); await activityFor('web', page, 10);
  assert(page.calls.some(x=>x[0] === 'wheel'));
  assert(page.calls.some(x=>x[0] === 'click'));
  assert(page.calls.some(x=>x[0] === 'reload'));
});

test('web activity tolerates navigation destroying the current execution context', async () => {
  const page = fakePage();
  page.evaluate = async () => { throw new Error('Execution context was destroyed, most likely because of a navigation'); };
  await activityFor('web', page, 1);
  assert(page.calls.some(x=>x[0] === 'click'));
});

test('prepareMySQLGUI opens the exact bound asset and account in graphical mode', async () => {
  const calls=[];
  const guiPage={waitForLoadState:async state=>calls.push(['load',state])};
  const search={fill:async value=>calls.push(['search',value]),press:async key=>calls.push(['press',key])};
  const button={click:async()=>calls.push(['connect'])};
  const row={getByRole:(role,options)=>{assert.equal(role,'button');assert.equal(options.name,'desktop');return button;}};
  const link={waitFor:async()=>calls.push(['asset-ready']),locator:selector=>{assert.equal(selector,'xpath=ancestor::tr');return row;}};
  const account={waitFor:async()=>calls.push(['account-ready']),hover:async()=>calls.push(['account-hover'])};
  const gui={click:async()=>calls.push(['gui-click'])};
  const page={
    evaluate:async (_fn,id)=>{calls.push(['asset-fetch',id]);return 'mysql-asset-name';},
    getByPlaceholder:name=>{assert.equal(name,'请输入查询内容');return search;},
    locator:selector=>{
      if(selector==='a[href="#/asset/asset-bound"]')return link;
      if(selector==='[data-menu-id$="account-account-bound"]')return account;
      throw new Error(`unexpected selector ${selector}`);
    },
    getByRole:(role,options)=>{assert.equal(role,'menuitem');assert.equal(options.name,'图形化GUI');return gui;}
  };
  const context={waitForEvent:async event=>{assert.equal(event,'page');return guiPage;}};
  assert.equal(await prepareMySQLGUI(context,page,'asset-bound','account-bound',1234),guiPage);
  assert(calls.some(x=>x[0]==='search'&&x[1]==='mysql-asset-name'));
  assert(calls.some(x=>x[0]==='account-hover'));
  assert(calls.some(x=>x[0]==='gui-click'));
});

test('waitForMySQLGUI requires Connected and an operable ACE query editor', async () => {
  const calls=[];
  const connected={waitFor:async options=>calls.push(['connected',options.timeout])};
  const newQuery={count:async()=>1,click:async()=>calls.push(['new-query'])};
  const queryChoice={filter:()=>({evaluate:async()=>calls.push(['query-choice'])})};
  const editor={waitFor:async options=>calls.push(['editor',options.timeout])};
  const execute={waitFor:async options=>calls.push(['execute',options.timeout])};
  const page={
    getByText:(text,options)=>{assert.equal(text,'Connected');assert.equal(options.exact,true);return connected;},
    locator:selector=>{
      if(selector==='[title="New query"]')return newQuery;
      if(selector==='.new-object-button')return queryChoice;
      if(selector==='.ace_text-input')return editor;
      if(selector==='[title^="查询: 执行"]')return execute;
      throw new Error(`unexpected selector ${selector}`);
    }
  };
  await waitForMySQLGUI(page,2222);
  assert.deepEqual(calls.map(x=>x[0]),['connected','new-query','query-choice','editor','execute']);
});

test('mysql activity executes only the fixed read-only query and waits for result refresh', async () => {
  const calls=[];
  const tables={count:async()=>1,last:()=>({innerText:async()=> 'previous result'})};
  const editor={first:()=>({click:async options=>calls.push(['editor-click',options.force])})};
  const execute={first:()=>({click:async options=>calls.push(['execute-click',options.force])})};
  const page={
    locator:selector=>{
      if(selector==='table')return tables;
      if(selector==='.ace_content')return editor;
      if(selector==='[title^="查询: 执行"]')return execute;
      throw new Error(`unexpected selector ${selector}`);
    },
    keyboard:{press:async key=>calls.push(['key',key]),insertText:async value=>calls.push(['query',value])},
    waitForFunction:async (_predicate,args,options)=>calls.push(['result-wait',args,options.timeout])
  };
  await activityFor('mysql',page,1);
  const query=calls.find(x=>x[0]==='query')?.[1]??'';
  assert.equal(query,'SELECT CURRENT_TIMESTAMP AS pam_loadtest_time');
  assert(!/\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|GRANT|TRUNCATE)\b/i.test(query));
  assert(calls.some(x=>x[0]==='execute-click'));
  assert(calls.some(x=>x[0]==='result-wait'));
});

test('redaction removes MySQL GUI recording contexts and bound identifiers', () => {
  const value='http://pam.test/pamdb-native/?emmPamPamdbRecordingContext=opaque&assetId=asset-value&accountId=account-value';
  const safe=redact(value);
  assert(!safe.includes('opaque'));
  assert(!safe.includes('asset-value'));
  assert(!safe.includes('account-value'));
});

test('messages are validated and errors are sanitized', async () => {
  await assert.rejects(()=>handleMessage({type:'start', protocol:'ssh'}), /unsupported protocol/);
  assert(!redact('password=secret X-Auth-Token=abc').includes('secret'));
  assert(!redact('password=secret X-Auth-Token=abc').includes('abc'));
});

test('worker executable reads and writes NDJSON', async () => {
  const child = spawn(process.execPath, ['worker.mjs'], {cwd:new URL('.', import.meta.url), stdio:['pipe','pipe','inherit']});
  child.stdin.end(`${JSON.stringify({type:'start', protocol:'ssh'})}\n`);
  let output=''; child.stdout.setEncoding('utf8'); child.stdout.on('data', chunk=>output+=chunk);
  await once(child, 'exit');
  const message = JSON.parse(output.trim());
  assert.equal(message.type, 'error');
  assert.match(message.error, /unsupported protocol/);
});

test('session manager shares one browser across isolated contexts', async () => {
  let launches=0, contexts=0;
  const browser={newContext:async()=>{contexts++;return{newPage:async()=>({...fakePage(),goto:async()=>{}}),close:async()=>{}}},close:async()=>{}};
  const manager=createSessionManager(async()=>{launches++;return browser},()=>{});
  await manager.start({id:'a',protocol:'rdp',url:'http://test/a',intervalMs:100000});
  await manager.start({id:'b',protocol:'vnc',url:'http://test/b',intervalMs:100000});
  assert.equal(launches,1);assert.equal(contexts,2);
  await manager.shutdown();
});

test('session manager reports MySQL started only after the bound GUI editor is ready', async () => {
  const noop=async()=>{};
  const guiPage={
    waitForLoadState:noop,
    getByText:()=>({waitFor:noop}),
    locator:selector=>{
      if(selector==='[title="New query"]')return{count:async()=>1,click:noop};
      if(selector==='.new-object-button')return{filter:()=>({evaluate:noop})};
      if(selector==='.ace_text-input'||selector==='[title^="查询: 执行"]')return{waitFor:noop};
      throw new Error(`unexpected GUI selector ${selector}`);
    }
  };
  const search={fill:noop,press:noop};
  const row={getByRole:()=>({click:noop})};
  const entryPage={
    goto:noop,
    evaluate:async()=> 'mysql-asset-name',
    getByPlaceholder:()=>search,
    locator:selector=>{
      if(selector==='a[href="#/asset/asset-bound"]')return{waitFor:noop,locator:()=>row};
      if(selector==='[data-menu-id$="account-account-bound"]')return{waitFor:noop,hover:noop};
      throw new Error(`unexpected entry selector ${selector}`);
    },
    getByRole:()=>({click:noop})
  };
  const context={newPage:async()=>entryPage,waitForEvent:async()=>guiPage,close:noop};
  const browser={newContext:async()=>context,close:noop};
  const manager=createSessionManager(async()=>browser,()=>{});
  const result=await manager.start({id:'mysql-gui',protocol:'mysql',url:'http://pam.test/#/asset',assetId:'asset-bound',accountId:'account-bound',intervalMs:100000});
  assert.equal(result.type,'started');
  assert.equal(result.protocol,'mysql');
  await manager.shutdown();
});

test('session manager measures MySQL from GUI click through Connected', async () => {
  const emitted=[];
  const noop=async()=>{};
  const guiPage={
    waitForLoadState:noop,
    getByText:(text, options)=>{
      assert.equal(text,'Connected');assert.equal(options.exact,true);
      return {waitFor:noop};
    },
    locator:selector=>{
      if(selector==='[title="New query"]')return{count:async()=>1,click:noop};
      if(selector==='.new-object-button')return{filter:()=>({evaluate:noop})};
      if(selector==='.ace_text-input'||selector==='[title^="查询: 执行"]')return{waitFor:noop};
      throw new Error(`unexpected GUI selector ${selector}`);
    }
  };
  const entryPage={
    goto:noop,
    evaluate:async()=> 'mysql-asset-name',
    getByPlaceholder:()=>({fill:noop,press:noop}),
    locator:selector=>{
      if(selector==='a[href="#/asset/asset-bound"]')return{waitFor:noop,locator:()=>({getByRole:()=>({click:noop})})};
      if(selector==='[data-menu-id$="account-account-bound"]')return{waitFor:noop,hover:noop};
      throw new Error(`unexpected entry selector ${selector}`);
    },
    getByRole:()=>({click:noop})
  };
  const context={newPage:async()=>entryPage,waitForEvent:async()=>guiPage,close:noop};
  const browser={newContext:async()=>context,close:noop};
  const clock=[0,7100,9300,9700];
  const manager=createSessionManager(async()=>browser,message=>emitted.push(message),()=>clock.shift());
  try {
    const result=await manager.start({id:'mysql-timing',protocol:'mysql',url:'http://pam.test/#/asset',assetId:'asset-bound',accountId:'account-bound',intervalMs:100000});
    assert.deepEqual(result,{type:'started',id:'mysql-timing',protocol:'mysql',connectLatencyMs:2200,prepareMs:7100,editorReadyMs:400});
    assert.deepEqual(emitted,[]);
  } finally {
    await manager.shutdown();
  }
});

test('session manager serializes activity within a browser context', async () => {
  let concurrent=0, maxConcurrent=0;
  const page={
    ...fakePage(),
    goto:async()=>{},
    mouse:{
      wheel:async()=>{concurrent++;maxConcurrent=Math.max(maxConcurrent,concurrent);await new Promise(resolve=>setTimeout(resolve,15));concurrent--;},
      click:async()=>{},move:async()=>{}
    }
  };
  const browser={newContext:async()=>({newPage:async()=>page,close:async()=>{}}),close:async()=>{}};
  const manager=createSessionManager(async()=>browser,()=>{});
  await manager.start({id:'serialized',protocol:'web',url:'http://test',intervalMs:1});
  await new Promise(resolve=>setTimeout(resolve,12));
  await manager.stop('serialized');
  await new Promise(resolve=>setTimeout(resolve,20));
  assert.equal(maxConcurrent,1);
  await manager.shutdown();
});

test('loginPage authenticates through the visible PAM login form', async()=>{
  const calls=[];const locator=selector=>({first:()=>({fill:async value=>calls.push(['fill',selector,value]),click:async()=>calls.push(['click',selector])})});
  const response={url:()=> 'http://pam.test/login',request:()=>({method:()=> 'POST'}),ok:()=>true,status:()=>200};
  const page={goto:async url=>calls.push(['goto',url]),locator,waitForResponse:async predicate=>{calls.push(['wait-response']);assert.equal(predicate(response),true);return response;}};
  await loginPage(page,'http://pam.test','runtime-user','runtime-password');
  assert(calls.some(x=>x[0]==='fill'&&x[2]==='runtime-user'));assert(calls.some(x=>x[0]==='fill'&&x[2]==='runtime-password'));assert(calls.some(x=>x[0]==='click'));
  assert(calls.findIndex(x=>x[0]==='wait-response')<calls.findIndex(x=>x[0]==='click'));
});

test('session manager reuses supplied PAM cookies without another login', async () => {
  const added=[];
  const page={...fakePage(),goto:async()=>{}};
  const browser={
    newContext:async()=>({
      addCookies:async cookies=>added.push(...cookies),
      newPage:async()=>page,
      close:async()=>{}
    }),
    close:async()=>{}
  };
  const manager=createSessionManager(async()=>browser,()=>{});
  await manager.start({
    id:'cookie-auth',protocol:'rdp',url:'http://pam.test/#/access',
    loginUrl:'http://pam.test',username:'runtime-user',password:'runtime-password',
    cookies:[{name:'sid',value:'runtime-cookie',url:'http://pam.test'}],intervalMs:100000
  });
  assert.deepEqual(added,[{name:'sid',value:'runtime-cookie',url:'http://pam.test'}]);
  await manager.shutdown();
});

test('session manager does not report started before graphical rendering is ready', async () => {
  let release;
  const page={
    ...fakePage(),
    goto:async()=>{},
    waitForFunction:async()=>new Promise(resolve=>{release=resolve;})
  };
  const browser={newContext:async()=>({newPage:async()=>page,close:async()=>{}}),close:async()=>{}};
  const manager=createSessionManager(async()=>browser,()=>{});
  let settled=false;
  const starting=manager.start({id:'render-gate',protocol:'rdp',url:'http://pam.test/#/access',intervalMs:100000}).then(result=>{settled=true;return result;});
  await new Promise(resolve=>setTimeout(resolve,5));
  assert.equal(settled,false);
  release();
  assert.equal((await starting).type,'started');
  await manager.shutdown();
});

test('graphical readiness requires a rendered canvas or receiving video', async () => {
  let captured;
  const page={waitForFunction:async predicate=>{captured=predicate;}};
  await waitForGraphicalConnection(page,'web',1234);
  assert.equal(typeof captured,'function');
});

test('launch options use an explicitly configured system Chromium', () => {
  assert.deepEqual(
    launchOptions({headless:false}, {PAM_BROWSER_EXECUTABLE_PATH:'/usr/bin/chromium'}),
    {headless:false, executablePath:'/usr/bin/chromium'}
  );
  assert.deepEqual(launchOptions({}, {}), {headless:true});
});
