"use strict";
/** QA-only: real Keycloak -> original Django BFF session -> Chromium S01
 * -> S03 Native Fastify -> disposable PostgreSQL16. Synthetic preapproved
 * identity/product digest materialized by the test harness, NOT the
 * production issuer SQL. No live data, API registration or content release.
 * Pin exact S03 source and reuse its real QA Native engine, not new logic. */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path");
const {randomBytes,createHash}=require("node:crypto"),{createRequire}=require("node:module");
const {execFileSync}=require("node:child_process");
const root=process.env.S03_QA_S03_ROOT;
assert.ok(root&&path.isAbsolute(root)&&root.startsWith("/tmp/"),
 "Exact S03 draft checkout under /tmp is required");
const s03Head=execFileSync("git",["-C",root,"rev-parse","HEAD"],{encoding:"utf8"}).trim();
assert.equal(s03Head,"d038f085d84db085055432c03cf99e4bad12d828",
 "S03 Native source changed; re-review the joined Keycloak test contract");
const dep=createRequire(path.join(root,"backend/package.json"));
const {Client}=dep("pg"),Fastify=dep("fastify");
const socket=process.env.S03_QA_PG_SOCKET,database=process.env.S03_QA_PG_DATABASE;
const build=process.env.S03_QA_S01_BFF_BUILD_ROOT;
const playwrightPath=process.env.S03_QA_PLAYWRIGHT_MODULE;
assert.match(socket||"",/^\/tmp\/sumlaude-s03-pg16-qa\.[A-Za-z0-9]{6}\/socket$/);
assert.match(database||"",/^sumlaude_native_qa_disposable_[a-z0-9_]+$/);
assert.ok(build&&fs.statSync(build).isDirectory(),"Independent S01 BFF build required");
assert.ok(playwrightPath&&path.isAbsolute(playwrightPath),"Actual Chromium runner required");
const {chromium}=require(playwrightPath);
Object.assign(process.env,{
 NODE_ENV:"test",PRODUCT_RUNTIME:"sumlaude",SUMLAUDE_NATIVE_LOCAL_QA:"true",
 SUMLAUDE_OPAQUE_BFF_LOCAL_QA:"true",
 DATABASE_URL:"postgresql://sumlaude_qa_app@127.0.0.1:1/sumlaude_native_qa_disposable_http_guard",
 JWT_ISSUER:"sumlaude-app",JWT_AUDIENCE:"sumlaude-learner",
 TS_NODE_PROJECT:path.join(root,"backend/tsconfig.json"),
 TS_NODE_COMPILER_OPTIONS:JSON.stringify({module:"CommonJS",moduleResolution:"Node",ignoreDeprecations:"5.0"}),
 TS_NODE_TRANSPILE_ONLY:"true"
});
dep("ts-node/register/transpile-only");
const routes=require(path.join(root,"backend/src/modules/valoria/native/sumlaude-opaque-bff-qa.routes.ts"));
const original=JSON.parse(fs.readFileSync(path.join(root,"scripts/qa/fixtures/s03-str012-lc1-v02-original-author-review-qa.json")));
const units=original.modules.flatMap(m=>m.units);
const steps=units.flatMap(u=>u.activities.filter(a=>["reading","objective_practice","recall"].includes(a.type)));
const sourceSha=createHash("sha256").update(fs.readFileSync(path.join(root,"scripts/qa",
 "fixtures/s03-str012-lc1-v02-original-author-review-qa.json"))).digest("hex");
assert.equal(sourceSha,"6f6502a6ccda3ad6d418973fd481d29941a7b11f9461b1ec90b8bcce3cf335b9");
assert.equal(original.syntheticDevOnly,true);assert.equal(original.contentOrigin,"needs_review");
assert.equal(units.length,5);assert.equal(steps.length,7);assert.equal(original.questions.length,11);
const owner=1004,pe="c4000000-0000-4000-8000-000000000004";
const ce="c5000000-0000-4000-8000-000000000004";
const org="c1000000-0000-4000-8000-000000000001";
const prog="c2000000-0000-4000-8000-000000000001";
const course="c3000000-0000-4000-8000-000000000001";
const release="c7000000-0000-4000-8000-000000000001";
const base="/api/valoria/learning/courses/"+ce;
const hash=secret=>createHash("sha256").update(secret).digest();
const bundleFile=process.env.S03_QA_REAL_IDENTITY_BUNDLE;
assert.ok(bundleFile&&path.isAbsolute(bundleFile),"REAL Keycloak QA identity bundle required");
const bundle=JSON.parse(fs.readFileSync(bundleFile,"utf8"));
assert.match(bundle.productCookie,/^[0-9a-f]{64}$/);
assert.equal(bundle.issuer,"https://127.0.0.1:18443/realms/omnilyzer-auth-spike");
assert.ok(bundle.sub.length>=8);
const secret=bundle.productCookie;
const bridge="/tmp/omnilyzer-platform-identity-p0-20261029/services/identity/tests/qa_keycloak_native_bridge.py";
const python="/tmp/omnilyzer-platform-identity-p0-20261029/.venv/bin/python";
const bridgeCall=(mode,cookie="")=>execFileSync(python,[bridge,mode],{
 env:{...process.env,S03_QA_BROWSER_COOKIE_HEADER:cookie},encoding:"utf8",timeout:25000
}).trim();
async function connect(user="postgres"){
 const c=new Client({host:socket,database,user});await c.connect();return c;
}
async function main(){
 const admin=await connect();let app,browser;const calls=[],errors=[],foreign=[];
 const sigs=[
  "sumlaude_auth.reader_learning_context()",
  "sumlaude_auth.reader_current_course(uuid)",
  "sumlaude_auth.reader_noncredit_progress(uuid)",
  "sumlaude_auth.reader_native_content(uuid,text,text)",
  "sumlaude_auth.submit_noncredit_evidence(uuid,uuid,text,uuid,jsonb)",
  "sumlaude_auth.verified_learner_session(bytea)"
 ];
 try{
  await admin.query("BEGIN");
  try{
   await admin.query("INSERT INTO public.users(id,email,password_hash,is_active,email_verified,account_status) VALUES($1,'browser-qa@sumlaude.invalid','INERT_QA_PASSWORD',true,true,'active')",[owner]);
   await admin.query("INSERT INTO public.valoria_memberships(organization_id,user_id,role,status) VALUES($1,$2,'learner','active')",[org,owner]);
   await admin.query("INSERT INTO public.valoria_program_enrollments(id,user_id,organization_id,program_id,status) VALUES($1,$2,$3,$4,'active')",[pe,owner,org,prog]);
   await admin.query("INSERT INTO public.valoria_course_enrollments(id,program_enrollment_id,program_id,course_id,status) VALUES($1,$2,$3,$4,'active')",[ce,pe,prog,course]);
   await admin.query("INSERT INTO public.valoria_active_learning_contexts(user_id,program_enrollment_id) VALUES($1,$2)",[owner,pe]);
   await admin.query("INSERT INTO sumlaude_private.external_identity_links(user_id,issuer,subject) VALUES($1,$2,$3)",[owner,bundle.issuer,bundle.sub]);
   await admin.query("INSERT INTO sumlaude_private.learner_admission(user_id,age_class,assurance,jurisdiction,decision_reference,policy_version,approved_at,expires_at) VALUES($1,'minor','verified_guardian','PH','fictional-browser-only-1004','qa-v1',now(),now()+interval '1 day')",[owner]);
   await admin.query("INSERT INTO sumlaude_private.learner_sessions(user_id,jti_sha256,expires_at) VALUES($1,$2,now()+interval '20 minutes')",[owner,hash(secret)]);
   await admin.query("COMMIT");
  }catch(e){await admin.query("ROLLBACK");throw e;}
  const proof=Buffer.from((await admin.query("SELECT encode(key_bytes,'hex') k FROM sumlaude_private.scope_keys WHERE key_version='v1'")).rows[0].k,"hex");
  for(const sig of sigs)await admin.query("GRANT EXECUTE ON FUNCTION "+sig+" TO sumlaude_qa_app");
  app=Fastify({logger:false});
  await app.register(routes.registerSumlaudeOpaqueBffQa,{
   open:()=>connect("sumlaude_qa_app"),close:async c=>c.end(),
   dbProofKey:proof,csrfKey:randomBytes(48)
  });await app.ready();
  browser=await chromium.launch({headless:true,args:["--no-sandbox","--disable-dev-shm-usage"]});
  const context=await browser.newContext({viewport:{width:390,height:844}});
  await context.addCookies([{
   name:"__Host-sumlaude_session",value:secret,url:"https://app.sumlaude.com",
   secure:true,httpOnly:true,sameSite:"Lax"
  },{
   name:"__Host-omnilyzer_identity",value:bundle.identityCookie,url:"https://app.sumlaude.com",
   secure:true,httpOnly:true,sameSite:"Lax"
  }]);
  const origin="https://app.sumlaude.com";
  // The real signed Keycloak callback ran in the permanent Django BFF.
  // A TEST-ONLY forced 503 first checks the fail-closed identity boundary.
  // Positive session state is read from actual Django PostgreSQL, never stubbed.
  let platformSessionAvailable=false;
  await context.route("**/*",async route=>{
   const req=route.request(),url=new URL(req.url());
   if(url.origin!==origin){foreign.push(req.url());return route.abort();}
   const pathname=url.pathname;
   if(pathname==="/auth/session"){
    if(!platformSessionAvailable){
     calls.push({method:req.method(),path:pathname,status:503});
     return route.fulfill({status:503,contentType:"application/json",
      headers:{"cache-control":"no-store"},body:'{"code":"SHARED_IDENTITY_UNAVAILABLE"}'});
    }
    const headers=await req.allHeaders();
    const result=JSON.parse(bridgeCall("status",headers.cookie||""));
    assert.equal(typeof result.authenticated,"boolean");
    calls.push({method:req.method(),path:pathname,status:200,
     verifiedFrom:"real-Django-PostgreSQL"});
    return route.fulfill({status:200,contentType:"application/json",
     headers:{"cache-control":"no-store"},body:JSON.stringify(result)});
   }
   if(pathname.startsWith("/api/")){
    const method=req.method(),headers={...await req.allHeaders()};
    // Browser content-length should not override Fastify inject's payload.
    delete headers["content-length"];delete headers["host"];
    const r=await app.inject({method,url:pathname+url.search,headers,
     ...(req.postData()?{payload:req.postData()}:{})});
    calls.push({method,path:pathname,status:r.statusCode});
    return route.fulfill({status:r.statusCode,headers:{
     "content-type":r.headers["content-type"]||"application/json",
     "cache-control":"private, no-store"
    },body:r.body});
   }
   if(pathname==="/"||pathname==="/index.html")
    return route.fulfill({status:200,contentType:"text/html",
     body:fs.readFileSync(path.join(build,"index.html"))});
   if(/^\/assets\/[A-Za-z0-9_.-]+\.(js|css)$/.test(pathname)){
    const file=path.join(build,pathname.slice(1));
    return route.fulfill({status:200,
     contentType:pathname.endsWith(".js")?"application/javascript":"text/css",
     body:fs.readFileSync(file)});
   }
   return route.fulfill({status:404,body:"not found"});
  });
  const page=await context.newPage();
  page.setDefaultTimeout(16000);
  page.on("pageerror",e=>errors.push(e.message));
  await page.goto(origin+"/");
  await page.getByRole("heading",{name:"Secure sign-in is unavailable"}).waitFor();
  assert.equal(calls.filter(c=>c.path.startsWith("/api/")).length,0,
   "Failed platform identity MUST NOT invoke S03, even with valid S03 cookie");
  assert.equal(await page.locator("[aria-label='Account session']").count(),0);
  assert.equal(await page.getByText(/This is not full LC1 completion/).count(),0);
  console.log("CHROMIUM_PLATFORM_SESSION_503_DENIAL_PASS no_native_requests");
  // Positive identity is a FICTIONAL platform response, not Keycloak proof.
  platformSessionAvailable=true;
  await page.getByRole("button",{name:"Retry secure sign-in"}).click();
  const activity=async a=>{
   await page.getByRole("heading",{name:a.title}).waitFor();
   if(a.type==="reading"){
    await page.getByRole("button",{name:"Mark reading complete"}).click();
   }else{
    const count=original.questions.filter(q=>q.activityId===a.id).length;
    for(let j=0;j<count;j++){
     await page.getByRole("radio").first().check();
     if(j<count-1)await page.getByRole("button",{name:"Next question"}).click();
    }
    await page.getByRole("button",{name:"Save complete activity"}).click();
   }
  };
  for(const [idx,u] of units.entries()){
   for(const a of u.activities.filter(x=>steps.some(s=>s.id===x.id)))
    await activity(a);
   await page.getByRole("heading",{name:"Native unit activities recorded"}).waitFor();
   // Six original author-written reflections / review prompts are now
   // visible, with no automatic score/submission or saved written answer.
   for(const manual of u.activities.filter(x=>["reflection","review"].includes(x.type))){
    await page.getByRole("heading",{name:manual.title}).waitFor();
    await page.getByText(manual.prompt,{exact:true}).waitFor();
   }

   if(idx<units.length-1)
    await page.getByRole("button",{name:idx===3?"Open optional recall":"Continue available noncredit practice"}).click();
  }
  await page.getByText(/This is not full LC1 completion/).waitFor();
  const posted=calls.filter(c=>c.method==="POST"&&c.path.endsWith("/submissions"));
  assert.deepEqual(posted.map(p=>p.status),Array(7).fill(200));
  const saved=(await admin.query("SELECT activity_id,credit_eligible,xp_delta FROM public.valoria_learning_evidence WHERE user_id=$1 ORDER BY activity_id",[owner])).rows;
  assert.deepEqual(saved.map(s=>s.activity_id).sort(),steps.map(s=>s.id).sort());
  assert.ok(saved.every(s=>!s.credit_eligible&&Number(s.xp_delta)===0));
  const answers=await admin.query("SELECT count(*)::integer n FROM public.valoria_evidence_answers a JOIN public.valoria_learning_evidence e ON e.id=a.evidence_id WHERE e.user_id=$1",[owner]);
  assert.equal(answers.rows[0].n,11);
  console.log("CHROMIUM_LC1_REAL_BFF_PG16_UI_PASS steps=7 questions=11 units=5 mobile=390x844");
  const before=posted.length;
  await page.setViewportSize({width:1440,height:900});
  await page.reload();
  await page.getByText(/This is not full LC1 completion/).waitFor();
  assert.equal(calls.filter(c=>c.method==="POST"&&c.path.endsWith("/submissions")).length,before);
  console.log("CHROMIUM_REAL_BFF_RELOAD_PASS desktop=1440x900 no_duplicate_POST");
  // S01's newest focus/visibility correction must invalidate the mounted
  // lesson BEFORE rechecking the platform session, without a full page load.
  // Keep the real S03 learner cookie valid throughout this failure.
  const beforeFocusApi=calls.filter(c=>c.path.startsWith("/api/")).length;
  const beforeFocusPosts=calls.filter(c=>c.method==="POST").length;
  platformSessionAvailable=false;
  await page.evaluate(()=>window.dispatchEvent(new Event("focus")));
  await page.getByRole("heading",{name:"Secure sign-in is unavailable"}).waitFor();
  assert.equal(await page.getByText(/This is not full LC1 completion/).count(),0,
    "Learner content must disappear on tab return after platform logout");
  assert.equal(calls.filter(c=>c.path.startsWith("/api/")).length,beforeFocusApi,
    "Focus-triggered platform rejection must never reach S03 private APIs");
  assert.equal(calls.filter(c=>c.method==="POST").length,beforeFocusPosts);
  platformSessionAvailable=true;
  await page.getByRole("button",{name:"Retry secure sign-in"}).click();
  await page.getByText(/This is not full LC1 completion/).waitFor();
  assert.equal(calls.filter(c=>c.method==="POST").length,beforeFocusPosts);
  console.log("CHROMIUM_PLATFORM_TAB_RETURN_DENIAL_PASS no_private_api no_duplicate_post");
  // Simulate loss of ORIGINAL platform identity while the S03 digest remains
  // valid. The complete cached lesson and any S03 API request must disappear.
  const beforeIdentityOutage=calls.filter(c=>c.path.startsWith("/api/")).length;
  platformSessionAvailable=false;
  await page.reload();
  await page.getByRole("heading",{name:"Secure sign-in is unavailable"}).waitFor();
  assert.equal(calls.filter(c=>c.path.startsWith("/api/")).length,beforeIdentityOutage);
  assert.equal(await page.getByText(/This is not full LC1 completion/).count(),0);
  console.log("CHROMIUM_PLATFORM_SESSION_LOSS_DENIAL_PASS no_native_requests no_stale_content");
  platformSessionAvailable=true;
  await page.getByRole("button",{name:"Retry secure sign-in"}).click();
  await page.getByText(/This is not full LC1 completion/).waitFor();
  assert.equal(calls.filter(c=>c.method==="POST"&&c.path.endsWith("/submissions")).length,before);
  await admin.query("UPDATE sumlaude_private.learner_sessions SET revoked_at=clock_timestamp() WHERE user_id=$1",[owner]);
  await page.reload();
  await page.getByRole("heading",{name:"Learning unavailable"}).waitFor();
  assert.equal(await page.getByText(/This is not full LC1 completion/).count(),0);
  assert.equal(calls.filter(c=>c.method==="POST").length,before);
  assert.deepEqual(errors,[]);assert.deepEqual(foreign,[]);
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  console.log("CHROMIUM_REAL_BFF_REVOKED_SESSION_PASS no_stale_private_content no_browser_storage");
  // Complete the SAME actual provider-backed Django session and confirm
  // Chromium's old host-only identity cookie cannot remount private Native.
  const cookieHeader="__Host-omnilyzer_identity="+bundle.identityCookie+
   "; __Host-sumlaude_session="+secret;
  const end=bridgeCall("logout",cookieHeader);
  assert.match(end,/REAL_KEYCLOAK_DJANGO_POSTGRES_LOGOUT_QA_PASS/);
  const beforeLogoutApi=calls.filter(c=>c.path.startsWith("/api/")).length;
  await page.reload();
  await page.getByRole("heading",{name:"Sign in to study"}).waitFor();
  assert.equal(calls.filter(c=>c.path.startsWith("/api/")).length,beforeLogoutApi);
  assert.deepEqual(errors,[]);assert.deepEqual(foreign,[]);
  console.log("REAL_KEYCLOAK_TO_S01_FULL_LC1_LOGOUT_DENIAL_PASS");
  console.log("REAL_KEYCLOAK_TO_S01_FULL_LC1_CHROMIUM_QA_PASS",sourceSha);
 }finally{
  try{await browser?.close()}catch{}
  try{await app?.close()}catch{}
  for(const sig of sigs){
   try{await admin.query("REVOKE EXECUTE ON FUNCTION "+sig+" FROM sumlaude_qa_app")}catch(e){console.error("REVOKE FAILED",sig,e.message);throw e;}
  }
  await admin.end();
 }
}
main().catch(e=>{console.error("S03_S01_CHROMIUM_PG16_FAIL",e.stack||e.message);process.exitCode=1;});
