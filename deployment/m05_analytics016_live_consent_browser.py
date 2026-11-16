"""Read-only Firefox consent OAT against the private signed DEV tracker.

Uses an empty temporary browser profile. Collector fetches are intercepted;
the real collector HTTP/PG acceptance is recorded separately. No test account,
real site key, credential, production URL or application configuration change.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request

BASE = 'http://127.0.0.1:3141'


def main():
    with tempfile.TemporaryDirectory(prefix='m05-016-consent-', dir='/home/omnigpt') as folder:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        log = open(Path(folder) / 'geckodriver.log', 'wb')
        driver = subprocess.Popen(['/snap/bin/geckodriver', '--host', '127.0.0.1', '--port', str(port)],
                                  stdout=log, stderr=subprocess.STDOUT)
        endpoint = 'http://127.0.0.1:' + str(port)
        session = None
        def call(method, path, body=None):
            data = None if body is None else json.dumps(body).encode()
            req = urllib.request.Request(endpoint + path, data=data, method=method,
                                         headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=45) as response:
                value = json.load(response)['value']
            if isinstance(value, dict) and 'error' in value:
                raise RuntimeError(value['error'])
            return value
        def execute(script, *args):
            return call('POST', '/session/' + session + '/execute/sync', {'script': script, 'args': args})
        def check(name, condition):
            if not condition:
                raise RuntimeError(name)
            print('LIVE_FIREFOX_CONSENT_PASS', name, flush=True)
        def load(mode):
            return call('POST', '/session/' + session + '/execute/async', {
                'script': '''const mode=arguments[0],done=arguments[arguments.length-1];
const s=document.createElement('script');s.src='/api/v1/collect/script.js';
s.dataset.site='0123456789abcdef0123456789abcdef';s.dataset.requireConsent=mode;
s.dataset.consentGranted='false';s.dataset.allowedPaths='/';
s.onload=()=>{window.__m05Script=s;done(true)};s.onerror=()=>done(false);
document.head.appendChild(s);''', 'args': [mode]})
        try:
            for _ in range(100):
                try:
                    call('GET', '/status')
                    break
                except Exception:
                    if driver.poll() is not None:
                        raise RuntimeError('geckodriver terminated')
                    time.sleep(0.1)
            result = call('POST', '/session', {'capabilities': {'alwaysMatch': {
                'browserName': 'firefox', 'moz:firefoxOptions': {'args': ['-headless']}}}})
            session = result['sessionId']
            print('LIVE_FIREFOX_VERSION', result['capabilities']['browserVersion'], flush=True)
            call('POST', '/session/' + session + '/url', {'url': BASE + '/'})
            execute('''window.__m05Calls=[];window.__m05Fetch=window.fetch;
window.fetch=function(url,opts){if(String(url).includes('/api/v1/collect/')){
window.__m05Calls.push({credentials:opts.credentials,method:opts.method,path:JSON.parse(opts.body).path});
return Promise.resolve(new Response(null,{status:202}));}return window.__m05Fetch.apply(this,arguments)};
localStorage.removeItem('omnilyzer-cookie-consent');sessionStorage.removeItem('omnilyzer_analytics_session');
history.replaceState(null,'','/');''')
            check('external_live_script_loaded', load('external'))
            check('external_no_consent_no_emit_or_session', execute("return __m05Calls.length===0&&!sessionStorage.getItem('omnilyzer_analytics_session')"))
            execute("__m05Script.dataset.consentGranted='true';dispatchEvent(new Event('omnilyzer-consent-updated'))")
            check('external_affirmative_emits_without_credentials', execute("return __m05Calls.length===1&&__m05Calls[0].credentials==='omit'&&__m05Calls[0].method==='POST'"))
            execute("__m05Script.dataset.consentGranted='false';history.replaceState(null,'','/withdrawn/');dispatchEvent(new Event('popstate'))")
            check('external_withdrawal_stops_emission', execute('return __m05Calls.length===1'))
            execute("history.replaceState(null,'','/');sessionStorage.removeItem('omnilyzer_analytics_session')")
            check('native_live_script_loaded', load('omnilyzer'))
            check('native_no_consent_no_emit_or_session', execute("return __m05Calls.length===1&&!sessionStorage.getItem('omnilyzer_analytics_session')"))
            execute("localStorage.setItem('omnilyzer-cookie-consent',JSON.stringify({preferences:{essential:true,analytics:true,functional:false,marketing:false}}));dispatchEvent(new Event('omnilyzer-consent-updated'))")
            check('native_affirmative_emits', execute('return __m05Calls.length===2'))
            execute("localStorage.setItem('omnilyzer-cookie-consent',JSON.stringify({preferences:{essential:true,analytics:false,functional:false,marketing:false}}));history.replaceState(null,'','/withdrawn/');dispatchEvent(new Event('omnilyzer-consent-updated'))")
            check('native_withdrawal_stops_emission', execute('return __m05Calls.length===2'))
            execute("localStorage.setItem('omnilyzer-cookie-consent',JSON.stringify({preferences:{essential:true,analytics:true,functional:false,marketing:false}}));history.replaceState(null,'','/private/qa/');dispatchEvent(new Event('popstate'))")
            check('exact_public_path_allowlist_excludes_private', execute('return __m05Calls.length===2'))
            with urllib.request.urlopen(BASE + '/api/v1/collect/script.js', timeout=5) as response:
                print('LIVE_TRACKER_SHA256', hashlib.sha256(response.read(32769)).hexdigest(), flush=True)
            print('LIVE_FIREFOX_CONSENT_COMPLETE_PASS collector_fetches_intercepted=true', flush=True)
        finally:
            if session is not None:
                try:
                    call('DELETE', '/session/' + session)
                except Exception:
                    pass
            driver.terminate()
            try:
                driver.wait(timeout=10)
            except subprocess.TimeoutExpired:
                driver.kill()
                driver.wait(timeout=5)
            log.close()


if __name__ == '__main__':
    main()
