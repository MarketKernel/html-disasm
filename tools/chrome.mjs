/**
 * Headless Chrome over the DevTools protocol, for the browser tests and the
 * screenshots. No puppeteer: the installed Chrome is started with
 * --remote-debugging-port=0 and spoken to over Node's built-in WebSocket.
 *
 *   const browser = await launch();            // null when no Chrome is found
 *   await browser.open('file:///…/build/disassembler.html');
 *   await browser.until('document.title.includes("x")');
 *   await browser.setFile('#file-input', '/path/to/program');
 *   await browser.shot('shots/listing.png');
 *   await browser.close();
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const CHROME =
  process.env.CHROME ??
  ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Chromium.app/Contents/MacOS/Chromium', '/usr/bin/google-chrome', '/usr/bin/chromium'].find((path) =>
    existsSync(path),
  );

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function launch({ width = 1440, height = 900 } = {}) {
  if (!CHROME) return null;
  const profile = await mkdtemp(join(tmpdir(), 'disasm-chrome-'));
  const flags = ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', `--window-size=${width},${height}`, '--hide-scrollbars'];
  if (process.platform === 'linux') flags.push('--no-sandbox');
  const chrome = spawn(CHROME, [...flags, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const wsUrl = await new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error('Chrome did not start')), 20000);
    chrome.stderr.on('data', (d) => {
      buf += d;
      const m = /DevTools listening on (ws:\/\/\S+)/.exec(buf);
      if (m) {
        clearTimeout(timer);
        resolve(m[1]);
      }
    });
  });
  const port = new URL(wsUrl).port;
  const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  const page = targets.find((t) => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve) => ws.addEventListener('open', resolve));

  let id = 0;
  const waiting = new Map();
  const errors = [];
  ws.addEventListener('message', (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && waiting.has(msg.id)) {
      waiting.get(msg.id)(msg);
      waiting.delete(msg.id);
    } else if (msg.method === 'Runtime.exceptionThrown') {
      errors.push(msg.params.exceptionDetails.exception?.description ?? msg.params.exceptionDetails.text);
    } else if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
      errors.push(msg.params.entry.text);
    } else if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
      errors.push(msg.params.args.map((a) => a.value ?? a.description).join(' '));
    }
  });
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const n = ++id;
      waiting.set(n, (msg) => (msg.error ? reject(new Error(`${method}: ${JSON.stringify(msg.error)}`)) : resolve(msg.result)));
      ws.send(JSON.stringify({ id: n, method, params }));
    });
  await send('Runtime.enable');
  await send('Log.enable');
  await send('Page.enable');
  await send('DOM.enable');

  const evaluate = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`${expression}\n${r.exceptionDetails.exception?.description ?? 'evaluation failed'}`);
    return r.result.value;
  };

  const browser = {
    errors,
    send,
    evaluate,
    async open(url) {
      await send('Page.navigate', { url });
      await browser.until('document.readyState === "complete" && document.documentElement.hasAttribute("data-ready")');
    },
    /** Polls an expression until it is truthy. Wrap expressions with ?? or || in parentheses. */
    async until(expression, timeout = 15000) {
      const end = Date.now() + timeout;
      let last;
      while (Date.now() < end) {
        try {
          if (await evaluate(expression)) return true;
        } catch (error) {
          last = error;
          if (!/navigated or closed|Cannot find context|context was destroyed/.test(error.message)) throw error;
        }
        await sleep(50);
      }
      throw new Error(`timed out waiting for: ${expression}${last ? `\n${last.message}` : ''}`);
    },
    async viewport(width, height, mobile = false) {
      await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: mobile ? 3 : 2, mobile });
    },
    async theme(scheme) {
      await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: scheme }] });
    },
    /** Hands a local file to an <input type=file>, as picking it would. */
    async setFile(selector, path) {
      const { result } = await send('Runtime.evaluate', { expression: `document.querySelector(${JSON.stringify(selector)})` });
      await send('DOM.setFileInputFiles', { files: [path], objectId: result.objectId });
    },
    /** A mouse click at the middle of an element, as a person would. */
    async click(selector) {
      const box = await evaluate(`(() => { const r = document.querySelector(${JSON.stringify(selector)})?.getBoundingClientRect(); return r && { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
      if (!box) throw new Error(`nothing to click at ${selector}`);
      for (const type of ['mousePressed', 'mouseReleased']) await send('Input.dispatchMouseEvent', { type, x: box.x, y: box.y, button: 'left', clickCount: 1 });
    },
    /** A drag from the middle of an element, `dx` pixels across, in a few moves as a hand would. */
    async drag(selector, dx) {
      const box = await evaluate(`(() => { const r = document.querySelector(${JSON.stringify(selector)})?.getBoundingClientRect(); return r && { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
      if (!box) throw new Error(`nothing to drag at ${selector}`);
      await send('Input.dispatchMouseEvent', { type: 'mousePressed', x: box.x, y: box.y, button: 'left', buttons: 1, clickCount: 1 });
      for (let step = 1; step <= 5; step++) await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x + (dx * step) / 5, y: box.y, button: 'left', buttons: 1 });
      await send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: box.x + dx, y: box.y, button: 'left', buttons: 0, clickCount: 1 });
    },
    async press(key, code = key, modifiers = 0) {
      const text = key.length === 1 ? key : undefined;
      await send('Input.dispatchKeyEvent', { type: 'keyDown', key, code, modifiers, text, windowsVirtualKeyCode: VK[key] ?? (key.length === 1 ? key.toUpperCase().charCodeAt(0) : 0) });
      await send('Input.dispatchKeyEvent', { type: 'keyUp', key, code, modifiers, windowsVirtualKeyCode: VK[key] ?? 0 });
    },
    async type(text) {
      await send('Input.insertText', { text });
    },
    async wheel(selector, deltaY) {
      const box = await evaluate(`(() => { const r = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
      await send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: box.x, y: box.y, deltaX: 0, deltaY });
    },
    /** Lets the page download files into `dir` (returns the folder). */
    async downloadsTo(dir) {
      await send('Page.setDownloadBehavior', { behavior: 'allow', downloadPath: dir });
      return dir;
    },
    async shot(path) {
      await sleep(250);
      const { data } = await send('Page.captureScreenshot', { format: 'png' });
      await writeFile(path, Buffer.from(data, 'base64'));
    },
    async close() {
      ws.close();
      chrome.kill();
      await sleep(200);
      await rm(profile, { recursive: true, force: true }).catch(() => {});
    },
  };
  return browser;
}

const VK = { Enter: 13, Escape: 27, ArrowDown: 40, ArrowUp: 38, ArrowLeft: 37, ArrowRight: 39, PageDown: 34, PageUp: 33, Home: 36, End: 35, Tab: 9 };
