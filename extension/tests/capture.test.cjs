const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { setImmediate } = require("node:timers/promises");
const test = require("node:test");
const vm = require("node:vm");

const background = fs.readFileSync(path.join(__dirname, "../background.js"), "utf8");

function startWorker(listenerFetch) {
  const storage = {};
  const callbacks = {};
  const listen = (name) => ({
    addListener(callback) { callbacks[name] = callback; },
  });
  const chrome = {
    tabs: { onActivated: listen("tab") },
    webNavigation: { onCompleted: listen("navigation") },
    cookies: { onChanged: listen("cookie") },
    webRequest: { onCompleted: listen("request") },
    downloads: { onCreated: listen("download") },
    runtime: { onMessage: listen("message") },
    storage: {
      session: {
        async get(key) { return structuredClone({ [key]: storage[key] }); },
        async set(value) { Object.assign(storage, structuredClone(value)); },
      },
    },
  };
  const context = vm.createContext({ chrome, fetch: listenerFetch, URL, AbortSignal, console });
  vm.runInContext(background, context);
  return {
    callbacks,
    storage,
    sendLog: vm.runInContext("sendLog", context),
    async flush() {
      await setImmediate();
      await vm.runInContext("statsWrite", context);
    },
  };
}

test("counts overlapping deliveries, listener rejections, and unavailable delivery", async () => {
  const responses = [200, 500, null, 200];
  const worker = startWorker(async (_url, { signal }) => {
    assert.equal(signal.aborted, false);
    const status = responses.shift();
    if (status === null) throw new Error("listener offline");
    return new Response(null, { status });
  });

  await Promise.all([
    worker.sendLog({ type: "navigation" }),
    worker.sendLog({ type: "navigation" }),
    worker.sendLog({ type: "tab" }),
    worker.sendLog({ type: "tab" }),
  ]);

  assert.deepEqual(worker.storage.captureStats, {
    delivered: 2, rejected: 1, unavailable: 1, suppressed: 0,
    byType: { navigation: 1, tab: 1 },
  });
});

test("reports throttling only for eligible repeated requests", async () => {
  const worker = startWorker(async () => new Response(null, { status: 200 }));
  const request = {
    url: "https://tracker.example.test/event",
    type: "xmlhttprequest",
    initiator: "https://example.test",
  };
  worker.callbacks.request(request);
  worker.callbacks.request({ ...request, type: "image" });
  worker.callbacks.request(request);
  await worker.flush();

  assert.equal(worker.storage.captureStats.delivered, 1);
  assert.equal(worker.storage.captureStats.suppressed, 1);
});

test("only forwards supported page fields and assigns the tab URL", async () => {
  const events = [];
  const worker = startWorker(async (_url, { body }) => {
    events.push(JSON.parse(body));
    return new Response(null, { status: 200 });
  });
  const sender = { tab: { url: "https://example.test" } };
  worker.callbacks.message({ __bf: true, payload: { type: "navigation" } }, sender);
  worker.callbacks.message({
    __bf: true,
    payload: { type: "permission", permission: "camera", url: "https://override.test", id: "external" },
  }, sender);
  await worker.flush();

  assert.equal(events.length, 1);
  assert.equal(events[0].source, "page-observation");
  assert.equal(events[0].permission, "camera");
  assert.equal(events[0].url, sender.tab.url);
  assert.equal(events[0].domain, "example.test");
  assert.equal(Object.hasOwn(events[0], "id"), false);
});
