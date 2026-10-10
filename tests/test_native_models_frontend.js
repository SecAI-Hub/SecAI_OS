/* Run with: node tests/test_native_models_frontend.js (no browser dependencies). */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../services/ui/ui/templates/models.html'), 'utf8');
const script = html.match(/<script nonce="\{\{ csp_nonce \}\}">([\s\S]*?)<\/script>/)[1];
function element() {
    return {innerHTML: '', textContent: '', value: '', disabled: false, style: {}, listeners: {},
        classList: {add() {}, remove() {}, toggle() {}},
        addEventListener(event, fn) {this.listeners[event] = fn;},
        contains() {return false;}, querySelectorAll() {return [];}, getAttribute() {return null;}, focus() {}, click() {}};
}
const esc = value => String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[char]));
const response = (status, payload) => ({status, ok: status >= 200 && status < 300, json: async () => payload});
(async () => {
    const elements = new Map();
    const calls = [];
    let handler = async () => response(200, []);
    let modelsHandler = async () => response(200, []);
    const context = vm.createContext({
        document: {activeElement: null, getElementById(id) {
            if (!elements.has(id)) elements.set(id, element());
            return elements.get(id);
        }, createElement: element},
        setTimeout() {return 1;}, setInterval() {return 1;},
        fetch: async url => {
            calls.push(url);
            if (url === '/api/models/quarantine') return handler();
            if (url === '/api/models') return modelsHandler();
            return response(200, url === '/api/catalog' || url === '/api/models' ? [] : {});
        }, esc, formatBytes: value => value + ' B', toast() {}, showConfirm: async () => false,
    });
    vm.runInContext(script, context);
    await new Promise(resolve => setImmediate(resolve));
    const panel = elements.get('quarantine-list');
    assert.match(panel.innerHTML, /No files pending\./);
    handler = async () => response(200, [{filename: '<img src=x onerror=alert(1)>', size_bytes: 7}]);
    await context.loadQuarantine();
    assert.match(panel.innerHTML, /&lt;img src=x onerror=alert\(1\)&gt;/);
    assert.doesNotMatch(panel.innerHTML, /<img/);
    assert.match(panel.innerHTML, /scanning/);
    assert.match(panel.innerHTML, /7 B/);
    let parsed = false;
    handler = async () => ({status: 401, ok: false, json: async () => {
        parsed = true; return {error: '<img src=x>'};
    }});
    await context.loadQuarantine();
    assert.equal(parsed, false);
    assert.match(panel.innerHTML, /Sign in again/);
    assert.match(panel.innerHTML, /href="\/login"/);
    assert.doesNotMatch(panel.innerHTML, /No files pending|<img|scanning/);
    const failures = [
        ['HTTP 500', async () => response(500, {error: '<img src=x>'})],
        ['HTTP failure with empty array', async () => response(503, [])],
        ['non-array object', async () => response(200, {error: '<img src=x>'})],
        ['null payload', async () => response(200, null)],
        ['string payload', async () => response(200, '[]')],
        ['malformed JSON', async () => ({status: 200, ok: true, json: async () => {throw new SyntaxError('bad JSON');}})],
        ['transport rejection', async () => {throw new Error('network failure');}],
    ];
    for (const [name, fn] of failures) {
        handler = fn;
        await context.loadQuarantine();
        assert.match(panel.innerHTML, /Quarantine status is unavailable/, name);
        assert.match(panel.innerHTML, /role="alert"/, name);
        assert.match(panel.innerHTML, /data-action="quarantine-retry"/, name);
        assert.doesNotMatch(panel.innerHTML, /No files pending|<img|scanning/, name);
    }
    const before = calls.filter(url => url === '/api/models/quarantine').length;
    handler = async () => response(200, []);
    await panel.listeners.click({target: {closest: () => ({getAttribute: () => 'quarantine-retry'})}});
    assert.equal(calls.filter(url => url === '/api/models/quarantine').length, before + 1);
    assert.match(panel.innerHTML, /No files pending\./);
    assert.doesNotMatch(panel.innerHTML, /unavailable|Sign in/);
    handler = async () => response(200, [{filename: 'pending.gguf', size_bytes: 42}]);
    await context.loadQuarantine();
    assert.match(panel.innerHTML, /pending\.gguf/);
    assert.doesNotMatch(panel.innerHTML, /unavailable|No files pending/);
    const modelsPanel = elements.get('models-list');
    const registered = [{name: '<img src=x onerror=alert(1)>', format: 'gguf', filename: 'safe.gguf', size_bytes: 42}];
    modelsHandler = async () => response(200, registered);
    await context.loadModels();
    assert.match(modelsPanel.innerHTML, /&lt;img src=x onerror=alert\(1\)&gt;/);
    assert.doesNotMatch(modelsPanel.innerHTML, /<img/);
    assert.match(modelsPanel.innerHTML, /Use in Chat|Verify Hash/);
    assert.equal(context.trustedModels.length, 1);
    let modelsParsed = false;
    modelsHandler = async () => ({status: 401, ok: false, json: async () => {
        modelsParsed = true; return {error: '<img src=x>'};
    }});
    await context.loadModels();
    assert.equal(modelsParsed, false);
    assert.equal(context.trustedModels.length, 0);
    assert.match(modelsPanel.innerHTML, /Sign in again/);
    assert.match(modelsPanel.innerHTML, /href="\/login"/);
    assert.doesNotMatch(modelsPanel.innerHTML, /No models registered|<img|Use in Chat/);
    for (const [name, fn] of failures) {
        modelsHandler = async () => response(200, registered);
        await context.loadModels();
        modelsHandler = fn;
        await context.loadModels();
        assert.equal(context.trustedModels.length, 0, name);
        assert.match(modelsPanel.innerHTML, /Trusted models are unavailable/, name);
        assert.match(modelsPanel.innerHTML, /role="alert"/, name);
        assert.match(modelsPanel.innerHTML, /data-action="models-retry"/, name);
        assert.doesNotMatch(modelsPanel.innerHTML, /No models registered|<img|Use in Chat/, name);
    }
    const modelsBefore = calls.filter(url => url === '/api/models').length;
    modelsHandler = async () => response(200, []);
    await modelsPanel.listeners.click({target: {closest: () => ({getAttribute: () => 'models-retry'})}});
    assert.equal(calls.filter(url => url === '/api/models').length, modelsBefore + 1);
    assert.match(modelsPanel.innerHTML, /No models registered/);
    assert.doesNotMatch(modelsPanel.innerHTML, /unavailable|Sign in/);
    modelsHandler = async () => response(200, registered);
    await context.loadModels();
    assert.equal(context.trustedModels.length, 1);
    assert.match(modelsPanel.innerHTML, /Use in Chat/);
    const catalogPanel = elements.get('catalog-list');
    modelsHandler = async () => response(503, []);
    await context.loadCatalog();
    assert.match(catalogPanel.innerHTML, /unavailable/i);
    assert.match(catalogPanel.innerHTML, /catalog-refresh/);
    assert.doesNotMatch(catalogPanel.innerHTML, /Local state recovery/);
    assert.doesNotMatch(catalogPanel.innerHTML, /No catalog entries configured/);
    modelsHandler = async () => response(401, {error: 'private details'});
    await context.loadCatalog();
    assert.match(catalogPanel.innerHTML, /Sign in/i);
    assert.doesNotMatch(catalogPanel.innerHTML, /private details/);
    modelsHandler = async () => response(200, {});
    await context.loadCatalog();
    assert.match(catalogPanel.innerHTML, /unavailable/i);
    modelsHandler = async () => response(200, []);
    await catalogPanel.listeners.click({target: {closest: () => ({getAttribute: () => 'catalog-refresh'})}});
    assert.match(catalogPanel.innerHTML, /No catalog entries configured/);
    console.log('Models frontend: quarantine and trusted list/empty, session expiry, HTTP/JSON/transport failures, escaped content, stale-cache clearing and retry recovery passed.');
})().catch(error => {console.error(error); process.exitCode = 1;});
