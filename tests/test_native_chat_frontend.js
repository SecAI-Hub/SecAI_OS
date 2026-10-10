/* Run with: node tests/test_native_chat_frontend.js (no browser dependencies). */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '../services/ui/ui/templates/index.html'), 'utf8');
const script = html.match(/<script nonce="\{\{ csp_nonce \}\}">([\s\S]*?)<\/script>/)[1];
const requestId = 'a'.repeat(32);
function status(loaded, selection = {}) {
    return {available: !!loaded, automation_available: true, deployment_mode: 'appliance',
        model_selection: selection, chat_models: ['a.gguf', 'b.gguf'].map(filename => ({
            filename, name: filename, usable: filename === loaded, loaded: filename === loaded,
        }))};
}
function element() {
    return {value: '', disabled: false, style: {}, listeners: {}, options: [], selectedIndex: 0,
        classList: {add() {}, toggle() {}}, addEventListener(event, fn) {this.listeners[event] = fn;},
        focus() {}, remove() {}, appendChild() {},
        get innerHTML() {return this.html || '';},
        set innerHTML(value) {
            this.html = value;
            this.options = [...value.matchAll(/<option value="([^"]*)"[^>]*>/g)].map(match => ({
                value: match[1], getAttribute(name) {
                    return (match[0].match(new RegExp(name + '="([^"]*)"')) || [,''])[1];
                },
            }));
            this.value = this.options[0]?.value || '';
        },
    };
}
async function harness() {
    const elements = new Map();
    const feedback = [];
    const calls = [];
    let now = 0;
    let handler = () => status('a.gguf');
    const context = vm.createContext({
        document: {getElementById(id) {
            if (!elements.has(id)) elements.set(id, element());
            return elements.get(id);
        }, createElement: element},
        window: {location: {search: ''}}, URLSearchParams, AbortController,
        Date: {now: () => now},
        setTimeout(fn, ms) {
            if (ms === 2000) {now += ms; queueMicrotask(fn);}
            return 1;
        }, clearTimeout() {},
        fetch: async (url, options) => {
            calls.push({url, options});
            if (url === '/api/search/status') return {ok: true, json: async () => ({})};
            const payload = await handler(url, options);
            return {ok: payload.httpStatus === undefined || payload.httpStatus < 400, json: async () => payload};
        },
        esc: value => value, showConfirm: async () => true,
        toast: (text, kind) => feedback.push({text, kind}),
    });
    vm.runInContext(script, context);
    await new Promise(resolve => setImmediate(resolve));
    function chooseB() {
        context.modelSelect.value = 'b.gguf';
        context.modelSelect.selectedIndex = 1;
        context.modelSelect.listeners.change();
    }
    return {context, feedback, calls, chooseB, setHandler(fn) {handler = fn;}};
}

(async () => {
    // A failed refresh must remove old usable evidence, including after finally refreshes controls.
    const failed = await harness();
    assert.equal(failed.context.selectedModelUsable, true);
    failed.setHandler(() => {throw new Error('transient status failure');});
    assert.equal(await failed.context.loadChatModels(), null);
    failed.context.refreshChatModelControls({});
    assert.equal(failed.context.selectedModelUsable, false);
    assert.equal(failed.context.modelSelect.disabled, true);
    assert.equal(failed.context.sendBtn.disabled, true);

    const safetyBlocked = await harness();
    safetyBlocked.setHandler(() => ({...status('a.gguf'), runtime_ready: false}));
    await safetyBlocked.context.loadChatModels();
    assert.match(safetyBlocked.context.modelSelect.innerHTML, /safety checks required/);
    assert.equal(safetyBlocked.context.sendBtn.disabled, true);
    assert.equal(safetyBlocked.context.inferenceAutomationAvailable, false);
    safetyBlocked.context.userInput.value = 'preserve blocked draft';
    await safetyBlocked.context.sendMessage();
    assert.equal(safetyBlocked.context.userInput.value, 'preserve blocked draft');
    assert.equal(safetyBlocked.calls.some(call => call.url === '/api/chat' || call.url === '/api/inference/select'), false);
    assert.match(safetyBlocked.feedback.at(-1).text, /Open Security Status/);
    safetyBlocked.setHandler(() => ({...status('a.gguf'), runtime_ready: true}));
    await safetyBlocked.context.loadChatModels();
    assert.equal(safetyBlocked.context.sendBtn.disabled, false);
    failed.context.userInput.value = 'keep this draft';
    await failed.context.sendMessage();
    assert.equal(failed.calls.some(call => call.url === '/api/chat'), false);
    assert.equal(failed.context.userInput.value, 'keep this draft');
    failed.setHandler(() => status('a.gguf'));
    await failed.context.loadChatModels();
    assert.equal(failed.context.selectedModelUsable, true);
    assert.equal(failed.context.sendBtn.disabled, false);

    // An explicit registry failure cannot borrow the backend's loaded-model state.
    failed.setHandler(() => ({...status('a.gguf'), registry_available: false}));
    assert.equal(await failed.context.loadChatModels(), null);
    assert.match(failed.context.modelSelect.innerHTML, /Model registry unavailable/);
    assert.equal(failed.context.inferenceAvailable, false);
    assert.equal(failed.context.inferenceAutomationAvailable, false);
    assert.equal(failed.context.selectedModelUsable, false);
    assert.equal(failed.context.sendBtn.disabled, true);
    failed.setHandler(() => ({...status('a.gguf'), registry_available: true}));
    await failed.context.loadChatModels();
    assert.equal(failed.context.selectedModelUsable, true);

    failed.setHandler(() => ({...status('a.gguf'), chat_models: {error: 'bad inventory'}}));
    assert.equal(await failed.context.loadChatModels(), null);
    assert.equal(failed.context.sendBtn.disabled, true);

    // Restart acknowledgement with A still loaded must retain B, block chat, and keep polling.
    const recovered = await harness();
    recovered.chooseB();
    let polls = 0;
    recovered.setHandler(async url => {
        if (url === '/api/inference/select') return {status: 'queued', request_id: requestId};
        polls += 1;
        assert.equal(recovered.context.inferenceSelectionPending, true);
        recovered.context.userInput.value = 'draft for B';
        await recovered.context.sendMessage();
        assert.equal(recovered.context.userInput.value, 'draft for B');
        assert.equal(recovered.context.sendBtn.disabled, true);
        assert.equal(recovered.context.selectedModel, 'b.gguf');
        if (polls === 1) return status('a.gguf', {request_id: requestId, status: 'succeeded'});
        if (polls === 2) throw new Error('transient status failure');
        assert.equal(recovered.feedback.some(item => item.kind === 'success'), false);
        return status('b.gguf', {request_id: requestId, status: 'succeeded'});
    });
    await recovered.context.startNativeInference('b.gguf');
    assert.equal(polls, 3);
    assert.equal(recovered.context.selectedModel, 'b.gguf');
    assert.equal(recovered.context.selectedModelUsable, true);
    assert.equal(recovered.context.modelSelect.disabled, false);
    assert.equal(recovered.context.sendBtn.disabled, false);
    assert.equal(recovered.calls.some(call => call.url === '/api/chat'), false);
    assert.equal(recovered.feedback.at(-1).kind, 'success');
    recovered.setHandler(url => {
        assert.equal(url, '/api/chat');
        return {choices: [{message: {content: 'Reply from B'}}]};
    });
    await recovered.context.sendMessage();
    const chatCall = recovered.calls.find(call => call.url === '/api/chat');
    assert.equal(JSON.parse(chatCall.options.body).model, 'b.gguf');
    assert.equal(recovered.context.messages.at(-1).content, 'Reply from B');
    assert.equal(recovered.context.sendBtn.disabled, false);

    // A matching controller failure ends polling and leaves B unavailable.
    const rejected = await harness();
    rejected.chooseB();
    rejected.setHandler(url => url === '/api/inference/select'
        ? {status: 'queued', request_id: requestId}
        : status('a.gguf', {request_id: requestId, status: 'failed', detail: 'Model verification failed.'}));
    await rejected.context.startNativeInference('b.gguf');
    assert.equal(rejected.context.selectedModelUsable, false);
    assert.equal(rejected.context.sendBtn.disabled, true);
    assert.equal(rejected.feedback.at(-1).text, 'Model verification failed.');

    // Poll timeout after repeated failed reads must not re-enable stale controls.
    const timedOut = await harness();
    timedOut.setHandler(url => {
        if (url === '/api/inference/select') return {status: 'queued', request_id: requestId};
        throw new Error('status remains unavailable');
    });
    await timedOut.context.startNativeInference('a.gguf');
    assert.equal(timedOut.context.selectedModelUsable, false);
    assert.equal(timedOut.context.modelSelect.disabled, true);
    assert.equal(timedOut.context.sendBtn.disabled, true);
    assert.equal(timedOut.feedback.at(-1).kind, 'warning');
    console.log('Native chat frontend: failure recovery, exact-model polling, send guard, controller failure and timeout passed.');
})().catch(error => {console.error(error); process.exitCode = 1;});
