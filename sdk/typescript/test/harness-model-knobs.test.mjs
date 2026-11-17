// The 0g-harness model knobs in others= (webSearch, subagentModels,
// subagentDefault), checked before anything is signed the way sealed reads
// them (harness/settings.go), and the provider registry's webSearch field.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  HARNESS_ONLY_KEYS, MAX_SUBAGENT_MODELS, assertHarnessKnobShapes, assertOthersFitFramework,
  assertSubagentDefaultOffered, parseAssignments,
} from '../dist/cli/settings.js';
import { WEB_SEARCH_SERVICES, listInferenceProviders, providerWebSearch, routeHash, validateProvider } from '../dist/Providers.js';

const others = (o) => parseAssignments([`others=${JSON.stringify(o)}`]);

test('webSearch: a known service, an optional credential name, a model only for a model-run search', () => {
  for (const ok of [
    { webSearch: { service: '0g-router' } },
    { webSearch: { service: 'off' } },
    { webSearch: { service: 'openai', credential: 'my-openai', model: 'gpt-x' } },
    { webSearch: { service: 'anthropic', model: 'claude-haiku-5-5' } },
  ]) assert.doesNotThrow(() => others(ok), JSON.stringify(ok));
  for (const bad of [
    { webSearch: 'openai' },
    { webSearch: { service: 'bing' } },
    { webSearch: { service: 'openai', credential: 'Not A Name' } },
    { webSearch: { service: '0g-router', model: 'x' } },
    { webSearch: { service: 'openai', apiKey: 'sk-x' } },
  ]) assert.throws(() => others(bad), (e) => e.code === 'BAD_FLAG', JSON.stringify(bad));
});

test('subagentModels: at most 8 distinct {provider, model, credential?}; subagentDefault: {provider, model}', () => {
  assert.doesNotThrow(() => others({ subagentModels: [{ provider: '0g-compute', model: 'deepseek-v3' }, { provider: 'openai', model: 'gpt-x', credential: 'my-openai' }] }));
  const many = Array.from({ length: MAX_SUBAGENT_MODELS + 1 }, (_, i) => ({ provider: 'openai', model: `m${i}` }));
  for (const bad of [
    { subagentModels: many },
    { subagentModels: { provider: 'openai' } },
    { subagentModels: [{ provider: 'Open AI', model: 'm' }] },
    { subagentModels: [{ provider: 'openai', model: 'm' }, { provider: 'openai', model: 'm' }] },
    { subagentModels: [{ provider: 'openai', model: 'm', key: 'sk-x' }] },
    { subagentDefault: { provider: 'openai' } },
  ]) assert.throws(() => others(bad), (e) => e.code === 'BAD_FLAG', JSON.stringify(bad));
  assert.doesNotThrow(() => assertHarnessKnobShapes(null));
});

test('subagentDefault must be the agent\'s model or one of subagentModels', () => {
  const doc = (o) => ({ provider: '0g-compute', model: 'glm-5.3', others: o });
  assert.doesNotThrow(() => assertSubagentDefaultOffered(doc({ subagentDefault: { provider: '0g-compute', model: 'glm-5.3' } })));
  assert.doesNotThrow(() => assertSubagentDefaultOffered(doc({ subagentModels: [{ provider: 'openai', model: 'gpt-x', credential: 'k' }], subagentDefault: { provider: 'openai', model: 'gpt-x' } })));
  assert.doesNotThrow(() => assertSubagentDefaultOffered({ model: 'glm-5.3', others: { subagentDefault: { provider: '0g-compute', model: 'glm-5.3' } } }));
  assert.throws(() => assertSubagentDefaultOffered(doc({ subagentDefault: { provider: 'openai', model: 'gpt-x' } })), (e) => e.code === 'BAD_FLAG');
  assert.doesNotThrow(() => assertSubagentDefaultOffered(doc({})));
});

test('the model knobs are 0g-harness switches', () => {
  for (const k of ['webSearch', 'subagentModels', 'subagentDefault']) assert.ok(HARNESS_ONLY_KEYS.includes(k), k);
  assert.throws(() => assertOthersFitFramework(others({ webSearch: { service: 'openai' } }), 'openclaw'), /0g-harness switch/);
  assert.doesNotThrow(() => assertOthersFitFramework(others({ webSearch: { service: 'openai' } }), '0g-harness'));
});

test('each built-in provider names the web search service its key pays for, outside the route hash', () => {
  const byId = Object.fromEntries(listInferenceProviders().map((p) => [p.id, p]));
  assert.equal(byId['0g-compute'].webSearch, '0g-router');
  assert.equal(byId.openai.webSearch, 'openai');
  assert.equal(byId.anthropic.webSearch, 'anthropic');
  assert.deepEqual([...WEB_SEARCH_SERVICES], ['0g-router', 'openai', 'anthropic']);
  const without = structuredClone(byId['0g-compute']);
  delete without.webSearch;
  assert.equal(routeHash(without), routeHash(byId['0g-compute']));
  assert.throws(() => validateProvider({ ...byId.openai, webSearch: 'bing' }), /web search/);
});

test('a registry without the webSearch field gets the service sealed would use', () => {
  const stripped = listInferenceProviders().map((p) => { const q = structuredClone(p); delete q.webSearch; return q; });
  const byId = Object.fromEntries(stripped.map((p) => [p.id, providerWebSearch(p)]));
  assert.deepEqual(byId, { '0g-compute': '0g-router', openai: 'openai', anthropic: 'anthropic' });
  assert.equal(providerWebSearch({ id: 'other', name: 'Other', formats: ['openai'] }), undefined);
  assert.equal(providerWebSearch({ id: 'other', name: 'Other', formats: ['openai'], webSearch: 'openai' }), 'openai');
});
