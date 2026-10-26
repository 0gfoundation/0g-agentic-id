import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { listInferenceProviders, inferenceModels, changesProvider } from '../dist/Providers.js';
import { modelAdvisory } from '../dist/Settings.js';
import { AgentDNA } from '../dist/index.js';

test('SDK provider definitions exactly match the measured runtime source', () => {
  const source = readFileSync(new URL('../../../sealed/internal/inference/providers.json', import.meta.url), 'utf8');
  assert.equal(readFileSync(new URL('../src/provider-catalog.json', import.meta.url), 'utf8'), source);
  assert.deepEqual(listInferenceProviders(), JSON.parse(source));
  const copy = listInferenceProviders();
  copy[0].endpoints.openai = 'https://wrong.example';
  assert.equal(listInferenceProviders()[0].endpoints.openai, 'https://router-api.0g.ai/v1');
});

test('native providers never use the compute catalog for SDK discovery or advisory', async () => {
  const real = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('unexpected catalog fetch'); };
  try {
    assert.deepEqual(await inferenceModels('openai'), []);
    assert.deepEqual(await modelAdvisory({ provider: 'anthropic', model: 'private-model' }), []);
    await assert.rejects(inferenceModels('typo'), /UNSUPPORTED_INFERENCE_PROVIDER/);
  } finally { globalThis.fetch = real; }
});

test('provider-scoped model listing retains no-argument compute behavior', async () => {
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(String(url), 'https://router-api.0g.ai/v1/models');
    return new Response(JSON.stringify({ data: [{ id:'m', supported_formats:['openai'], supported_parameters:['tools'] }] }));
  };
  try {
    const client = new AgentDNA({ addresses: {} });
    assert.deepEqual(await client.agent.listModels(), ['m']);
    assert.deepEqual(await client.agent.listModelCaps({ provider:'0g-compute' }), [{ id:'m',chat:true,tools:true,formats:['openai'] }]);
    assert.deepEqual(await client.agent.listModels({ provider:'openai' }), []);
  } finally { globalThis.fetch = real; }
});

test('legacy settings mean compute and provider changes require a reset', () => {
  assert.equal(changesProvider(null, { provider:'0g-compute' }), false);
  assert.equal(changesProvider(null, { provider:'openai' }), true);
  assert.equal(changesProvider({ provider:'openai' }, { provider:'openai', model:'next' }), false);
});
