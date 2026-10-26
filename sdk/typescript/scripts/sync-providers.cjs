// Keep the npm artifact's trusted definitions identical to the sealed image.
const { existsSync, readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const canonical = join(__dirname, '../../../sealed/internal/inference/providers.json');
const target = join(__dirname, '../src/provider-catalog.json');
const source = readFileSync(existsSync(canonical) ? canonical : target, 'utf8');
JSON.parse(source);
if (existsSync(canonical)) writeFileSync(target, source);
