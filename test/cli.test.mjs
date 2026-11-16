import test from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../argus.mjs';

test('parseArgs extracts positionals, booleans, values, and lists', () => {
  const { positionals, flags } = parseArgs([
    'username',
    '@example',
    '--category',
    'social,dev',
    '--category=creative',
    '--sites',
    'github,reddit',
    '--json',
    '--no-save',
    '--timeout',
    '12s',
    '--concurrency=8',
    '--port',
    '9999',
  ]);

  assert.deepEqual(positionals, ['username', '@example']);
  assert.equal(flags.json, true);
  assert.equal(flags.noSave, true);
  assert.deepEqual(flags.categories, ['social', 'dev', 'creative']);
  assert.deepEqual(flags.sourceIds, ['github', 'reddit']);
  assert.equal(flags.timeout, '12s');
  assert.equal(flags.concurrency, '8');
  assert.equal(flags.port, '9999');
});

test('parseArgs supports --value=... and the short help/version/json flags', () => {
  assert.deepEqual(parseArgs(['-h']).flags, { help: true });
  assert.deepEqual(parseArgs(['-v']).flags, { version: true });
  assert.deepEqual(parseArgs(['-j']).flags, { json: true });
  assert.equal(parseArgs(['--out=./copy.jpg']).flags.out, './copy.jpg');
});

test('parseArgs rejects unknown, valueless, and malformed options', () => {
  assert.throws(() => parseArgs(['username', '--bogus']), /unknown option/i);
  assert.throws(() => parseArgs(['username', '--category']), /needs a value/i);
  assert.throws(() => parseArgs(['username', '--json=true']), /does not take a value/i);
  assert.throws(() => parseArgs(['username', '-x']), /unknown option/i);
});
