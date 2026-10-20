import { readdirSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
for (const dir of ['src', 'scripts', 'public', 'test']) {
  for (const name of readdirSync(dir).filter(v => /\.(mjs|js)$/.test(v))) {
    const result = spawnSync(process.execPath, ['--check', dir + '/' + name], { stdio: 'inherit' });
    if (result.status !== 0) process.exit(result.status || 1);
  }
}
JSON.parse(readFileSync('package.json', 'utf8'));
console.log('Sintaxe e pacote verificados.');
