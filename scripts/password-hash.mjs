import { createInterface } from 'node:readline/promises';
import { hashPassword } from '../src/security.mjs';
if (!process.stdin.isTTY) {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  console.log(await hashPassword(input.trimEnd()));
} else {
  // Oculta caracteres; a senha não aparece no histórico nem nos argumentos.
  const { Writable } = await import('node:stream');
  let hidden = false;
  const muted = new Writable({ write(chunk, encoding, callback) { if (!hidden) process.stdout.write(chunk, encoding); callback(); } });
  const rl = createInterface({ input: process.stdin, output: muted, terminal: true });
  process.stdout.write('Nova senha técnica (12–128 caracteres): ');
  hidden = true;
  const password = await rl.question('');
  hidden = false;
  process.stdout.write('\n');
  rl.close();
  console.log(await hashPassword(password));
}
