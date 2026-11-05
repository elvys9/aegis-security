// Prefer the isolated project toolchain; do not alter the user's global PATH.
import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const env = { ...process.env };
// Windows environment keys are case-insensitive; do not create a second PATH
// entry beside Path, or child cmd.exe may receive the wrong one.
const pathKey = Object.keys(env).find(key => key.toLowerCase() === 'path') || 'PATH';
env[pathKey] = path.dirname(process.execPath) + path.delimiter + (env[pathKey] || '');
const tools = path.join(root, '.tools');
if (existsSync(path.join(tools, 'cargo', 'bin'))) {
  env.CARGO_HOME = path.join(tools, 'cargo'); env.RUSTUP_HOME = path.join(tools, 'rustup');
  env[pathKey] = path.join(tools, 'cargo', 'bin') + path.delimiter + env[pathKey];
}
const cli = path.join(root, 'node_modules', '@tauri-apps', 'cli', 'tauri.js');
if (!existsSync(cli)) { console.error('Dipendenze mancanti. Eseguire npm install prima della build Tauri.'); process.exit(1); }
const child = spawn(process.execPath, [cli, ...process.argv.slice(2)], { cwd: root, env, stdio: 'inherit', shell: false });
child.on('exit', code => process.exit(code ?? 1));
child.on('error', error => { console.error(error.message); process.exit(1); });
