const fs = require('node:fs');
const path = require('node:path');
const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const exec = promisify(execFile);
const sleep = promisify(setTimeout);

async function main() {
  const [msys, output] = process.argv.slice(2);
  if (!msys || !output)
    throw new Error('Usage: watch-cmake.cjs <MSYS2 root> <evidence directory>');

  const cmake = path.join(msys, 'usr', 'bin', 'cmake.exe');
  const cdb = path.join(process.env['ProgramFiles(x86)'] || '',
    'Windows Kits', '10', 'Debuggers', 'x64', 'cdb.exe');
  const debuggerPath = fs.existsSync(cdb) ? cdb :
    path.join(msys, 'usr', 'bin', 'gdb.exe');
  if (!fs.existsSync(cmake) || !fs.existsSync(debuggerPath))
    throw new Error(`Missing CMake or debugger: ${cmake}; ${debuggerPath}`);

  const started = Date.now();
  const captured = new Set();
  let progress = '';
  let progressTime = started;
  const write = (name, value) => fs.writeFileSync(path.join(output, name),
    `${JSON.stringify(value, null, 2)}\n`);
  const query = async command => {
    const { stdout, stderr } = await exec('pwsh.exe',
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
        '$ErrorActionPreference = "Stop"; ' + command],
      { windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
    if (stderr)
      fs.appendFileSync(path.join(output, 'watcher-query.stderr.log'), stderr);
    const value = stdout.trim() ? JSON.parse(stdout) : [];
    return Array.isArray(value) ? value : [value];
  };
  const processes = () => query(
    'Get-CimInstance Win32_Process -Filter "Name = \'cmake.exe\'" ' +
    '-OperationTimeoutSec 5 | Select-Object ProcessId,ParentProcessId,' +
    'ExecutablePath,CommandLine,@{Name="CreatedUtc";Expression={' +
    '$_.CreationDate.ToUniversalTime().ToString("o")}} | ' +
    'ConvertTo-Json -Compress');

  await processes();
  write('watcher-ready.json', {
    startedUtc: new Date(started).toISOString(), cmake, debuggerPath,
    quietSeconds: 45,
    note: fs.existsSync(cdb) ? 'CDB noninvasive capture' :
      'CDB not found at the SDK path; using the installed MSYS GDB'
  });
  console.log(`Watching ${cmake}; debugger=${debuggerPath}`);

  while (!fs.existsSync(path.join(output, 'watcher-stop'))) {
    const logs = fs.readdirSync(output).filter(name =>
      /^cmake-\d+(?:\.stderr)?\.log$/.test(name)).sort();
    const current = logs.map(name =>
      `${name}:${fs.statSync(path.join(output, name)).size}`).join(';');
    if (current !== progress) {
      progress = current;
      progressTime = Date.now();
    }
    for (const target of await processes()) {
      const created = Date.parse(target.CreatedUtc);
      const key = `${target.ProcessId}-${target.CreatedUtc}`;
      if (target.ExecutablePath?.toLowerCase() !== cmake.toLowerCase() ||
          !Number.isFinite(created) || created < started ||
          Date.now() - created < 45000 ||
          Date.now() - progressTime < 45000 || captured.has(key))
        continue;
      captured.add(key);
      const prefix = `hang-${target.ProcessId}`;
      write(`${prefix}.json`, {
        ...target, observedUtc: new Date().toISOString(), logs,
        quietSeconds: (Date.now() - progressTime) / 1000,
        note: 'Suspected full-target stall; capture may perturb the target'
      });
      const all = await query(
        'Get-CimInstance Win32_Process -OperationTimeoutSec 5 | ' +
        'Select-Object ProcessId,ParentProcessId,Name,ExecutablePath | ' +
        'ConvertTo-Json -Compress');
      write(`${prefix}-processes.json`, all);
      const args = fs.existsSync(cdb) ?
        ['-pv', '-pd', '-sins', '-netsyms', 'no', '-y', output,
          '-p', String(target.ProcessId), '-c',
          '.time; lm; ~* kp; !address; .detach; q'] :
        ['-nx', '-batch', '-iex', 'set auto-load off',
          '-iex', 'set debuginfod enabled off',
          '-ex', 'set pagination off', '-p', String(target.ProcessId),
          '-ex', 'info sharedlibrary', '-ex', 'info threads',
          '-ex', 'thread apply all bt 24', '-ex', 'info files',
          '-ex', 'detach', '-ex', 'quit'];
      write(`${prefix}-debugger.json`, { debuggerPath, args });
      const fd = fs.openSync(path.join(output, `${prefix}-debugger.log`), 'a');
      let timer;
      const result = await Promise.race([
        new Promise((resolve, reject) => {
          const child = spawn(debuggerPath, args,
            { windowsHide: true, stdio: ['ignore', fd, fd] });
          child.once('error', reject);
          child.once('close', (code, signal) => {
            fs.closeSync(fd);
            write(`${prefix}-debugger-exit.json`, { code, signal });
            resolve({ code, signal });
          });
        }),
        new Promise(resolve => {
          timer = setTimeout(() => resolve({ timedOut: true }), 30000);
        })
      ]);
      clearTimeout(timer);
      write(`${prefix}-capture.json`, result);
      console.log(`Captured CMake PID ${target.ProcessId}: ` +
        JSON.stringify(result));
      if (result.timedOut) {
        throw new Error('Debugger exceeded 30 seconds; partial output saved. ' +
          'Debugger and target were not killed; inspect before reattaching.');
      }
      if (result.code !== 0)
        throw new Error(`Debugger exited ${result.code}; inspect saved output`);
    }
    await sleep(3000);
  }
  write('watcher-finished.json', { finishedUtc: new Date().toISOString() });
}

main().catch(error => {
  const output = process.argv[3];
  if (output && fs.existsSync(output))
    fs.appendFileSync(path.join(output, 'watcher-error.log'), `${error.stack}\n`);
  console.error(error);
  process.exitCode = 1;
});
