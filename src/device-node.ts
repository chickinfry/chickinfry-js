import type {Owner, Store} from "./device.js";
import {failure} from "./device.js";
import type * as FileSystem from "node:fs/promises";
import type {Stats} from "node:fs";

// Variable specifiers keep Node-only modules out of browser and edge bundles.
const nodeModule = (name: string): Promise<any> => import(name);
const localLocks = new Map<string, Promise<unknown>>();

export async function openStore(owner: Owner, requested: string | undefined, cwd: string): Promise<Store> {
  try {
    const fs: typeof FileSystem = await nodeModule("node:fs/promises");
    const {constants} = await nodeModule("node:fs");
    const path: typeof import("node:path") = await nodeModule("node:path");
    const os: typeof import("node:os") = await nodeModule("node:os");
    const {createHash, randomUUID} = await nodeModule("node:crypto");
    const windows = process.platform === "win32";
    const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
    let base: string;
    if (requested !== undefined) base = path.resolve(cwd, requested);
    else {
      const app = hash(owner[0]);
      if (windows) base = path.join((await windowsPath()).trim(), "Chickinfry", app);
      else if (process.platform === "darwin") base = path.join(os.homedir(), "Library", "Application Support", "Chickinfry", app);
      else {
        const xdg = process.env.XDG_STATE_HOME;
        base = path.join(xdg && path.isAbsolute(xdg) ? xdg : path.join(os.homedir(), ".local", "state"), "chickinfry", app);
      }
    }
    if (!path.isAbsolute(base)) throw failure();
    const stem = hash(owner);
    const file = path.join(base, stem + ".json"), lock = path.join(base, stem + ".lock");
    const noFollow = constants.O_NOFOLLOW ?? 0;
    const uid = process.getuid?.();
    const checkFile = async (handle: FileSystem.FileHandle, name: string): Promise<Stats> => {
      const before = await fs.lstat(name), info = await handle.stat();
      if (!info.isFile() || before.isSymbolicLink() || !before.isFile() || info.nlink !== 1 ||
          before.ino !== info.ino || before.dev !== info.dev || (!windows && (info.uid !== uid || (info.mode & 0o7777) !== 0o600))) throw failure();
      if (windows) await windowsAccess(name, false, false);
      return info;
    };
    const directory = async () => {
      const root = path.parse(base).root;
      let current = root;
      for (const part of base.slice(root.length).split(path.sep).filter(Boolean)) {
        current = path.join(current, part);
        try {
          const info = await fs.lstat(current);
          if (!info.isDirectory() || info.isSymbolicLink()) throw failure();
          if (!windows && ((info.uid !== 0 && info.uid !== uid) ||
              ((info.mode & 0o022) !== 0 && (info.mode & 0o1000) === 0))) throw failure();
        } catch (error) {
          if (!isCode(error, "ENOENT")) throw error;
          if (windows) await windowsAccess(current, true, true);
          else { try { await fs.mkdir(current, {mode: 0o700}); } catch (error) { if (!isCode(error, "EEXIST")) throw error; } }
          const info = await fs.lstat(current);
          if (!info.isDirectory() || info.isSymbolicLink() || (!windows && (info.uid !== uid || (info.mode & 0o077) !== 0))) throw failure();
        }
      }
      const info = await fs.lstat(base);
      if (!windows && (info.uid !== uid || (info.mode & 0o022) !== 0)) throw failure();
      if (windows) await windowsAccess(base, false, true);
    };
    await directory();
    if (windows) await windowsParents(base);
    const {DatabaseSync}: typeof import("node:sqlite") = await nodeModule("node:sqlite");
    const lockFile = async <T>(work: () => Promise<T>): Promise<T> => {
      await directory();
      try {
        const info = await fs.lstat(lock);
        if (!info.isFile() || info.isSymbolicLink()) throw failure();
      } catch (error) { if (!isCode(error, "ENOENT")) throw error; }
      const handle = await fs.open(lock, constants.O_CREAT | constants.O_RDWR | noFollow, 0o600);
      let db: import("node:sqlite").DatabaseSync | undefined;
      try {
        await checkFile(handle, lock);
        db = new DatabaseSync(lock);
        db.exec("PRAGMA busy_timeout = 3000; BEGIN IMMEDIATE");
        await checkFile(handle, lock);
        for (const name of await fs.readdir(base)) {
          if (!name.startsWith(stem + ".") || !/^[0-9a-f-]{36}\.tmp$/.test(name.slice(stem.length + 1))) continue;
          const abandoned = path.join(base, name);
          const temporary = await fs.open(abandoned, constants.O_RDONLY | noFollow);
          try { await checkFile(temporary, abandoned); } finally { await temporary.close(); }
          await fs.unlink(abandoned);
        }
        return await work();
      } finally {
        try { db?.close(); } finally { await handle.close(); }
      }
    };
    const locked = async <T>(work: () => Promise<T>): Promise<T> => {
      // A synchronous SQLite busy wait must not block this process's async owner.
      const previous = localLocks.get(lock) ?? Promise.resolve();
      const current = previous.catch(() => {}).then(() => lockFile(work));
      localLocks.set(lock, current);
      try { return await current; }
      finally { if (localLocks.get(lock) === current) localLocks.delete(lock); }
    };
    const read = async (validateOnly = false): Promise<string | null> => {
      let handle: FileSystem.FileHandle;
      try { handle = await fs.open(file, constants.O_RDONLY | noFollow); }
      catch (error) { if (isCode(error, "ENOENT")) return null; throw error; }
      try {
        const info = await checkFile(handle, file);
        if (validateOnly) return null;
        if (info.size > 8192) throw failure("device_storage_corrupt");
        return await handle.readFile("utf8");
      } finally { await handle.close(); }
    };
    return {
      async read() { try { return await locked(read); } catch (error) { throw mapFailure(error); } },
      async swap(expected, value, reset) {
        try {
          return await locked(async () => {
            if (reset) await read(true);
            else if (await read() !== expected) return false;
            const temporary = path.join(base, stem + "." + randomUUID() + ".tmp");
            let created = false;
            try {
              const handle = await fs.open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollow, 0o600);
              created = true;
              try { await checkFile(handle, temporary); await handle.writeFile(value, "utf8"); await handle.sync(); }
              finally { await handle.close(); }
              await fs.rename(temporary, file);
              created = false;
              if (!windows) {
                const directory = await fs.open(base, constants.O_RDONLY | constants.O_DIRECTORY | noFollow);
                try { await directory.sync(); } finally { await directory.close(); }
              }
              return true;
            } finally { if (created) await fs.unlink(temporary); }
          });
        } catch (error) { throw mapFailure(error); }
      },
    };
  } catch (error) { throw mapFailure(error); }
}

function isCode(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}
function mapFailure(error: unknown) {
  if (typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" && error.code.startsWith("device_storage_")) return error;
  return failure(isCode(error, "ENOSPC") || isCode(error, "EDQUOT") ? "device_storage_full" : undefined);
}

async function powershell(script: string, input = ""): Promise<string> {
  const {execFile}: typeof import("node:child_process") = await nodeModule("node:child_process");
  const path: typeof import("node:path") = await nodeModule("node:path");
  const systemRoot = process.env.SystemRoot ?? "C:\\Windows";
  return new Promise((resolve, reject) => {
    const child = execFile(path.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
      ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
      {env: {SystemRoot: systemRoot, TEMP: process.env.TEMP, TMP: process.env.TMP}, windowsHide: true,
        timeout: 5000, maxBuffer: 16384}, (error, stdout) => error ? reject(failure()) : resolve(stdout));
    child.stdin?.end(input);
  });
}
function windowsPath(): Promise<string> {
  return powershell("[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)");
}
async function windowsParents(path: string): Promise<void> {
  await powershell(`$ErrorActionPreference = 'Stop'
$path = [Console]::In.ReadToEnd()
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$trusted = @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')
$installer = New-Object Security.Principal.NTAccount('NT SERVICE', 'TrustedInstaller')
$trusted += $installer.Translate([Security.Principal.SecurityIdentifier]).Value
$parent = [IO.Directory]::GetParent($path)
while ($null -ne $parent) {
  $item = Get-Item -Force -LiteralPath $parent.FullName
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unavailable' }
  $acl = Get-Acl -LiteralPath $parent.FullName
  if ($trusted -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'Unavailable' }
  $rights = [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
  if ($null -ne $parent.Parent) { $rights = $rights -bor [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData }
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
    if ($rule.AccessControlType -eq 'Allow' -and $trusted -notcontains $rule.IdentityReference.Value -and ($rule.FileSystemRights -band $rights) -ne 0) { throw 'Unavailable' }
  }
  $parent = $parent.Parent
}`, path);
}
async function windowsAccess(path: string, create: boolean, directory: boolean): Promise<void> {
  await powershell(`$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
if ($request.create -and -not [IO.Directory]::Exists($request.path)) {
  $security = New-Object Security.AccessControl.DirectorySecurity
  $security.SetOwner($sid)
  $security.SetAccessRuleProtection($true, $false)
  $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
  $security.AddAccessRule($rule)
  [void][IO.Directory]::CreateDirectory($request.path, $security)
}
$item = Get-Item -Force -LiteralPath $request.path
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unavailable' }
$acl = Get-Acl -LiteralPath $request.path
if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'Unavailable' }
foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
  if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -ne $sid.Value) { throw 'Unavailable' }
}`, JSON.stringify({path, create, directory}));
}
