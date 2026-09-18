'use strict';
// Loaded by android_monitor.py after the installed frida-tools Java bridge.
const options = globalThis.SC0PE_OPTIONS || {};
const events = [];
let dropped = 0, calls = 0;
const suppressedThreads = new Map();
function isSuppressed() { return (suppressedThreads.get(Process.getCurrentThreadId()) || 0) > 0; }
function withoutObservation(callback) {
    const tid = Process.getCurrentThreadId();
    suppressedThreads.set(tid, (suppressedThreads.get(tid) || 0) + 1);
    try { return callback(); }
    finally {
        const count = suppressedThreads.get(tid) - 1;
        if (count) suppressedThreads.set(tid, count); else suppressedThreads.delete(tid);
    }
}
const hooks = { native: [], java: [], errors: [], java_state: 'waiting' };
const listeners = [];
function short(value, maximum = 512) {
    try { return String(value).slice(0, maximum); } catch (_) { return '<unreadable>'; }
}
function emit(event) {
    if (isSuppressed()) return;
    calls++;
    if (events.length >= 256) { dropped++; return; }
    events.push(Object.assign({ time: Date.now() / 1000, pid: Process.id,
        tid: Process.getCurrentThreadId() }, event));
}
function flush() {
    send({ type: 'batch', events: events.splice(0), calls: calls, dropped: dropped });
}
const timer = setInterval(flush, 250);
function cstring(address) {
    try {
        if (address.isNull()) return null;
        const range = Process.findRangeByAddress(address);
        if (!range) return '<unreadable>';
        const end = range.base.add(range.size);
        const size = address.add(512).compare(end) <= 0 ? 512 : end.sub(address).toUInt32();
        const bytes = new Uint8Array(address.readVolatile ? address.readVolatile(size) : address.readByteArray(size));
        const nul = bytes.indexOf(0);
        return address.readUtf8String(nul < 0 ? bytes.length : nul);
    } catch (_) { return '<unreadable>'; }
}
function sockaddr(address) {
    try {
        const family = address.readU16();
        const port = (address.add(2).readU8() << 8) | address.add(3).readU8();
        if (family === 2) return { family: 'ipv4', host: [4,5,6,7].map(i => address.add(i).readU8()).join('.'), port: port };
        if (family === 10) return { family: 'ipv6', host: [8,10,12,14,16,18,20,22].map(i =>
            ((address.add(i).readU8() << 8) | address.add(i+1).readU8()).toString(16)).join(':'), port: port };
        return { family: family };
    } catch (_) { return { error: 'unreadable sockaddr' }; }
}
function installNative() {
    const specifications = {
        connect: args => ({ fd: args[0].toInt32(), peer: sockaddr(args[1]) }),
        open: args => ({ path: cstring(args[0]), flags: args[1].toInt32() }),
        openat: args => ({ dirfd: args[0].toInt32(), path: cstring(args[1]), flags: args[2].toInt32() }),
        unlink: args => ({ path: cstring(args[0]) }),
        rename: args => ({ source: cstring(args[0]), destination: cstring(args[1]) }),
        execve: args => ({ path: cstring(args[0]) }),
        mprotect: args => ({ address: args[0].toString(), size: args[1].toString(), protection: args[2].toInt32() }),
        ptrace: args => ({ request: args[0].toInt32(), target_pid: args[1].toInt32() }),
        process_vm_writev: args => ({ target_pid: args[0].toInt32() })
    };
    for (const name of Object.keys(specifications)) {
        try {
            const address = Module.findGlobalExportByName ? Module.findGlobalExportByName(name) : Module.findExportByName(null, name);
            if (!address) continue;
            listeners.push(Interceptor.attach(address, {
                onEnter(args) {
                    this.skip = isSuppressed();
                    if (!this.skip) {
                        try { this.args = specifications[name](args); } catch (_) { this.args = { error: 'unreadable arguments' }; }
                    }
                },
                onLeave(value) {
                    if (this.skip) return;
                    const result = value.toInt32();
                    const success = result >= 0;
                    emit({ type: 'api', layer: 'native', api: name, arguments: this.args,
                        result: result,
                        success: success, errno: result < 0 ? this.errno : null });
                }
            }));
            hooks.native.push(name);
        } catch (error) { hooks.errors.push(name + ': ' + short(error)); }
    }
    // Android's loader selects namespaces from caller return addresses. Replacing
    // the return address for a dlopen onLeave hook can break library loading.
    // Observe actual module loads instead of instrumenting that call boundary.
    if (Process.attachModuleObserver) {
        let initial = true;
        listeners.push(Process.attachModuleObserver({
            onAdded(module) { emit({ type: 'module', action: initial ? 'present' : 'loaded',
                name: module.name, path: module.path, base: module.base.toString(), size: module.size }); },
            onRemoved(module) { emit({ type: 'module', action: 'unloaded',
                name: module.name, path: module.path, base: module.base.toString() }); }
        }));
        initial = false;
    }
}
function installJava() {
    if (typeof Java === 'undefined' || !Java.available) {
        hooks.java_state = 'unavailable'; send({ type: 'hooks', hooks: hooks }); return;
    }
    Java.perform(function () {
        const specifications = [
            ['java.net.Socket', 'connect', ['java.net.SocketAddress']],
            ['java.net.Socket', 'connect', ['java.net.SocketAddress', 'int']],
            ['java.net.InetAddress', 'getAllByName', ['java.lang.String']],
            ['java.net.URL', 'openConnection', []],
            ['java.io.FileInputStream', '$init', ['java.lang.String']],
            ['java.io.FileOutputStream', '$init', ['java.lang.String']],
            ['java.io.FileOutputStream', '$init', ['java.lang.String', 'boolean']],
            ['java.lang.Runtime', 'exec', ['java.lang.String']],
            ['java.lang.Runtime', 'exec', ['[Ljava.lang.String;']],
            ['java.lang.ProcessBuilder', 'start', []],
            ['dalvik.system.DexClassLoader', '$init', ['java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader']],
            ['android.content.ContextWrapper', 'startActivity', ['android.content.Intent']],
            ['android.content.ContextWrapper', 'startService', ['android.content.Intent']],
            ['javax.crypto.Cipher', 'getInstance', ['java.lang.String']]
        ];
        for (const spec of specifications) {
            const label = spec[0] + '.' + spec[1];
            try {
                const type = Java.use(spec[0]);
                const method = type[spec[1]].overload(...spec[2]);
                method.implementation = function (...args) {
                    const skip = isSuppressed();
                    let values = [];
                    if (!skip) {
                        values = args.slice(0, 4).map(value => short(value));
                        if (spec[0] === 'java.net.URL') values = [short(this.toString())];
                        if (spec[0] === 'java.lang.ProcessBuilder') values = [short(this.command())];
                    }
                    try {
                        const result = method.call(this, ...args);
                        if (!skip) emit({ type: 'api', layer: 'java', api: label,
                            arguments: values, success: true });
                        return result;
                    } catch (error) {
                        if (!skip) emit({ type: 'api', layer: 'java', api: label,
                            arguments: values, success: false, error: short(error) });
                        throw error;
                    }
                };
                hooks.java.push(label + '(' + spec[2].join(',') + ')');
            } catch (error) { hooks.errors.push(label + ': ' + short(error)); }
        }
        hooks.java_state = 'ready'; send({ type: 'hooks', hooks: hooks });
    });
}
function inJava(callback) {
    return new Promise((resolve, reject) => {
        if (typeof Java === 'undefined' || !Java.available) { reject(new Error('Java runtime is unavailable')); return; }
        Java.perform(function () {
            try { resolve(withoutObservation(callback)); } catch (error) { reject(error); }
        });
    });
}
function dataDirectory() {
    const application = Java.use('android.app.ActivityThread').currentApplication();
    if (application === null) throw new Error('Application context is not ready');
    return short(application.getApplicationInfo().dataDir.value, 4096);
}
function inside(path, root) { return path.startsWith(root + '/'); }
function inventory() {
    const File = Java.use('java.io.File');
    const Stream = Java.use('java.io.FileInputStream');
    const Digest = Java.use('java.security.MessageDigest');
    const root = short(File.$new(dataDirectory()).getCanonicalPath(), 4096);
    const queue = [{ file: File.$new(root), depth: 0 }], files = [];
    let nodes = 0, hashed = 0, skipped = 0, traversalSkipped = 0;
    while (queue.length && nodes < 1024 && files.length < 256) {
        const current = queue.shift(); nodes++;
        const canonical = short(current.file.getCanonicalPath(), 4096);
        if (canonical !== root && !inside(canonical, root)) { skipped++; traversalSkipped++; continue; }
        if (current.file.isDirectory()) {
            if (current.depth >= 8) { skipped++; traversalSkipped++; continue; }
            const children = current.file.listFiles();
            if (children !== null) {
                for (let i = 0; i < children.length && queue.length < 1024; i++) {
                    const child = children[i];
                    // A canonical/path difference means a symlink; do not follow it.
                    if (short(child.getCanonicalPath(),4096) !== short(child.getAbsolutePath(),4096)) { skipped++; traversalSkipped++; continue; }
                    queue.push({ file: child, depth: current.depth + 1 });
                }
            } else { skipped++; traversalSkipped++; }
            continue;
        }
        if (!current.file.isFile()) continue;
        const size = Number(current.file.length());
        const entry = { path: canonical.slice(root.length + 1), size: size,
            modified_ms: Number(current.file.lastModified()), sha256: null, kind: 'file' };
        if (size <= 262144 && hashed + size <= 2097152) {
            let stream = null;
            try {
                stream = Stream.$new(current.file);
                const digest = Digest.getInstance('SHA-256');
                const buffer = Java.array('byte', new Array(4096).fill(0));
                let count = 0, read;
                while ((read = stream.read(buffer)) > 0) {
                    if (count === 0 && read >= 4) {
                        const magic = [0,1,2,3].map(i => buffer[i] & 255);
                        if (magic.join(',') === '100,101,120,10') entry.kind = 'dex';
                        else if (magic.join(',') === '127,69,76,70') entry.kind = 'elf';
                        else if (magic.join(',') === '80,75,3,4') entry.kind = 'zip';
                    }
                    count += read; hashed += read;
                    if (count > 262144 || hashed > 2097152) throw new Error('File grew beyond read budget');
                    digest.update(buffer, 0, read);
                }
                entry.sha256 = Array.from(digest.digest(), value => (value & 255).toString(16).padStart(2, '0')).join('');
            } catch (error) { entry.error = short(error); skipped++; }
            finally { if (stream !== null) stream.close(); }
        } else {
            entry.hash_skipped = 'size_or_cycle_budget'; skipped++;
            // Preserve dropped-code identification even when a full hash is too expensive.
            let stream = null;
            try {
                stream = Stream.$new(current.file);
                const header = Java.array('byte', new Array(8).fill(0));
                if (stream.read(header) >= 4) {
                    const magic = [0,1,2,3].map(i => header[i] & 255).join(',');
                    if (magic === '100,101,120,10') entry.kind = 'dex';
                    else if (magic === '127,69,76,70') entry.kind = 'elf';
                    else if (magic === '80,75,3,4') entry.kind = 'zip';
                }
            } catch (error) { entry.error = short(error); }
            finally { if (stream !== null) stream.close(); }
        }
        files.push(entry);
    }
    return { root: root, files: files, nodes: nodes, bytes_hashed: hashed,
        status: queue.length || skipped ? 'partial' : 'complete', skipped: skipped,
        enumeration_complete: queue.length === 0 && traversalSkipped === 0 };
}
rpc.exports = {
    identity() { return { pid: Process.id, arch: Process.arch, hooks: hooks }; },
    ranges() {
        const ranges = Process.enumerateRanges({ protection: 'r--', coalesce: true });
        return { truncated: ranges.length > 4096, ranges: ranges.slice(0,4096).map(range => ({
            base: range.base.toString(), size: range.size, protection: range.protection,
            file: range.file ? range.file.path : null })) };
    },
    readBytes(address, size) {
        if (!Number.isInteger(size) || size <= 0 || size > 262144) throw new Error('Invalid read size');
        const pointer = ptr(address), range = Process.findRangeByAddress(pointer);
        if (!range || !range.protection.startsWith('r') || pointer.add(size).compare(range.base.add(range.size)) > 0)
            throw new Error('Read outside current readable mapping');
        return withoutObservation(() => pointer.readVolatile ? pointer.readVolatile(size) : pointer.readByteArray(size));
    },
    files() { return inJava(inventory); },
    stop() {
        clearInterval(timer);
        for (const listener of listeners) listener.detach();
        flush();
    }
};
if (options.hooks !== false) { installNative(); installJava(); }
else { hooks.java_state = 'hooks_disabled'; }
send({ type: 'hooks', hooks: hooks });
send({ type: 'agent_ready', pid: Process.id, arch: Process.arch });
