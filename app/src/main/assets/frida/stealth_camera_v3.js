/*
 * stealth_camera_v3.js
 *
 * 完整零拷贝帧传输：stealth hooks + memfd ring + unix socket (SCM_RIGHTS)
 * 协议兼容 helper_bridge.cpp 客户端。
 *
 * ⚠️  关键：绝不使用 `_send` 作为变量名！Frida 内部使用该名称。
 *
 * 协议流程：
 *   1. 客户端 connect → 服务端 accept
 *   2. 服务端发送 24 字节元数据 header
 *   3. 服务端逐个通过 SCM_RIGHTS 发送 memfd fd
 *   4. 客户端发送 ACK (0x01)
 *   5. 帧循环：服务端每帧 memcpy 到 memfd slot → 发送 1 字节 slot index
 *   6. 客户端读取帧 → 发送 release (0xA0 | idx)
 */
"use strict";

var LOG_FILE = "/data/local/tmp/stealth_v3.log";
var _libc = Process.getModuleByName("libc.so");
var _open = new NativeFunction(_libc.getExportByName("open"), "int", ["pointer", "int", "int"]);
var _write_raw = new NativeFunction(_libc.getExportByName("write"), "int", ["int", "pointer", "int"]);
var _close = new NativeFunction(_libc.getExportByName("close"), "int", ["int"]);
var _strlen = new NativeFunction(_libc.getExportByName("strlen"), "int", ["pointer"]);
var _logFd = _open(Memory.allocUtf8String(LOG_FILE), 0x441, 0x1b6);

function fileLog(msg) {
    if (_logFd < 0) return;
    var line = "[" + new Date().toISOString() + "] " + msg + "\n";
    var buf = Memory.allocUtf8String(line);
    _write_raw(_logFd, buf, _strlen(buf));
}
var _origConsoleLog = console.log;
console.log = function() {
    var args = Array.prototype.slice.call(arguments);
    var msg = args.join(" ");
    fileLog(msg);
    try { _origConsoleLog.apply(console, arguments); } catch(e) {}
};

Process.setExceptionHandler(function(details) {
    fileLog("[CRASH] type=" + details.type + " addr=" + details.address +
            " pc=" + (details.context ? details.context.pc : "?"));
    return false;
});

var stealthMode = false, gAvmInoutStatusAddr = null;
var blockCount = 0, allowCount = 0, hookDisabled = false, errorCount = 0;
function log(msg) { console.log(msg); }
function findModule(name) {
    var mod = null;
    Process.enumerateModules().forEach(function(m) {
        if (m.name.indexOf(name) !== -1 && mod === null) mod = m;
    });
    return mod;
}
function safeHookError(tag, e) {
    errorCount++;
    fileLog("[ERROR #" + errorCount + "] " + tag + ": " + e.message);
    if (errorCount >= 50 && !hookDisabled) {
        try { Interceptor.detachAll(); } catch(ex) {}
        hookDisabled = true;
        fileLog("[FATAL] too many errors, hooks detached");
    }
}

// ==================== STEALTH HOOKS ====================
var GHIDRA_BASE = 0x100000;
var glMod = findModule("libtest-opengl-swapinterval");
if (glMod) {
    var switchAvmAddr = glMod.base.add(0x108928 - GHIDRA_BASE);
    gAvmInoutStatusAddr = glMod.base.add(0x11fae0 - GHIDRA_BASE).readPointer();
    Interceptor.attach(switchAvmAddr, {
        onEnter: function(args) {
            if (hookDisabled) return;
            try {
                var state = args[0].toInt32();
                if (state === 0) {
                    if (!stealthMode) { stealthMode = true; blockCount++; }
                    this._needWriteback = true;
                } else if (state === -1) {
                    blockCount++; args[0] = ptr(3); this._needWriteback = false;
                } else {
                    if (state === 1 || state === 2) { if (stealthMode) stealthMode = false; }
                    allowCount++; this._needWriteback = false;
                }
            } catch(e) { safeHookError("switch_avm", e); }
        },
        onLeave: function(retval) {
            if (!hookDisabled && this._needWriteback && gAvmInoutStatusAddr)
                try { gAvmInoutStatusAddr.writeS32(1); } catch(e) {}
        }
    });
    log("[✓] switch_avm hooked");
}
var camMod = findModule("libavmcamera");
if (camMod) {
    // setAppState_C
    Interceptor.attach(camMod.base.add(0x19488), {
        onEnter: function(args) {
            if (hookDisabled) return;
            try { var s = args[0].toInt32(); if (stealthMode && (s===0||s===-1)) args[0] = ptr(3); } catch(e) {}
        }
    });
    // NdkCamera::setAppState
    Interceptor.attach(camMod.base.add(0x1b418), {
        onEnter: function(args) {
            if (hookDisabled) return;
            try { var s = args[1].toInt32(); if (stealthMode && (s===0||s===-1)) args[1] = ptr(3); } catch(e) {}
        }
    });
    // stopAvmCamera
    Interceptor.attach(camMod.base.add(0x193b8), { onEnter: function(args) { if (hookDisabled) return; } });
    log("[✓] setAppState + stop hooked");
}

// ==================== MEMFD NativeFunction ====================
var _memfd_create = null, _ftruncate = null, _mmap = null;
(function() {
    try {
        var _memfd_ptr = _libc.findExportByName("memfd_create");
        if (_memfd_ptr) {
            _memfd_create = new NativeFunction(_memfd_ptr, "int", ["pointer", "int"]);
        } else {
            var _syscall = new NativeFunction(_libc.getExportByName("syscall"), "int", ["int", "pointer", "int"]);
            _memfd_create = function(name, flags) { return _syscall(279, name, flags); };
        }
        _ftruncate = new NativeFunction(_libc.getExportByName("ftruncate"), "int", ["int", "int64"]);
        _mmap = new NativeFunction(_libc.getExportByName("mmap"), "pointer", ["pointer", "int64", "int", "int", "int", "int64"]);
        log("[✓] memfd NF ready");
    } catch(e) { fileLog("[FATAL] memfd NF: " + e.message); }
})();

// ==================== SOCKET NativeFunction ====================
// ⚠️  使用 _nfSend 而非 _send（Frida 内部保留名）
var _nfSocket = null, _nfBind = null, _nfListen = null, _nfAccept = null;
var _nfSend = null, _nfRecv = null, _nfUnlink = null, _nfSendmsg = null;
var _nfChmod = null, _nfFcntl = null;
var _sockNfReady = false;

function ensureSocketNF() {
    if (_sockNfReady) return;
    try {
        _nfSocket  = new NativeFunction(_libc.getExportByName("socket"),  "int", ["int", "int", "int"]);
        _nfBind    = new NativeFunction(_libc.getExportByName("bind"),    "int", ["int", "pointer", "int"]);
        _nfListen  = new NativeFunction(_libc.getExportByName("listen"),  "int", ["int", "int"]);
        _nfAccept  = new NativeFunction(_libc.getExportByName("accept"),  "int", ["int", "pointer", "pointer"]);
        _nfSend    = new NativeFunction(_libc.getExportByName("send"),    "int", ["int", "pointer", "int", "int"]);
        _nfRecv    = new NativeFunction(_libc.getExportByName("recv"),    "int", ["int", "pointer", "int", "int"]);
        _nfUnlink  = new NativeFunction(_libc.getExportByName("unlink"),  "int", ["pointer"]);
        _nfSendmsg = new NativeFunction(_libc.getExportByName("sendmsg"), "int", ["int", "pointer", "int"]);
        _nfChmod   = new NativeFunction(_libc.getExportByName("chmod"),   "int", ["pointer", "int"]);
        _nfFcntl   = new NativeFunction(_libc.getExportByName("fcntl"),   "int", ["int", "int", "int"]);
        _sockNfReady = true;
        log("[✓] socket NF ready (10 NF)");
    } catch(e) { fileLog("[FATAL] socket NF: " + e.message); }
}

// ==================== STATE ====================
var SOCK_PATH = "/data/local/tmp/starlight_bridge.sock";
var maxFrames = 4;
var planeLenY = 0, planeLenU = 0, planeLenV = 0, frameSlotSize = 0;
var ringReady = false;
var _memfd_fds = [], _memfd_addrs = [];
var _serverFd = -1, _clientFd = -1;
var clientReady = false; // handshake 完成
var frameWidth = 0, frameHeight = 0, frameFmt = 0;
var wireWidth = 0, wireHeight = 0;
var frameCount = 0, skippedCount = 0, sentCount = 0;
var lastWriteTs = 0, lastLogTs = 0, startTs = Date.now();
var targetFps = 20, minIntervalMs = 50;
var FORCE_OUTPUT_RES = false;
var OUTPUT_WIDTH = 2560;
var OUTPUT_HEIGHT = 1920;

function resolveWireDimensions(srcW, srcH) {
    if (!FORCE_OUTPUT_RES) return [srcW, srcH];
    if ((srcW * srcH) !== (OUTPUT_WIDTH * OUTPUT_HEIGHT)) {
        log("[!] output size mismatch, keep source dims: " + srcW + "x" + srcH);
        return [srcW, srcH];
    }
    return [OUTPUT_WIDTH, OUTPUT_HEIGHT];
}

// ==================== SOCKET SERVER ====================
function createSocketServer() {
    if (!_sockNfReady) return false;
    _nfUnlink(Memory.allocUtf8String(SOCK_PATH));
    _serverFd = _nfSocket(1, 1, 0); // AF_UNIX=1, SOCK_STREAM=1
    if (_serverFd < 0) { log("[!] socket() fail"); return false; }

    var addr = Memory.alloc(110);
    addr.writeU16(1); // AF_UNIX
    addr.add(2).writeUtf8String(SOCK_PATH);
    if (_nfBind(_serverFd, addr, 2 + SOCK_PATH.length + 1) < 0) {
        log("[!] bind() fail"); _close(_serverFd); _serverFd = -1; return false;
    }
    _nfChmod(Memory.allocUtf8String(SOCK_PATH), 0x1ff); // 0777

    if (_nfListen(_serverFd, 2) < 0) {
        log("[!] listen() fail"); _close(_serverFd); _serverFd = -1; return false;
    }

    // 非阻塞
    var flags = _nfFcntl(_serverFd, 3, 0); // F_GETFL=3
    if (flags >= 0) _nfFcntl(_serverFd, 4, flags | 0x800); // F_SETFL=4, O_NONBLOCK=0x800

    log("[✓] socket server: " + SOCK_PATH + " fd=" + _serverFd);
    return true;
}

function tryAcceptClient() {
    if (_serverFd < 0 || _clientFd >= 0) return;
    var fd = _nfAccept(_serverFd, ptr(0), ptr(0));
    if (fd < 0) return; // EAGAIN
    _clientFd = fd;
    log("[✓] client accepted: fd=" + fd);

    // 客户端 fd 设为阻塞 + 超时
    var flags = _nfFcntl(_clientFd, 3, 0);
    if (flags >= 0) _nfFcntl(_clientFd, 4, flags & ~0x800); // 清除 O_NONBLOCK

    // 执行握手
    doHandshake();
}

// ==================== HANDSHAKE ====================
function doHandshake() {
    if (_clientFd < 0 || !ringReady) return;

    // 1. 发送 24 字节元数据 header
    var header = Memory.alloc(24);
    header.writeU32(0x5A430000 | maxFrames);           // magic | fdCount
    header.add(4).writeU32(wireWidth);                  // width (wire)
    header.add(8).writeU32(wireHeight);                 // height (wire)
    header.add(12).writeU32(frameFmt);                  // fmt (35=YUV_420_888)
    header.add(16).writeU32(frameSlotSize & 0xFFFFFFFF);// frameSize low
    header.add(20).writeU32(0);                         // frameSize high (< 4GB)

    var n = _nfSend(_clientFd, header, 24, 0);
    if (n !== 24) {
        log("[!] handshake: send metadata fail (" + n + ")");
        _close(_clientFd); _clientFd = -1; return;
    }
    log("[*] handshake: metadata sent (wire=" + wireWidth + "x" + wireHeight +
        " src=" + frameWidth + "x" + frameHeight +
        " fmt=" + frameFmt + " size=" + frameSlotSize + " fds=" + maxFrames + ")");

    // 2. 逐个发送 memfd fd (SCM_RIGHTS)
    for (var i = 0; i < maxFrames; i++) {
        if (!sendFdViaSCM(_clientFd, _memfd_fds[i])) {
            log("[!] handshake: sendFd[" + i + "] fail");
            _close(_clientFd); _clientFd = -1; return;
        }
    }
    log("[*] handshake: " + maxFrames + " fds sent");

    // 3. 等待 ACK
    var ackBuf = Memory.alloc(1);
    var nr = _nfRecv(_clientFd, ackBuf, 1, 0);
    if (nr !== 1 || ackBuf.readU8() !== 0x01) {
        log("[!] handshake: ACK fail (nr=" + nr + ")");
        _close(_clientFd); _clientFd = -1; return;
    }

    // 客户端 fd 设为非阻塞（帧循环中 send 不能阻塞 hook）
    var flags2 = _nfFcntl(_clientFd, 3, 0);
    if (flags2 >= 0) _nfFcntl(_clientFd, 4, flags2 | 0x800);

    clientReady = true;
    log("[✓] handshake complete! client ready for frames");
}

// 通过 SCM_RIGHTS 发送单个 fd
function sendFdViaSCM(sockFd, fdToSend) {
    // struct iovec (16 bytes on aarch64)
    var iovBuf = Memory.alloc(1);
    iovBuf.writeU8(0x58); // 'X'
    var iov = Memory.alloc(16);
    iov.writePointer(iovBuf);       // iov_base
    iov.add(8).writeU64(1);         // iov_len = 1

    // cmsg buffer: CMSG_SPACE(sizeof(int)) = 24 on aarch64
    var cmsgBuf = Memory.alloc(24);
    cmsgBuf.writeU64(20);           // cmsg_len = CMSG_LEN(4) = 20
    cmsgBuf.add(8).writeS32(1);    // cmsg_level = SOL_SOCKET
    cmsgBuf.add(12).writeS32(1);   // cmsg_type = SCM_RIGHTS
    cmsgBuf.add(16).writeS32(fdToSend); // fd payload

    // struct msghdr (56 bytes on aarch64)
    var msghdr = Memory.alloc(56);
    msghdr.writePointer(ptr(0));         // msg_name = NULL
    msghdr.add(8).writeU32(0);          // msg_namelen = 0
    // padding 4 bytes at offset 12 (implicit)
    msghdr.add(16).writePointer(iov);   // msg_iov
    msghdr.add(24).writeU64(1);         // msg_iovlen = 1
    msghdr.add(32).writePointer(cmsgBuf); // msg_control
    msghdr.add(40).writeU64(24);        // msg_controllen = CMSG_SPACE(4)
    msghdr.add(48).writeS32(0);         // msg_flags = 0

    var ret = _nfSendmsg(sockFd, msghdr, 0);
    return ret >= 0;
}

// ==================== RING SETUP ====================
function ensureRing(p0, p1, p2, w, h, fmt) {
    if (ringReady) return;
    planeLenY = p0.len; planeLenU = p1.len; planeLenV = p2.len;
    frameSlotSize = planeLenY + planeLenU + planeLenV;
    frameWidth = w; frameHeight = h; frameFmt = fmt;
    var wireDims = resolveWireDimensions(w, h);
    wireWidth = wireDims[0];
    wireHeight = wireDims[1];
    log("[*] frameSlotSize=" + frameSlotSize + " (" + w + "x" + h + " fmt=" + fmt + ")");
    if (wireWidth !== frameWidth || wireHeight !== frameHeight) {
        log("[*] header override: " + frameWidth + "x" + frameHeight + " -> " + wireWidth + "x" + wireHeight);
    }

    for (var i = 0; i < maxFrames; i++) {
        var name = Memory.allocUtf8String("frida_frame_" + i);
        var fd = _memfd_create(name, 0);
        if (fd < 0) { log("[!] memfd_create fail"); ringReady = true; return; }
        _ftruncate(fd, frameSlotSize);
        var addr = _mmap(ptr(0), frameSlotSize, 3, 1, fd, 0); // PROT_READ|PROT_WRITE=3, MAP_SHARED=1
        if (addr.equals(ptr(-1)) || addr.isNull()) {
            log("[!] mmap fail"); _close(fd); ringReady = true; return;
        }
        _memfd_fds.push(fd);
        _memfd_addrs.push(addr);
        log("[*] memfd[" + i + "]: fd=" + fd + " addr=" + addr);
    }
    ringReady = true;
    log("[✓] memfd ring: " + maxFrames + " x " + frameSlotSize + " bytes");

    // 初始化 socket 并创建 server
    ensureSocketNF();
    createSocketServer();
}

// ==================== FRAME GRAB ====================
var m = Process.getModuleByName("libmediandk.so");
var ex = {};
m.enumerateExports().forEach(function(e) { ex[e.name] = e.address; });

var AImageReader_acquireLatestImage = new NativeFunction(ex["AImageReader_acquireLatestImage"], "int", ["pointer", "pointer"]);
var AImage_getWidth  = new NativeFunction(ex["AImage_getWidth"],  "int", ["pointer", "pointer"]);
var AImage_getHeight = new NativeFunction(ex["AImage_getHeight"], "int", ["pointer", "pointer"]);
var AImage_getFormat = new NativeFunction(ex["AImage_getFormat"], "int", ["pointer", "pointer"]);
var AImage_getPlaneData        = new NativeFunction(ex["AImage_getPlaneData"],        "int", ["pointer", "int", "pointer", "pointer"]);
var AImage_getPlaneRowStride   = new NativeFunction(ex["AImage_getPlaneRowStride"],   "int", ["pointer", "int", "pointer"]);
var AImage_getPlanePixelStride = new NativeFunction(ex["AImage_getPlanePixelStride"], "int", ["pointer", "int", "pointer"]);

var _planeBufs = [];
for (var _i = 0; _i < 3; _i++) {
    _planeBufs.push({ dp: Memory.alloc(Process.pointerSize), dl: Memory.alloc(4), rs: Memory.alloc(4), ps: Memory.alloc(4) });
}
var _wBuf = Memory.alloc(4), _hBuf = Memory.alloc(4), _fmtBuf = Memory.alloc(4);
var _memcpy = new NativeFunction(_libc.getExportByName("memcpy"), "pointer", ["pointer", "pointer", "int"]);

function getPlane(imgPtr, i) {
    var b = _planeBufs[i];
    AImage_getPlaneData(imgPtr, i, b.dp, b.dl);
    AImage_getPlaneRowStride(imgPtr, i, b.rs);
    AImage_getPlanePixelStride(imgPtr, i, b.ps);
    return { ptr: b.dp.readPointer(), len: b.dl.readS32(), row: b.rs.readS32(), pix: b.ps.readS32() };
}

// 帧索引发送缓冲区（重用，预分配）
var _idxBuf = Memory.alloc(1);
var _drainBuf = Memory.alloc(16);
// MSG_DONTWAIT=0x40, MSG_NOSIGNAL=0x4000
var MSG_DONTWAIT = 0x40;
var MSG_NOSIGNAL = 0x4000;

Interceptor.attach(ex["AImageReader_acquireLatestImage"], {
    onEnter: function(args) { this.imgPP = args[1]; },
    onLeave: function(retval) {
        if (hookDisabled) return;
        try {
            if (retval.toInt32() !== 0) return;
            var imgPtr = this.imgPP.readPointer();
            if (imgPtr.isNull()) return;
            var now = Date.now();
            if (now - lastWriteTs < minIntervalMs) { skippedCount++; return; }
            lastWriteTs = now;

            AImage_getWidth(imgPtr, _wBuf); AImage_getHeight(imgPtr, _hBuf); AImage_getFormat(imgPtr, _fmtBuf);
            var wi = _wBuf.readS32(), hi = _hBuf.readS32(), fi = _fmtBuf.readS32();
            var p0 = getPlane(imgPtr, 0), p1 = getPlane(imgPtr, 1), p2 = getPlane(imgPtr, 2);

            if (!ringReady) {
                ensureRing(p0, p1, p2, wi, hi, fi);
                log("[*] first frame: " + wi + "x" + hi + " fmt=" + fi);
            }

            // memcpy 到当前 slot
            var slot = frameCount % maxFrames;
            if (_memfd_addrs.length > 0) {
                var base = _memfd_addrs[slot];
                if (!p0.ptr.isNull() && p0.len > 0) _memcpy(base, p0.ptr, p0.len);
                if (!p1.ptr.isNull() && p1.len > 0) _memcpy(base.add(planeLenY), p1.ptr, p1.len);
                if (!p2.ptr.isNull() && p2.len > 0) _memcpy(base.add(planeLenY + planeLenU), p2.ptr, p2.len);
            }
            frameCount++;

            // 发送帧索引给客户端（非阻塞）
            if (clientReady && _clientFd >= 0) {
                _idxBuf.writeU8(slot);
                var sn = _nfSend(_clientFd, _idxBuf, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (sn === 1) {
                    sentCount++;
                } else {
                    // 客户端可能断开
                    clientReady = false;
                    _close(_clientFd);
                    _clientFd = -1;
                    log("[!] client disconnected (send fail)");
                }
            }

            // drain release signals (non-blocking read)
            if (clientReady && _clientFd >= 0) {
                _nfRecv(_clientFd, _drainBuf, 16, MSG_DONTWAIT);
            }

            if (now - lastLogTs >= 5000) {
                var e = (now - startTs) / 1000.0;
                log("[STATS] captured=" + frameCount + " sent=" + sentCount +
                    " skipped=" + skippedCount + " errors=" + errorCount +
                    " fps=" + (e > 0 ? (frameCount / e).toFixed(2) : "0") +
                    " client=" + (clientReady ? "yes" : "no"));
                lastLogTs = now;
            }
        } catch(e) { safeHookError("acq", e); }
    }
});

// ==================== PERIODIC TASKS ====================
setInterval(function() {
    // 尝试接受新客户端
    if (_serverFd >= 0 && _clientFd < 0) {
        tryAcceptClient();
    }
}, 500);

setInterval(function() {
    var status = gAvmInoutStatusAddr ? gAvmInoutStatusAddr.readS32() : "N/A";
    log("[STATUS] block:" + blockCount + " allow:" + allowCount + " status=" + status +
        " stealth=" + stealthMode + " client=" + (clientReady ? "connected" : "none"));
}, 60000);

log("[✓] stealth_camera_v3 loaded. Waiting for camera activation...");
