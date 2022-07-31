//----------------------------------------------------------------------
// proc- Process
function md(name=-1) {
    if(name==-1) {
        return Process.enumerateModules()
    } else {
        return Process.getModuleByName(name)
    }
}

String.prototype.md = function() {
    return md(this)
}

function td() {
    return Process.enumerateThreads()
}

function pid() {
    return Process.id
}

function tid() {
    return Process.getCurrentThreadId()
}

function arch() {
    return Process.arch
}

function isdbg() {
    return Process.isDebuggerAttached()
}

function mm(protection) {
    return Process.enumerateRanges(protection)
}
String.prototype.mm = function() {return Process.getRangeByAddress(ptr(this))}
Number.prototype.mm = function() {return Process.getRangeByAddress(ptr(this))}

// findModuleByAddress

//----------------------------------------------------------------------
// thrd- Thread

function ss(seconds) {
    Thread.sleep(seconds)
}

function btf(context) {
    if(context) {
        return Thread.backtrace(context, Backtracer.FUZZY)
    } else {
        return Thread.backtrace()
    }
}

function bt(context) {
    if(context) {
        return Thread.backtrace(context, Backtracer.ACCURATE)
    } else {
        return Thread.backtrace()
    }
}

Array.prototype.k = function() {
    log('\n---------------------------------------------\n'
        +this.map(DebugSymbol.fromAddress).join('\n'))
}
//----------------------------------------------------------------------
// mod- Module
// sym- symbol parse

function ld(path) {
    return Module.load(path)
}

String.prototype.ld = function() {return Module.load(this)}

Module.prototype.im = function() {
    return this.enumerateImports()
}

String.prototype.im = function() {
    return md(this).enumerateImports()
}

Module.prototype.ex = function(name='') {
    if(name==='') {
        return this.enumerateExports()
    } else {
        //findExportByName return null
        return this.getExportByName(name)
    }
}

String.prototype.ex = function(name='') {
    if(!this && name) {
        //Module.findExportByName return null
        return Module.getExportByName(null, name)
    }
    
    if(name==='') {
        return md(this).enumerateExports()
    } else {
        //findExportByName return null
        return md(this).getExportByName(name)
    }
}

Module.prototype.mm = function(protection) {
    return this.enumerateRanges(protection)
}

String.prototype.mm = function(protection) {
    return md(this).enumerateRanges(protection)
}

Module.prototype.b = function() {return this.base}
String.prototype.b = function() {
    //Module.findBaseAddress return null
    return Module.getBaseAddress(this)
}

String.prototype.iapi = function(case_insensitive=true) {
    const resolver = new ApiResolver('module');
    
    var query_string = 'imports:' + this
    if(case_insensitive) query_string += '/i'
    
    var matches = resolver.enumerateMatches(query_string)
    
    return matches
}

String.prototype.eapi = function(case_insensitive=true) {
    const resolver = new ApiResolver('module');
    
    var query_string = 'exports:' + this
    if(case_insensitive) query_string += '/i'
    
    var matches = resolver.enumerateMatches(query_string)
    
    return matches
}

String.prototype.api = function(case_insensitive=true) {
    const resolver = new ApiResolver('module');
    
    if(this.indexOf('!')==-1) {
        var query_string = 'exports:*!' + this
    } else {
        var query_string = 'exports:' + this
    }
    
    if(case_insensitive) query_string += '/i'
    
    var matches = resolver.enumerateMatches(query_string)
    
    return matches
}

String.prototype.apx = function(case_insensitive=true) {
    var ret = this.api(case_insensitive)
    if(ret.length==1) {
        return ret[0].address
    } else {
        return null
    }
}

Module.prototype.syms = function() {
    return this.enumerateSymbols()
}

String.prototype.syms = function() {
    return md(this).enumerateSymbols()
}

//----------------------------------------------------------------------
// mem- Memory

function rdm(addr, size) {
    return Memory.readByteArray(addr, size)
}

function wtm(addr, data) {
    return Memory.writeByteArray(addr, data)
}

function malloc(size) {
    return Memory.alloc(size)
}

function mcp(dst, src, size) {
    Memory.copy(dst, src, size)
}

function mdup(addr, size) {
    return Memory.dup(addr, size)
}

function mprot(addr, size, protection) {
    return Memory.protect(address, size, protection)
}

function mscan(addr, size, pattern) {
    return Memory.scanSync(addr, size, pattern)
}

function mscanx() {}

function u8s(str) {
    return Memory.allocUtf8String(str)
}

String.prototype.u8s = function() {
	var data = u8s(this)
	var i = -1;
	while(true) {
		i = i+1
		if(data.add(i).rdu8()===0) break
	}
	return data.rdm(i+1)
}

function u16s(str) {
    return Memory.allocUtf16String(str)
}

String.prototype.u16s = function() {
	var data = u16s(this)
	var i = -2
	while(true) {
		i = i+2
		if(data.add(i).rdu16()===0) break
	}
	return data.rdm(i+2)
}

function as(str) {
    return Memory.allocAnsiString(str)
}

String.prototype.as = function() {
	var data = as(this)
	var i = -1
	while(true) {
		i = i+1
		if(data.add(i).rdu8()===0) break
	}
	return data.rdm(i+1)
}

//----------------------------------------------------------------------
//fn- NativeFunction NativeCallbacks

//ret && arg_list types
//- void - pointer - int - uint - long - ulong 
//- char - uchar - size_t - ssize_t - float 
//- double - int8 - uint8 - int16 - uint16 - int32 
//- uint32 - int64 - uint64 - bool

function fn(addr) {
    return (ret) => {
        return (...arg_list) => {
            return new NativeFunction(addr, ret, arg_list)
        }
    }
}

NativePointer.prototype.fn = function(ret) {
    return (...arg_list) => {
        return new NativeFunction(this, ret, arg_list)
    }
}
String.prototype.fn = function(ret) {
    return (...arg_list) => {
        return new NativeFunction(ptr(this), ret, arg_list)
    }
}
Number.prototype.fn = function(ret) {
    return (...arg_list) => {
        return new NativeFunction(ptr(this), ret, arg_list)
    }
}

function fnx(js_func) {
    return (ret) => {
        return (...arg_list) => {
            return new NativeCallback(js_func, ret, arg_list)
        }
    }
}

Function.prototype.fnx = function(ret) {
    return (...arg_list) => {
        return new NativeCallback(this, ret, arg_list)
    }
}

function rp(target) {
    return (replacement) => {
        if(Function.prototype.isPrototypeOf(replacement)) {
            return (ret) => {
                return (...arg_list) => {
                    Interceptor.replace(ptr(target), new NativeCallback(replacement, ret, arg_list))
                }
            }
        }
        else {
            Interceptor.replace(ptr(target), replacement)
        }
    }
}

NativePointer.prototype.rp = function(replacement) {
    if(Function.prototype.isPrototypeOf(replacement)) {
        return (ret) => {
            return (...arg_list) => {
                Interceptor.replace(ptr(this), new NativeCallback(replacement, ret, arg_list))
            }
        }
    }
    else {
        Interceptor.replace(ptr(this), replacement)
    }
}
String.prototype.rp = function(replacement) {
    if(Function.prototype.isPrototypeOf(replacement)) {
        return (ret) => {
            return (...arg_list) => {
                Interceptor.replace(ptr(this), new NativeCallback(replacement, ret, arg_list))
            }
        }
    }
    else {
        Interceptor.replace(ptr(this), replacement)
    }
}
Number.prototype.rp = function(replacement) {
    if(Function.prototype.isPrototypeOf(replacement)) {
        return (ret) => {
            return (...arg_list) => {
                Interceptor.replace(ptr(this), new NativeCallback(replacement, ret, arg_list))
            }
        }
    }
    else {
        Interceptor.replace(ptr(this), replacement)
    }
}

NativePointer.prototype.rv = function() {Interceptor.revert(this)}
String.prototype.rv = function() {Interceptor.revert(ptr(this))}
Number.prototype.rv = function() {Interceptor.revert(ptr(this))}

//----------------------------------------------------------------------
//hook- hk- Interceptor

function hk(target, callback) {
    if((callback.op===undefined) && (callback.ed===undefined)) {
        Interceptor.attach(target, callback)
    } else {
        Interceptor.attach(target, {onEnter:callback.op, onLeave:callback.ed})
    }
}

NativePointer.prototype.hk = function(callback) {
    return hk(this, callback)
}

String.prototype.hk = function(callback) {
    return hk(ptr(this), callback)
}

Number.prototype.hk = function(callback) {
    return hk(ptr(this), callback)
}

Array.prototype.hk = function(mod_name) {
    return (callback=undefined) => {
        this.map(ptr)
        .map((x)=>{
            return x.add(mod_name.b())
        })
        .map((x)=>{
            var callback_backup
            if(callback===undefined) {
                callback_backup = (args) => {
                    log(tid(), x)
                }
            }
            return x.hk(callback_backup)
        })
    }
}

function uhk() {
    Interceptor.detachAll()
}

//----------------------------------------------------------------------
//ins- Instruction

function dis(addr, n=1) {
    var insts = []
    for(var i=0; i<n; ++i) {
        var ins = Instruction.parse(ptr(addr))
        insts.push(ins)
        addr = ptr(ins.next)
    }
    return insts
}

function u(addr, n=1) {
    var insts = dis(addr, n)
    var inst_str = ''
    for(var i=0; i<n; ++i) {
        inst_str += insts[i].address.toString() + '\t' + insts[i].toString() + '\n'
    }
    log(inst_str)
}

function ux(addr, n=1) {
    var insts = dis(addr, n)
    var inst_str = ''
    for(var i=0; i<n; ++i) {
        inst_str += insts[i].address.toString() + '\t' + insts[i].address.rdm(insts[i].size).hex().padEnd(32) + insts[i].toString() + '\n'
    }
    log(inst_str)
}

NativePointer.prototype.dis = function(n=1) {return dis(this, n)}
NativePointer.prototype.u = function(n=1) {u(this, n)}
NativePointer.prototype.ux = function(n=1) {ux(this, n)}

String.prototype.dis = function(n=1) {return dis(ptr(this), n)}
Number.prototype.dis = function(n=1) {return dis(ptr(this), n)}
String.prototype.u = function(n=1) {u(ptr(this), n)}
Number.prototype.u = function(n=1) {u(ptr(this), n)}
String.prototype.ux = function(n=1) {ux(ptr(this), n)}
Number.prototype.ux = function(n=1) {ux(ptr(this), n)}
//----------------------------------------------------------------------
//ptr- NativePointer
NativePointer.prototype.mm = function() {return Process.getRangeByAddress(this)}
NativePointer.prototype.s = function(pattern, size=512) {return mscan(this, size, pattern)}
NativePointer.prototype.cp = function(dst, size) {Memory.copy(dst, this, size)}
NativePointer.prototype.dup = function(size) {return Memory.dup(this, size)}
NativePointer.prototype.prot = function(protection, size=4096) {return Memory.protect(this, size, protection)}
NativePointer.prototype.hex = function(size=1) {return this.rdm(size).hex()}
NativePointer.prototype.hexd = function(size=48, off=0) {hexd(this, size, off)}

NativePointer.prototype.rdp = function() {return this.readPointer()}
NativePointer.prototype.wtp = function(addr) {return this.writePointer(ptr(addr))}
NativePointer.prototype.rdm = function(size=1) {return this.readByteArray(size)}
NativePointer.prototype.wtm = function(data) {return this.writeByteArray(data)}
NativePointer.prototype.rdu8s = function(size=-1) {return this.readUtf8String(size)}
NativePointer.prototype.rdu16s = function(len=-1) {return this.readUtf16String(len)}
NativePointer.prototype.wtu8s = function(str) {return this.writeUtf8String(str)}
NativePointer.prototype.wtu16s = function(str) {return this.writeUtf16String(str)}
NativePointer.prototype.rdas = function(size=-1) {return this.readAnsiString(size)}
NativePointer.prototype.wtas = function(str) {return this.writeAnsiString(str)}
NativePointer.prototype.rdcs = function(size=-1) {return this.readCString(size)}

NativePointer.prototype.rds8 = function() {return this.readS8()}
NativePointer.prototype.rds16 = function() {return this.readS16()}
NativePointer.prototype.rds32 = function() {return this.readS32()}
NativePointer.prototype.rds64 = function() {return this.readS64()}
NativePointer.prototype.rdu8 = function() {return this.readU8()}
NativePointer.prototype.rdu16 = function() {return this.readU16()}
NativePointer.prototype.rdu32 = function() {return this.readU32()}
NativePointer.prototype.rdu64 = function() {return this.readU64()}
NativePointer.prototype.rdf = function() {return this.readFloat()}
NativePointer.prototype.rdD = function() {return this.readDouble()}

NativePointer.prototype.eq = function(rhs) {return this.equals(rhs)}
NativePointer.prototype.cmp = function(rhs) {return this.compare(rhs)}
NativePointer.prototype.tos = function(radix=10) {return this.toString(radix)}
NativePointer.prototype.toi = function() {return parseInt(this)}
NativePointer.prototype.toh = function() {return this.toi().toh()}
//----------------------------------------------------------------------

ArrayBuffer.prototype.hex = function() { 
    return Array.prototype.map.call(new Uint8Array(this), x => ('00' + x.toString(16)).slice(-2)).join('');
}

String.prototype.bin = function() {
    return (new Uint8Array(this.match(/[a-fA-F0-9]{2}/g).map(byte => parseInt(byte, 16)))).buffer
}

ArrayBuffer.prototype.wt = function() {
    
}

function hexd(data, size=48, off=0) {
    console.log(hexdump(data, {
        offset: off,
        length: size,
        header: true,
        ansi: true
    }))
}

function sd(msg=undefined) {
    send(msg)
}

ArrayBuffer.prototype.sd = function(msg=undefined) {
    send(msg, this)
    return this
}

String.prototype.sd = function(msg=undefined) {
    send(msg, this.bin())
    return this.bin()
}

function rc(msg_type='input') {
    var recv_data = null
    
    function recv_callback(res) {
        if(res.data)
            recv_data = res.data.bin()
    }
    
    recv(msg_type, recv_callback).wait()
    return recv_data
}

String.prototype.rc = function() {
    var recv_data = null
    
    function recv_callback(res) {
        recv_data = res.data.bin()
    }
    
    if(this==='') {
        recv(recv_callback).wait()
    } else {
        recv(this, recv_callback).wait()
    }
    
    return recv_data
}

var log = console.log
var err = console.error

function wt(path, data) {
    var fd = new File(path, 'wb')
    var ret = fd.write(data)
    fd.flush()
    fd.close()
    return ret
}

String.prototype.wt = function(data) {
    var fd = new File(this, 'wb')
    var ret = fd.write(data)
    fd.flush()
    fd.close()
    return ret
}

//----------------------------------------------------------------------

Array.prototype.uniq = function() {return [...new Set(this)]}
Array.prototype.has = function(item) {return this.indexOf(item)!=-1}
Array.prototype.idx = function(item) {return this.indexOf(item)}
Array.prototype.len = function() {return this.length}
ArrayBuffer.prototype.len = function() {return this.byteLength}
ArrayBuffer.prototype.tol = function() {return [...new Uint8Array(this)]}
ArrayBuffer.prototype.mul = function(num=1) {return this.hex().mul(num).bin()}
String.prototype.len = function() {return this.length}
String.prototype.mul = function(num=1) {return this.repeat(num)}
String.prototype.pad = function(num, pad_char) {return this.padEnd(num, pad_char)}
String.prototype.padl = function(num, pad_char) {return this.padStart(num, pad_char)}
String.prototype.padr = function(num, pad_char) {return this.padEnd(num, pad_char)}
String.prototype.padc = function(num, pad_char) {return this.padStart((num+this.length)/2, pad_char).padEnd(num, pad_char)}
String.prototype.toi = function() {return parseInt(this)}
String.prototype.toh = function() {return this.toi().toh()}
String.prototype.p = function() {return ptr(this)}
Number.prototype.p = function() {return ptr(this)}
Number.prototype.tos = function() {return String(this)}
Number.prototype.toh = function() {return '0x'+this.toString(16)}

String.prototype.c = function() {return new CModule(this)}

Object.prototype.dmjs = function() {return JSON.stringify(this)}
Object.prototype.ldjs = function() {return JSON.parse(this)}


function lds(path) {
    DebugSymbol.load(path)
}

String.prototype.lds = function() {DebugSymbol.load(this)}
NativePointer.prototype.sym = function() {return DebugSymbol.fromAddress(this)}

//----------------------------------------------------------------------
//io- IOStream

InputStream.prototype.rd = function(size) {return this.read(size)}
InputStream.prototype.rda = function(size) {return this.readAll(size)}
InputStream.prototype.cls = function() {this.close()}

OutputStream.prototype.wt = function(data) {return this.write(data)}
OutputStream.prototype.wta = function(data) {return this.writeAll(data)}
OutputStream.prototype.wtx = function(addr, size) {return this.writeMemoryRegion(addr, size)}
OutputStream.prototype.cls = function() {this.close()}

NativePointer.prototype.wi = function(auto_close=false) {
    if(auto_close) {
        return new Win32InputStream(ptr(this), {autoClose:true})
    } else {
        return new Win32InputStream(ptr(this))
    }
    
}
String.prototype.wi = function(auto_close=false) {
    if(auto_close) {
        return new Win32InputStream(ptr(this), {autoClose:true})
    } else {
        return new Win32InputStream(ptr(this))
    }
    
}
Number.prototype.wi = function(auto_close=false) {
    if(auto_close) {
        return new Win32InputStream(ptr(this), {autoClose:true})
    } else {
        return new Win32InputStream(ptr(this))
    }
    
}
NativePointer.prototype.wo = function(auto_close=false) {
    if(auto_close) {
        return new Win32OutputStream(ptr(this), {autoClose:true})
    } else {
        return new Win32OutputStream(ptr(this))
    }
}
String.prototype.wo = function(auto_close=false) {
    if(auto_close) {
        return new Win32OutputStream(ptr(this), {autoClose:true})
    } else {
        return new Win32OutputStream(ptr(this))
    }
}
Number.prototype.wo = function(auto_close=false) {
    if(auto_close) {
        return new Win32OutputStream(ptr(this), {autoClose:true})
    } else {
        return new Win32OutputStream(ptr(this))
    }
}
NativePointer.prototype.ui = function(auto_close=false) {
    if(auto_close) {
        return new UnixInputStream(ptr(this), {autoClose:true})
    } else {
        return new UnixInputStream(ptr(this))
    }
}
String.prototype.ui = function(auto_close=false) {
    if(auto_close) {
        return new UnixInputStream(ptr(this), {autoClose:true})
    } else {
        return new UnixInputStream(ptr(this))
    }
}
Number.prototype.ui = function(auto_close=false) {
    if(auto_close) {
        return new UnixInputStream(ptr(this), {autoClose:true})
    } else {
        return new UnixInputStream(ptr(this))
    }
}
NativePointer.prototype.uo = function(auto_close=false) {
    if(auto_close) {
        return new UnixOutputStream(ptr(this), {autoClose:true})
    } else {
        return new UnixOutputStream(ptr(this))
    }
}
String.prototype.uo = function(auto_close=false) {
    if(auto_close) {
        return new UnixOutputStream(ptr(this), {autoClose:true})
    } else {
        return new UnixOutputStream(ptr(this))
    }
}
Number.prototype.uo = function(auto_close=false) {
    if(auto_close) {
        return new UnixOutputStream(ptr(this), {autoClose:true})
    } else {
        return new UnixOutputStream(ptr(this))
    }
}
//----------------------------------------------------------------------

var win = {
    rc:() => 'ws2_32.dll'.ex('recv').hk({
        op:function (args) {
            this.handle = args[0].toi()
            this.buf = args[1]
            this.len = args[2].toi()
        },
        ed:function (ret) {
            log()
            this.buf.hexd(64)
            log((' recv tid: '+tid().toh()+' '+tid().tos()+' '+
                'handle: '+this.handle.toh()+' '+this.handle.tos()+' ').padc(70, '*'))
        }
    }),
    
    rcf:() => 'ws2_32.dll'.ex('recvfrom').hk({
        op:function (args) {
            log('*********************recvfrom*********************')
        },
        ed:function (ret) {
            log((' recvfrom tid: '+tid().toh()+' '+tid().tos()+' '+
                'handle: '+this.handle.toh()+' '+this.handle.tos()+' ').padc(70, '*'))
        }
    }),
    
    rcx:() => 'ws2_32.dll'.ex('WSARecv').hk({
        op:function (args) {
                this.handle = args[0].toi()
                this.bufs = args[1]
                this.cnt = args[2]
                this.recvd_bytes_num = args[3]
                ss(0.5)
        },
        ed:function (ret) {
            if(arch()==='ia32') {
                
            } else {
                
            }
            log()
            log((' WSARecv tid: '+tid().toh()+' '+tid().tos()+' '+
                'handle: '+this.handle.toh()+' '+this.handle.tos()+' ').padc(70, '*'))
        }
    }),

    rcfx:() => 'ws2_32.dll'.ex('WSARecvFrom').hk({
        op:function (args) {
            log('*******************WSARecvFrom********************')
        }
    }),
    
    wf:() => 'kernel32.dll'.ex('WriteFile').hk({
        op:function (args) {
            this.handle = args[0].toi()
            this.buf = args[1]
            this.p_len = args[3]
        },
        ed:function (ret) {
            this.len = this.p_len.rdu32()
            log((' WriteFile tid: '+tid().toh()+' '+tid().tos()+' '+
                'handle: '+this.handle.toh()+' '+this.handle.tos()+' ').padc(70, '*'))
        }
    })
}

//----------------------------------------------------------------------