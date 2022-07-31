function main() {
}

function invokeScript() {
	log('\n================================================================================\n');
	main();
	log('\n================================================================================\n');
}

function rd(path, mode='rb') {
	let file = host.namespace.Debugger.Utility.FileSystem.OpenFile(path);
	let data;
	if(mode==='rb') {
		try {
			data = []
			while(true) {
				data.push(file.ReadBytes(1)[0]);
			}
		} catch(e){
			data = data.toh();
		};
	} else if(mode==='r') {
		data = en([...host.namespace.Debugger.Utility.FileSystem.CreateTextReader(file).ReadLineContents()]);
	} else {
		return null;
	}
	file.Close();
	return data;
}

function wt(path, mode='wb') {
	if(host.namespace.Debugger.Utility.FileSystem.FileExists(path))
		host.namespace.Debugger.Utility.FileSystem.DeleteFile(path);
	if(mode==='w') {
		return function(data='') {
			let file = host.namespace.Debugger.Utility.FileSystem.CreateFile(path);
			if(data!='') {
				let textWriter = host.namespace.Debugger.Utility.FileSystem.CreateTextWriter(file);
				textWriter.Write(data);
			}
			file.Close();
		}
	}
	if(mode==='wb') {
		return function(data) {
			let file = host.namespace.Debugger.Utility.FileSystem.CreateFile(path);
			data = data.tol();
			file.WriteBytes(data, data.length);
			file.Close();
		}
	}
}

function rm(path) {
	if(host.namespace.Debugger.Utility.FileSystem.FileExists(path))
		host.namespace.Debugger.Utility.FileSystem.DeleteFile(path);
}

// deserialization the JSON string
// @param {*} this: string
String.prototype.dser = function() {
	return JSON.parse(this.toString());
}

// serialization the Object to JSON string
// @param {*} this: Object
Object.prototype.ser = function() {
	return JSON.stringify(this);
}

// format the bin
// @param {*} this : bin
String.prototype.fm = function() {
	return this.toString().replace(/\s+/g, '').replace(/(..)/g, ' $1').strip();
}

// @param {*} this : hex
// @param {*} le : bool
String.prototype.p8 = function(le=true) {
	if(le)
		return this.toi().toString(16).padStart(2, '0').slice(-2).tol().reverse().toh();
	else
		return this.toi().toString(16).padStart(2, '0').slice(-2);
}
String.prototype.p16 = function(le=true) {
	if(le)
		return this.toi().toString(16).padStart(4, '0').slice(-4).tol().reverse().toh();
	else
		return this.toi().toString(16).padStart(4, '0').slice(-4);
}
String.prototype.p32 = function(le=true) {
	if(le)
		return this.toi().toString(16).padStart(8, '0').slice(-8).tol().reverse().toh();
	else
		return this.toi().toString(16).padStart(8, '0').slice(-8);
}
String.prototype.p64 = function(le=true) {
	if(le)
		return this.toi().toString(16).padStart(16, '0').slice(-16).tol().reverse().toh();
	else
		return this.toi().toString(16).padStart(16, '0').slice(-16);
}
String.prototype.pp = function(le=true) {
	if(x64())
		return this.p64(le);
	else
		return this.p32(le);
}

// @param {*} this : bin
String.prototype.u8 = function() {
	return '0x' + this.fm().replace(/\s+/g, '').slice(0, 2).tol().reverse().toh()
}
String.prototype.u16 = function() {
	return '0x' + this.fm().replace(/\s+/g, '').slice(0, 4).tol().reverse().toh()
}
String.prototype.u32 = function() {
	return '0x' + this.fm().replace(/\s+/g, '').slice(0, 8).tol().reverse().toh()
}
String.prototype.u64 = function() {
	return '0x' + this.fm().replace(/\s+/g, '').slice(0, 16).tol().reverse().toh()
}
String.prototype.up = function() {
	if(x64())
		return this.u64();
	else
		return this.u32();
}

// @param {*} this : String
String.prototype.strip = String.prototype.trim
String.prototype.lstrip = String.prototype.trimLeft
String.prototype.rstrip = String.prototype.trimRight

// @param {*} this : hex
// @param {*} val : Number
String.prototype.add = function(val) {
	if(typeof(val)==='string') {
		val = val.toi();
	}
	return host.parseInt64(this).add(val).toString();
}
String.prototype.sub = function(val) {
	if(typeof(val)==='string') {
		val = val.toi();
	}
	return host.parseInt64(this).subtract(val).toString();
}
String.prototype.mul = function(val) {
	if(typeof(val)==='string') {
		val = val.toi();
	}
	return host.parseInt64(this).multiply(val).toString();
}
String.prototype.div = function(val) {
	if(typeof(val)==='string') {
		val = val.toi();
	}
	return host.parseInt64(this).divide(val).toString();
}
String.prototype.and = function(val) {
	if(typeof(val)==='string') {
		val = val.toi();
	}
	return host.parseInt64(this).bitwiseAnd(val).toString();
}
String.prototype.or = function(val) {
	if(typeof(val)==='string') {
		val = val.toi();
	}
	return host.parseInt64(this).bitwiseOr(val).toString();
}
String.prototype.xor = function(val) {
	if(typeof(val)==='string') {
		val = val.toi();
	}
	return host.parseInt64(this).bitwiseXor(val).toString();
}
String.prototype.shl = function(val) {
	if(typeof(val)==='string') {
		val = val.toi();
	}
	return host.parseInt64(this).bitwiseShiftLeft(val).toString();
}
String.prototype.shr = function(val) {
	if(typeof(val)==='string') {
		val = val.toi();
	}
	return host.parseInt64(this).bitwiseShiftRight(val).toString();
}
String.prototype.cmp = function(val) {
	if(typeof(val)==='string') {
		val = val.toi();
	}
	return host.parseInt64(this).compareTo(host.parseInt64(val.toString()));
}

String.prototype.in_range = function(val_1, val_2) {
	if(typeof(val_1)==='string') {
		val_1 = val_1.toi();
	}
	if(typeof(val_2)==='string') {
		val_2 = val_2.toi();
	}
	return this.cmp(val_1)>=0 && this.cmp(val_2)<=0;
}

String.prototype.out_range = function(val_1, val_2) {
	return !this.in_range(val_1, val_2);
}

String.prototype.ton = function() {
	return this.toi().asNumber();
}

// @param {*} this : hex
String.prototype.toi = function() {
	return host.parseInt64(this);
}

// @param {*} this : bin
String.prototype.tol = function() {
	return this.match(/[a-fA-F0-9]{2}/g).map(byte => parseInt(byte, 16));
}

// @param {*} this : Array
Array.prototype.toh = function() {
	return this.map(byte => ('0' + (byte & 0xff).toString(16)).slice(-2)).join('');
}
Array.prototype.len = function() {
	return this.length;
}

// @param {*} this : Array
// @param {*} idx : Number
Array.prototype.at = function(idx) {
	if(idx>=0)
		return this[idx];
	else
		return this[this.length+idx];
}

// @param {*} sym : String => windbg address
function $(sym) {
	sym = sym.toString().strip();
	if(!sym)
		throw new Error(`Invalid Address! ${sym}`);
	val = exec(`?${sym}`)[0];
	if(val.indexOf('resolve error')!=-1)
		throw new Error(`Invalid Address! ${sym}`);
	ret = host.parseInt64(val.split(' ').at(-1), 16).toString();
	if(sym.length>=2 && sym[0]=="'" && sym.slice(-1)=="'")
		return ret.pp(false).replace(/^0*/, '').up();
	else
		return ret;
}

function exec(cmd) {
	var ctl = host.namespace.Debugger.Utility.Control;
	return [...ctl.ExecuteCommand(cmd)];
}

function mod(ea) {
	if(ea===undefined || ea==='')
		ea = cea();
	val = exec(`lmoa ${ea}`);
	if(val.length!=3)
		return '0x0';
	return $(val.at(-1).split(/\s+/)[0]);
}

function mod_name(ea) {
	if(ea==undefined || ea==='')
		ea = cea();
	val = exec(`lm1ma (${ea})`);
	if(val.length<1)
		return '';
	return val[0].strip();
}

function rva(ea) {
	if(ea===undefined || ea==='')
		ea = cea();
	return ea.sub(mod(ea).toi());
}

function rvk(pattern) {
	data = exec('k')
		.slice(1)
		.map(line => $(line.split(/\s+/)[2]))
		.filter(ea => ea.cmp(0)!=0)
	if(pattern!='' && pattern!=undefined)
		data = data.filter(ea => mod_name(ea).toLowerCase()===pattern.toLowerCase());
	return data.map(rva);
}

function proc() {
	return $('@$proc');
}

function cea() {
	return $('@$ip');
}

function ip() {
	return $('@$ip');
}

function sp() {
	return $('@$csp');
}

function rdm(addr, len) {
	return [... host.memory.readMemoryValues(host.parseInt64(addr), len)].toh();
}

// @param {*} this : hex
String.prototype.it = function() {
	return new it(this.toString());
}

String.prototype.n = function() {
	return new it(this.toString()).n().it().ea;
}

String.prototype.p = function() {
	return new it(this.toString()).p().it().ea;
}

String.prototype.rdm = function(len) {
	return [... host.memory.readMemoryValues(host.parseInt64(this), len)].toh();
}

String.prototype.rdi = function(cnt=1, size_to_cnt=false) {
	let ret = ''
	let cur_it = this
	
	if(size_to_cnt) {
		if(cnt>=0) {
			while(ret.length/2<cnt) {
				ret += cur_it.it().rdi();
				cur_it = cur_it.n();
			}
		} else {
			cnt = -cnt;
			while(ret.length/2<cnt) {
				ret = cur_it.it().rdi() + ret;
				cur_it = cur_it.p();
			}
		}
	} else {
		if(cnt>=0) {
			for(let i=0; i<cnt; ++i) {
				ret += cur_it.it().rdi();
				cur_it = cur_it.n();
			}
		} else {
			cnt = -cnt;
			let ret_list = [];
			for(let i=0; i<cnt; ++i) {
				ret_list.push(cur_it.it().rdi());
				cur_it = cur_it.p();
			}
			ret = ret_list.reverse().join('');
		}
	}
	return ret;
}

String.prototype.rdb = function() {
	return host.memory.readMemoryValues(this.toi(), 1, 1)[0];
}

String.prototype.rdw = function() {
	return host.memory.readMemoryValues(this.toi(), 1, 2)[0];
}

String.prototype.rdd = function() {
	return host.memory.readMemoryValues(this.toi(), 1, 4)[0];
}

String.prototype.rdq = function() {
	return host.memory.readMemoryValues(this.toi(), 1, 8)[0];
}

String.prototype.rdp = function() {
	if(x64())
		return this.rdq();
	else
		return this.rdd();
}

String.prototype.b = function(len=1) {
	let ret = [];
	for(i=0; i<len; ++i) {
		ret.push(this.add(i).rdb());
	}
	return ret;
}

String.prototype.w = function(len=1) {
	let ret = [];
	for(i=0; i<len; ++i) {
		ret.push(this.add(i*2).rdw());
	}
	return ret;
}

String.prototype.d = function(len=1) {
	let ret = [];
	for(i=0; i<len; ++i) {
		ret.push(this.add(i*4).rdd());
	}
	return ret;
}

String.prototype.q = function(len=1) {
	let ret = [];
	for(i=0; i<len; ++i) {
		ret.push(this.add(i*8).rdq());
	}
	return ret;
}

String.prototype.ptr = function(len=1) {
	if(x64())
		return this.q(len);
	else
		return this.d(len);
}

function rds(addr) {
	return host.memory.readString(addr);
}

String.prototype.rds = function() {
	return rds(host.parseInt64(this));
}

function rdws(addr) {
	return host.memory.readWideString(addr);
}

String.prototype.rdws = function() {
	return rdws(host.parseInt64(this));
}

String.prototype.wtm = function(data) {
	exec('eb ' + this + ' ' + data.fm());
}

function eva(...cmd) {
	log('\n================================================================================\n');
	log(eval(en(cmd)));
	log('\n================================================================================\n');
}

function en(list) {
	return list.join('\n');
}

function exec_log(cmd, pattern='', npattern='') {
	log('\n================================================================================\n');
	log(en(exec(cmd).filter((line)=>{
		if(npattern) 
			return line.toLowerCase().match(pattern.toLowerCase()) && !line.toLowerCase().match(npattern.toLowerCase());
		else
			return line.toLowerCase().match(pattern.toLowerCase());
	})));
	log('\n================================================================================\n');
}

function log(...string) {
	host.diagnostics.debugLog(...string);
}

function logn(...string) {
	log(...string, '\n')
}

function calc(...expr) {
	return host.evaluateExpression(...expr);
}

function x64() {
	return host.namespace.Debugger.State.PseudoRegisters.General.ptrsize === 8;
}

function x86() {
	return host.namespace.Debugger.State.PseudoRegisters.General.ptrsize === 4;
}

function kd() { 
	return host.namespace.Debugger.Sessions.First().Attributes.Target.IsKernelTarget === true;
}

class Pe {
	constructor(ea) {
		this.ea = ea;
	}
}

class Ps {
	constructor(proc_identifier=-1) {
		if(proc_identifier===-1) {
			this.proc = host.currentProcess;
		}
	}
}

class Cs {
	constructor(ea) {
		if(!Cs.disassembler)
			Cs.disassembler = x64() ? host.namespace.Debugger.Utility.Code.CreateDisassembler('X64'):host.namespace.Debugger.Utility.Code.CreateDisassembler('X86');
		if(ea===undefined)
			this.ea = cea();
		else
			this.ea = ea;
	}
	
	dis(cnt=1) {
		let tmp_cnt = 0;
		let ins_arr = [];
		
		if(cnt<1)
			return ins_arr;
		
		for(let i of Cs.disassembler.DisassembleInstructions(this.ea.toi())) {
			ins_arr.push(i)
			if(ins_arr.length>=cnt)
				break;
		}
		return ins_arr;
	}
	
	bb() {
		let func = Cs.disassembler.DisassembleFunction(this.ea.toi());
		let bbs = [... func.BasicBlocks];
		return bbs;
	}
}

class it {
	constructor(ea=undefined) {
		if(ea===undefined || ea==='') {
			this.ea = cea();
			this.ins = new Cs(this.ea).dis()[0];
		}
		else if(typeof(ea)==='string') {
			this.ea  = ea;
			this.ins = new Cs(this.ea).dis()[0];
		}
		else {
			throw new Error(`Invalid address! ${ea}`);
		}
	}
	
	ea() {
		return this.ea;
	}
	
	rva() {
		return rva(this.ea);
	}
	
	rdi() {
		return exec(`u ${this.ea} l1`).at(-1).split(/\s+/)[1];
	}
	
	n() {
		return this.ea.add(this.ins.Length);
	}
	
	p() {
		return this.ea.sub(exec(`ub ${this.ea} l5`).at(-1).split(/\s+/)[1].length/2);
	}
	
	iscall() {
		return this.ins.Attributes.IsCall;
	}
	
	isret() {
		return this.rdi().match(/^c2|^c3|^ca|^cb|^cf/) != null;
	}
	
	toString() {
		return 'it: ' + this.ea;
	}
}

class fn {
	constructor(ea=undefined) {
		if(ea===undefined)
			this.ea = cea();
		else
			this.ea = exec(`uf /o ${ea}`).slice(0, 5).filter(ins => ins.match(/^[a-fA-F0-9]{8}/)).map(ins => $(ins.split(/\s+/)[0]))[0];
	}
	
	ea() {
		return this.ea;
	}
	
	rva() {
		return rva(this.ea);
	}
	
	op() {
		return this.ea;
	}
	
	ed() {
		return exec(`uf /o ${this.ea}`).slice(-5).filter(ins => ins.match(/^[a-fA-F0-9]{8}/)).map(ins => $(ins.split(/\s+/)[0])).at(-1);
	}
	
	len() {
		return this.ed().n().sub(this.op().toi());
	}
	
	itx() {
		let bbs = new Cs(this.ea).bb().map(bb => [... bb.Instructions]);
		return [].concat(... bbs).map(ins => ins.Address.toString());
	}
	
	it() {
		let bbs = new Cs(this.ea).bb().map(bb => [... bb.Instructions]);
		return [].concat(... bbs).map(ins => ins.Address.toString().it());
	}
	
	call() {
		return this.itx().filter(it => it.it().iscall());
	}
	
	ret() {
		return this.itx().filter(it => it.it().isret());
	}
	
	toString() {
		return 'fn: ' + this.ea;
	}
}

class bb {
	constructor(ea=undefined) {
		
	}
	
	toString() {
		return 'bb: ' + this.ea;
	}
}

class Mm {
	static init(pages_cnt_per_type=8) {
		let pages_size_per_type = pages_cnt_per_type*0x1000;
		let mgr={};
		mgr.bitmap = {};
		for(let i=6; i<=9; ++i) {
			mgr.bitmap[i] = '0'.repeat(pages_size_per_type/(2**i));
		}
		
		rm('c:\\windbg_mm.json');
		wt('c:\\windbg_mm.json', 'w')(mgr.ser());
		return '';
	}
	
	static alloc(size=64, pool_base_rva=0x85000, pages_cnt_per_type=8) {
		let pages_size_per_type = pages_cnt_per_type*0x1000;
		
		let idx=0;
		for(let i=6; i<9; ++i) {
			if(size<=2**i) {
				idx = i;
				break;
			}
			if(size>2**i && size<=2**(i+1)) {
				idx = i+1;
				break;
			}
		}
		if(idx===0)
			throw new Error(`allocate failed! size: ${size}`);
		
		let mgr = rd('c:\\windbg_mm.json', 'r').dser();
		let base = $('HEVD').add(pool_base_rva).add((idx-6)*pages_size_per_type);
		let off_idx = mgr.bitmap[idx].search('0');
		if(off_idx===-1) {
			throw new Error(`allocate failed! Not enough storage!`);
		}
		else {
			mgr.bitmap[idx] = mgr.bitmap[idx].replace('0', '1');
			wt('c:\\windbg_mm.json', 'w')(mgr.ser());
		}
		return base.add(off_idx*(2**idx));
	}
	
	static free(addr, pool_base_rva=0x85000, pages_cnt_per_type=8) {
		let pages_size_per_type = pages_cnt_per_type*0x1000;
		
		let mgr = rd('c:\\windbg_mm.json', 'r').dser();
		let base = $('HEVD').add(pool_base_rva);
		
		let idx = addr.sub(base).div(pages_size_per_type).add(6);
		let off_idx = -1;
		if(idx.in_range(6, 9)) {
			off_idx = addr.sub(base.add(idx.sub(6).mul(pages_size_per_type))).div(2**idx).ton();
			mgr.bitmap[idx.ton()] = mgr.bitmap[idx.ton()].slice(0, off_idx)+'0'+mgr.bitmap[idx.ton()].slice(off_idx+1);
			wt('c:\\windbg_mm.json', 'w')(mgr.ser());
		}
		else {
			throw new Error(`free failed! Invalid address! ${addr}`);
		}
	}
}

class Bp {
	constructor(hook_entry) {
		this.hook_entry = hook_entry;
	}
	
	static op() {
		let mgr = {};
		rm('c:\\windbg_bp.json');
		wt('c:\\windbg_bp.json', 'w')(mgr.ser());
		return '';
	}
	
	static ed() {
		let mgr = rd('c:\\windbg_bp.json', 'r').dser();
	}
	
	static ls() {
		let mgr = rd('c:\\windbg_bp.json', 'r').dser();
		let log_text = '';
		
		for(let i of Object.keys(mgr)) {
			log_text += '\n' + '-'.repeat(8) + '\n' + '* idx: ' + i + '\n\n';
			log_text += JSON.stringify(mgr[i], null, "\t") + '\n';
		}
		if(Object.keys(mgr).length!=0)
			log(log_text + '-'.repeat(8) + '\n');
		return '';
	}
	
	static mk(bp_obj) {
		let mgr = rd('c:\\windbg_bp.json', 'r').dser();
		let idx = 0;
		let idx_list = Object.keys(mgr);
		while(true) {
			if(idx_list.indexOf(String(idx))!=-1)
				idx += 1;
			else
				break;
		}
		mgr[idx] = bp_obj;
		wt('c:\\windbg_bp.json', 'w')(mgr.ser());
	}
	
	static rm(idx) {
		if(idx===undefined)
			return;
		let mgr = rd('c:\\windbg_bp.json', 'r').dser();
		
		let patches = mgr[idx].patches;
		let patches_list = Object.keys(patches);
		for(let i of patches_list) {
			i.wtm(mgr[idx].patches[i]);
		}
		
		let allocs = mgr[idx].allocs;
		let allocs_list = Object.keys(allocs);
		for(let i of allocs_list) {
			Mm.free(i);
		}
		
		delete mgr[idx];
		wt('c:\\windbg_bp.json', 'w')(mgr.ser());
		return '';
	}
	
	static info(ea) {
		if(ea===undefined)
			ea = cea();
		let mgr = rd('c:\\windbg_bp.json', 'r').dser();
		
		
		
		return '';
	}
	
	ps() {
		let PsGetCurrentProcess = $('PsGetCurrentProcess');
		let KPROCESS = proc();
		let break_ins = this.hook_entry.rdi(17, true);
		let hook_entry_adjust = this.hook_entry.add(break_ins.length/2);
		let target = Mm.alloc(0x55);
		let hook_entry_ins = '50c7042441414141c744240442424242c3'
			.replace(/41414141/g, target.pp().slice(0, 8))
			.replace(/42424242/g, target.pp().slice(8, 16));
		let target_ins = '5048b84141414142424242ffd0c74424f843434343c74424fc44444444483b4424f87501cc5890909090909090909090909090909090909090909090909090909090909050c7042463454545c744240446464646c3'
			.replace(/41414141/g, PsGetCurrentProcess.pp().slice(0, 8))
			.replace(/42424242/g, PsGetCurrentProcess.pp().slice(8, 16))
			.replace(/43434343/g, KPROCESS.pp().slice(0, 8))
			.replace(/44444444/g, KPROCESS.pp().slice(8, 16))
			.replace(/63454545/g, hook_entry_adjust.pp().slice(0, 8))
			.replace(/46464646/g, hook_entry_adjust.pp().slice(8, 16))
			.replace('90'.repeat(30), break_ins);
		this.hook_entry.wtm(hook_entry_ins);
		target.wtm(target_ins);
		
		let bp_obj = {};
		bp_obj.type = 'ps';
		bp_obj.info = {};
		bp_obj.patches = {};
		bp_obj.allocs = {};
		bp_obj.info['proc'] = KPROCESS;
		bp_obj.patches[this.hook_entry] = break_ins;
		bp_obj.allocs[target] = '';
		Bp.mk(bp_obj);
		return ''
	}
	
	ps_tag(tag_pattern) {
		let tag_val = $(tag_pattern).p32().match(/../g).map(i=>i.toLowerCase()=='3f'?'00':i).join('');
		
		let PsGetCurrentProcess = $('PsGetCurrentProcess');
		let KPROCESS = proc();
		
		let op_target = Mm.alloc(0x4c);
		let ed_target = Mm.alloc(0x75);
		let args_address = Mm.alloc(40);
		let tag_address = args_address.add(0x10);
		
		let op_entry = $('ExAllocatePoolWithTag');
		let op_break_ins = op_entry.rdi(17, true);
		let op_adjust_entry = op_entry.add(op_break_ins.length/2);
		let hook_op_ins = '50c7042441414141c744240442424242c3'
			.replace(/41414141/g, op_target.pp().slice(0, 8))
			.replace(/42424242/g, op_target.pp().slice(8, 16));
		let op_target_ins = '415249ba414141414242424249890a498952084d8942104d894a18415a90909090909090909090909090909090909090909090909090909090909050c7042461434343c744240445454545c3'
			.replace(/41414141/g, args_address.pp().slice(0, 8))
			.replace(/42424242/g, args_address.pp().slice(8, 16))
			.replace(/61434343/g, op_adjust_entry.pp().slice(0, 8))
			.replace(/45454545/g, op_adjust_entry.pp().slice(8, 16))
			.replace('90'.repeat(30), op_break_ins);
			
		let ed_entry;
		let ret_ea_arr = new fn(op_entry).ret();
		if(ret_ea_arr.length===1)
			ed_entry = ret_ea_arr[0];
		else
			throw new Error(`Multi ret ins!\n ${en(ret_ea_arr)}`);
		
		let ed_break_ins = ed_entry.rdi(-17, true);
		let ed_adjust_entry = ed_entry.n().sub(ed_break_ins.length/2);
		let hook_ed_ins = '50c7042441414141c744240442424242c3'
			.replace(/41414141/g, ed_target.pp().slice(0, 8))
			.replace(/42424242/g, ed_target.pp().slice(8, 16));
		let ed_target_ins = '5141525048b84141414142424242ffd0c74424f843434343c74424fc45454545483b4424f8752c48b846464646474747478b0041ba48484848b1fc4584d274054438d0750ec1c80841c1ca08fec184c975e9cc58415a59909090909090909090909090909090909090909090909090909090909090'
			.replace(/41414141/g, PsGetCurrentProcess.pp().slice(0, 8))
			.replace(/42424242/g, PsGetCurrentProcess.pp().slice(8, 16))
			.replace(/43434343/g, KPROCESS.pp().slice(0, 8))
			.replace(/45454545/g, KPROCESS.pp().slice(8, 16))
			.replace(/46464646/g, tag_address.pp().slice(0, 8))
			.replace(/47474747/g, tag_address.pp().slice(8, 16))
			.replace(/48484848/g, tag_val)
			.replace('90'.repeat(30), ed_break_ins);
		
		op_target.wtm(op_target_ins);
		ed_target.wtm(ed_target_ins);
		op_entry.wtm(hook_op_ins);
		ed_adjust_entry.wtm(hook_ed_ins);
		
		let bp_obj = {};
		bp_obj.type = 'ps_tag';
		bp_obj.info = {};
		bp_obj.patches = {};
		bp_obj.allocs = {};
		bp_obj.info['proc'] = KPROCESS;
		bp_obj.info['tag_pattern'] = tag_pattern;
		bp_obj.info['args_address'] = args_address;
		bp_obj.patches[op_entry] = op_break_ins;
		bp_obj.patches[ed_adjust_entry] = ed_break_ins;
		bp_obj.allocs[op_target] = '';
		bp_obj.allocs[ed_target] = '';
		bp_obj.allocs[args_address] = '';
		Bp.mk(bp_obj);
		
		return '';
	}
	
	ps_ret(ret_val_op, ret_val_range_size=0) {
		let ret_val_ed = ret_val_op.add(ret_val_range_size);
		let PsGetCurrentProcess = $('PsGetCurrentProcess');
		let KPROCESS = proc();
		let break_ins = this.hook_entry.rdi(-17, true);
		let target = Mm.alloc(0x76);
		let hook_entry_ins = '50c7042441414141c744240442424242c3'
			.replace(/41414141/g, target.pp().slice(0, 8))
			.replace(/42424242/g, target.pp().slice(8, 16));
		let target_ins = '5048b84141414142424242ffd0c74424f843434343c74424fc45454545483b4424f87533488b0424c74424f846464646c74424fc47474747483b4424f87218c74424f848484848c74424fc49494949483b4424f87701cc58909090909090909090909090909090909090909090909090909090909090'
			.replace(/41414141/g, PsGetCurrentProcess.pp().slice(0, 8))
			.replace(/42424242/g, PsGetCurrentProcess.pp().slice(8, 16))
			.replace(/43434343/g, KPROCESS.pp().slice(0, 8))
			.replace(/45454545/g, KPROCESS.pp().slice(8, 16))
			.replace(/46464646/g, ret_val_op.pp().slice(0, 8))
			.replace(/47474747/g, ret_val_op.pp().slice(8, 16))
			.replace(/48484848/g, ret_val_ed.pp().slice(0, 8))
			.replace(/49494949/g, ret_val_ed.pp().slice(8, 16))
			.replace('90'.repeat(30), break_ins);
		this.hook_entry.n().sub(break_ins.length/2).wtm(hook_entry_ins);
		target.wtm(target_ins);
		
		let bp_obj = {};
		bp_obj.type = 'ps_ret';
		bp_obj.info = {};
		bp_obj.patches = {};
		bp_obj.allocs = {};
		bp_obj.info['proc'] = KPROCESS;
		bp_obj.info['ret_range'] = [ret_val_op, ret_val_ed];
		bp_obj.patches[this.hook_entry.n().sub(break_ins.length/2)] = break_ins;
		bp_obj.allocs[target] = '';
		Bp.mk(bp_obj);
		return '';
	}
	
	ps_arg(idx, arg_val_op, arg_val_range_size=0) {
		let arg_val_ed = arg_val_op.add(arg_val_range_size);
		let PsGetCurrentProcess = $('PsGetCurrentProcess');
		let KPROCESS = proc();
		let break_ins = this.hook_entry.rdi(17, true);
		let hook_entry_adjust = this.hook_entry.add(break_ins.length/2);
		let target = Mm.alloc(0x87);
		let hook_entry_ins = '50c7042441414141c744240442424242c3'
			.replace(/41414141/g, target.pp().slice(0, 8))
			.replace(/42424242/g, target.pp().slice(8, 16));
		let target_ins = '';
		if(idx===-1) {
			target_ins = '5048b84141414142424242ffd0c74424f843434343c74424fc45454545483b4424f87533488b0424c74424f846464646c74424fc47474747483b4424f87218c74424f848484848c74424fc49494949483b4424f87701cc5890909090909090909090909090909090909090909090909090909090909050c704244f313131c744240432323232c3';
		} else if(idx===0) {
			target_ins = '5048b84141414142424242ffd0c74424f843434343c74424fc45454545483b4424f87533488b0424c74424f846464646c74424fc47474747483b4c24f87218c74424f848484848c74424fc49494949483b4c24f87701cc5890909090909090909090909090909090909090909090909090909090909050c704244f313131c744240432323232c3';
		} else if (idx===1) {
			target_ins = '5048b84141414142424242ffd0c74424f843434343c74424fc45454545483b4424f87533488b0424c74424f846464646c74424fc47474747483b5424f87218c74424f848484848c74424fc49494949483b5424f87701cc5890909090909090909090909090909090909090909090909090909090909050c704244f313131c744240432323232c3';
		} else if(idx===2) {
			target_ins = '5048b84141414142424242ffd0c74424f843434343c74424fc45454545483b4424f87533488b0424c74424f846464646c74424fc474747474c3b4424f87218c74424f848484848c74424fc494949494c3b4424f87701cc5890909090909090909090909090909090909090909090909090909090909050c704244f313131c744240432323232c3';
		} else if(idx===3) {
			target_ins = '5048b84141414142424242ffd0c74424f843434343c74424fc45454545483b4424f87533488b0424c74424f846464646c74424fc474747474c3b4c24f87218c74424f848484848c74424fc494949494c3b4c24f87701cc5890909090909090909090909090909090909090909090909090909090909050c704244f313131c744240432323232c3';
		} else {
			return '';
		}
		target_ins = target_ins
			.replace(/41414141/g, PsGetCurrentProcess.pp().slice(0, 8))
			.replace(/42424242/g, PsGetCurrentProcess.pp().slice(8, 16))
			.replace(/43434343/g, KPROCESS.pp().slice(0, 8))
			.replace(/45454545/g, KPROCESS.pp().slice(8, 16))
			.replace(/46464646/g, arg_val_op.pp().slice(0, 8))
			.replace(/47474747/g, arg_val_op.pp().slice(8, 16))
			.replace(/48484848/g, arg_val_ed.pp().slice(0, 8))
			.replace(/49494949/g, arg_val_ed.pp().slice(8, 16))
			.replace(/4f313131/g, hook_entry_adjust.pp().slice(0, 8))
			.replace(/32323232/g, hook_entry_adjust.pp().slice(8, 16))
			.replace('90'.repeat(30), break_ins);
		this.hook_entry.wtm(hook_entry_ins);
		target.wtm(target_ins);
		
		let bp_obj = {};
		bp_obj.type = 'ps_arg';
		bp_obj.info = {};
		bp_obj.patches = {};
		bp_obj.allocs = {};
		bp_obj.info['proc'] = KPROCESS;
		bp_obj.info['arg_idx'] = idx;
		bp_obj.info['arg_range'] = [arg_val_op, arg_val_ed];
		bp_obj.patches[this.hook_entry] = break_ins;
		bp_obj.allocs[target] = '';
		Bp.mk(bp_obj);
		return '';
	}
}
