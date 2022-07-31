# coding=utf-8

import idc
import idautils
import ida_idp
import idaapi
import ida_kernwin
import ida_bytes
import ida_ua
import ida_nalt

from io import StringIO as sio
from io import BytesIO as bio

def set_clip(data):
    import win32clipboard
    import win32con
    data = str(data)
    win32clipboard.OpenClipboard()
    win32clipboard.EmptyClipboard()
    win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, data)
    win32clipboard.CloseClipboard()

def get_clip():
    import win32clipboard
    import win32con
    win32clipboard.OpenClipboard()
    data = win32clipboard.GetClipboardData()
    win32clipboard.CloseClipboard()
    return data
    
p = print
en = lambda lst:'\n'.join(list(map(str, lst)))
nem = lambda target: list(filter(lambda x:x, target))

def sset(data, ignore_case=True):
    def _strip(data):
        class custom_str(str):
            def __init__(self, data):
                self.data = data
            def __hash__(self):
                return hash(self.data.lower())
            def __eq__(self, other):
                return self.lower()==other.lower()
        if type(data)==str:
            if ignore_case:
                return nem(map(lambda x:custom_str(x.strip()), data.split('\n')))
            else:
                return nem(map(lambda x:x.strip(), data.split('\n')))
        ret = []
        try:
            if ignore_case:
                ret = map(lambda x:custom_str(str(x).strip()), data)
            else:
                ret = map(lambda x:str(x).strip(), data)
        except:
            if ignore_case:
                ret = [custom_str(str(data).strip())]
            else:
                ret = [str(data).strip()]
        return nem(ret)
    return set(_strip(data))
    
def rd(file_path, file_flag='rb'):
    import chardet
    if file_flag=='rb':
        return open(file_path, file_flag).read()
    elif file_flag=='r':
        content = open(file_path, 'rb').read()
        return content.decode(chardet.detect(content)['encoding'])
    else:
        return None
    
def wt(file_path, file_flag='wb'):
    return lambda data:open(file_path, file_flag).write(data)
    
def fmap(data):
    ret = []
    def _fmap(_data):
        try:
            if type(_data)==str or type(_data)==bytes or type(_data)==dict:
                raise ValueError
            for i in _data:
                _fmap(i)
        except:
            ret.append(_data)
    _fmap(data)
    return ret
# --------------------------------------------------------------------------------

cea = idc.here
bad = idc.BADADDR

symea = idc.get_name_ea_simple
rid = ida_idp.str2reg

def va_unpack(addr):
    if type(addr)==va:
        return addr.i
    elif type(addr)==int:
        return addr
    else:
        return None

def symnm(ea=-1):
    if ea==-1:
        ea = cea()
    return idc.get_name(va_unpack(ea))

def dman(name):
    return idc.demangle_name(name, idc.get_inf_attr(idc.INF_LONG_DN))
    
def fcf(ea=-1):
    if ea==-1:
        ea = cea()
    return idc.get_first_fcref_from(va_unpack(ea))
    
def fct(ea=-1):
    if ea==-1:
        ea = cea()
    return idc.get_first_fcref_to(va_unpack(ea))
    
def nct(ea, cur):
    return idc.get_next_fcref_to(va_unpack(ea), cur)
    
def fdf(ea=-1):
    if ea==-1:
        ea = cea()
    return idc.get_first_dref_from(va_unpack(ea))
    
def fdt(ea=-1):
    if ea==-1:
        ea = cea()
    return idc.get_first_dref_to(va_unpack(ea))
    
def ndt(ea, cur):
    return idc.get_next_dref_to(va_unpack(ea), cur)

def cro(x=-1):
    if x==-1:
        x = cea()
    x = va_unpack(x)
    ref = fcf(x)
    x_name = fn(x).nm
    try:
        return ref!=bad and x_name!=fn(ref).nm
    except fn_err:
        return ref!=bad and x_name!=symnm(ref)
    
def cf(ea=-1):
    if ea==-1:
        ea = cea()
    return list(idautils.CodeRefsFrom(va_unpack(ea), 0))

def ct(ea=-1):
    if ea==-1:
        ea = cea()
    return list(idautils.CodeRefsTo(va_unpack(ea), 0))
    
def df(ea=-1):
    if ea==-1:
        ea = cea()
    return list(idautils.DataRefsFrom(va_unpack(ea)))

def dt(ea=-1):
    if ea==-1:
        ea = cea()
    return list(idautils.DataRefsTo(va_unpack(ea)))

def jmp(ea=-1):
    if ea==-1:
        ida_kernwin.jumpto(cea())
    else:
        return ida_kernwin.jumpto(va_unpack(ea))
        
def jmp_rva(rva):
    jmp(idaapi.get_imagebase()+rva)
    
def jmp_off(off):
    jmp(idaapi.get_fileregion_ea(off))
        
def is32():
    return not is64()

def is64():
    return idaapi.get_inf_structure().is_64bit()
    
def isbe():
    return idaapi.get_inf_structure().is_be()
    
def base():
    return idaapi.get_imagebase()
    
def act_win(name):
    form = ida_kernwin.find_widget(name)
    ida_kernwin.activate_widget(form, True)
    
def clear_output_window():
    act_win('Output window')
    idaapi.process_ui_action('msglist:Clear')
    jmp()
    
def rva_to_va(data):
    ret = []
    if type(data)==list or type(data)==tuple or type(data)==set:
        for i in data:
            if type(i)==int:
               ret.append(i+base())
            if type(i)==str:
                ret.append(int(i, 0)+base())
    if type(data)==int:
        ret = data+base()
        
    if type(data)==str:
        ret = int(data, 0)+base()
    return ret
    
def va_to_rva(data):
    ret = []
    if type(data)==list or type(data)==tuple or type(data)==set:
        for i in data:
            if type(i)==int:
               ret.append(i-base())
            if type(i)==va:
               ret.append(i-base())
            if type(i)==str:
                ret.append(int(i, 0)-base())
                
    if type(data)==int:
        ret = data-base()
    if type(data)==va:
        ret.append(i-base())
    if type(data)==str:
        ret = int(data, 0)-base()
    return ret

def off_to_va(data):
    ret = []
    if type(data)==list or type(data)==tuple or type(data)==set:
        for i in data:
            if type(i)==int:
               ret.append(idaapi.get_fileregion_ea(i))
            if type(i)==str:
                ret.append(idaapi.get_fileregion_ea(int(i, 0)))
    if type(data)==int:
        ret = idaapi.get_fileregion_ea(data)
        
    if type(data)==str:
        ret = idaapi.get_fileregion_ea(int(data, 0))
    return ret
    
def off_to_rva(data):
    return va_to_rva(off_to_va(data))

class va_err(ValueError):
    pass

class va(int):
    @property
    def i(self):
        return int(self)
        
    @property
    def o(self):
        return idaapi.get_fileregion_offset(self.i)
        
    @property
    def it(self):
        return it(self.i)
        
    def dye(self, size=1, color=0):
        op = self
        cur = op
        cnt = 0
        while cnt<size:
            cur.it.dye(color)
            cnt += cur.sz
            cur = cur.n
        return [op, cur.p]
        
    def cmt(self, data):
        ida_bytes.append_cmt(self.i, data, True)
        
    @property
    def fn(self):
        return fn(self.i)
        
    @property
    def bb(self):
        return bb(self.i)
        
    @property
    def sz(self):
        return self.it.sz
        
    @property
    def dis(self):
        return self.it.dis
        
    @property
    def n(self):
        return self.it.n
        
    @property
    def p(self):
        return self.it.p
        
    @property
    def arg(self):
        ret = idaapi.get_arg_addrs(self.i)
        if not ret:
            raise va_err('Not Caller!')
        return list(map(va, ret))
        
    @property
    def fcf(self):
        return idc.get_first_fcref_from(va_unpack(self))
        
    @property
    def jmp(self):
        return jmp(va_unpack(self))
        
    @property
    def code(self):
        return idc.is_code(idc.get_full_flags(self.i))
        
    @property
    def data(self):
        return idc.is_data(idc.get_full_flags(self.i))
        
    @property
    def tail(self):
        return idc.is_tail(idc.get_full_flags(self.i))
        
    @property
    def head(self):
        return idc.is_head(idc.get_full_flags(self.i))
        
    @property
    def unk(self):
        return idc.is_unknown(idc.get_full_flags(self.i))

    @property
    def rva(self):
        return self-idaapi.get_imagebase()

    def rd(self, size=-1):
        if size==-1:
            if is32():
                size = 4
            elif is64():
                size = 8
            else:
                size = 1
            return idaapi.get_bytes(self.i, size)
        else:
            return idaapi.get_bytes(self.i, size)
            
    @property
    def rdb(self):
        return idc.get_wide_byte(self.i)
        
    def b(self, num=1):
        return [va(self.i+i*1).rdb for i in range(num)]
        
    @property
    def rdw(self):
        return idc.get_wide_word(self.i)
        
    def w(self, num=1):
        return [va(self.i+i*2).rdw for i in range(num)]
        
    @property
    def rdd(self):
        return idc.get_wide_dword(self.i)
        
    def d(self, num=1):
        return [va(self.i+i*4).rdd for i in range(num)]
        
    @property
    def rdq(self):
        return idc.get_qword(self.i)
        
    def q(self, num=1):
        return [va(self.i+i*8).rdq for i in range(num)]
        
    @property
    def rdp(self):
        return self.rdq if is64() else self.rdd
        
    def ptr(self, num=1):
        if is64():
            return self.q(num)
        else:
            return self.d(num)
        
    @property
    def rdf(self):
        return idc.GetFloat(self.i)
        
    def f(self, num=1):
        return [va(self.i+i*4).rdf for i in range(num)]
    
    @property
    def rdD(self):
        return idc.GetDouble(self.i)
        
    def D(self, num=1):
        return [va(self.i+i*8).rdD for i in range(num)]
        
    def rdi(self, cnt=1, size_to_cnt=False):
        ret = b''
        cur_it = self
        
        if size_to_cnt:
            while len(ret)<cnt:
                ret += cur_it.it.rdi
                cur_it = cur_it.n
        else:
            for i in range(cnt):
                ret += cur_it.it.rdi
                cur_it = cur_it.n
        return ret

    def xt(self, *opt):
        opt_cnt = 0
        color = 0
        ret_list = True
        filter = ''
        for i in opt:
            opt_cnt += 1
            if opt_cnt>3:
                break
            if type(i)==int:
                color = i
            if type(i)==bool:
                ret_list = i
            if type(i)==str:
                filter = i
        if not ret_list:
            ret = ['='*80]
        else:
            ret = []
        for i in idautils.XrefsTo(self.i):
            # if i.type==idc.fl_F:
                # continue
            if not ret_list:
                it(i.frm).dye(color)
            frm_site = hex(i.frm).ljust(20)
            frm_site_dis = '\n'+' '*4+va(i.frm).dis+'\n'
            ref_type = idautils.XrefTypeName(i.type).ljust(20)
            try:
                frm_start = hex(fn(i.frm).op).ljust(20)
                frm_name = fn(i.frm).nm
            except fn_err:
                frm_start = hex(bad).ljust(20)
                frm_name = symnm(i.frm)
            item = '[*] '+frm_site+ref_type+frm_start+frm_name+frm_site_dis
            if not ret_list:
                ret.append(item if filter.lower() in item.lower() else '')
            else:
                class tmp_ref:
                    def __init__(self, ref):
                        self.frm = va(ref.frm)
                        self.to = va(ref.to)
                        self.type = idautils.XrefTypeName(ref.type)
                ret.append(tmp_ref(i) if filter.lower() in item.lower() else None)
        if not ret_list:
            ret.extend(['='*80, ('to: '+hex(self.i)).ljust(20)+'total: '+str(len(nem(ret))-1), '='*80])
            return en(nem(ret))
        else:
            return nem(ret)
        
class it(object):
    def __init__(self, ea=-1):
        if ea==-1:
            self._ea = ida_bytes.get_item_head(cea())
        else:
            self._ea = ida_bytes.get_item_head(va_unpack(ea))
            
    def __repr__(self):
        return 'it: ' + hex(self.ea)

    @property
    def ea(self):
        if self._ea==bad:
            return va(bad)
        return va(self._ea)
        
    @property
    def rva(self):
        if self._ea==bad:
            return bad
        return self.ea.rva
    
    @property
    def n(self):
        if self._ea==bad:
            return va(bad)
        return va(idc.next_head(self._ea))
    
    @property
    def p(self):
        if self._ea==bad:
            return va(bad)
        return va(idc.prev_head(self._ea))
        
    @property
    def sz(self):
        return idc.get_item_size(self._ea)
        
    @property
    def rdi(self):
        return va(self.ea).rd(ida_ua.decode_insn(ida_ua.insn_t(), self.ea.i))
        
    @property
    def len(self):
        return len(self.rdi)

    @property
    def dis(self):
        return idc.generate_disasm_line(self._ea, 0)
        
    @property
    def fn(self):
        return fn(self.ea)
        
    @property
    def bb(self):
        return bb(self.ea)
        
    @property
    def arg(self):
        return self.ea.arg
    
    @property
    def op(self):
        if self._ea==bad:
            return ''
        return idc.print_insn_mnem(self._ea)
    
    @property
    def opnd(self):
        if self._ea==bad:
            return None
        operands = []
        idx = 0
        while True:
            operand = idc.print_operand(self._ea, idx)
            if operand =='':
                break
            else:
                operands.append(operand)
            idx += 1
        return operands
    
    @property
    def opv(self):
        if self._ea==bad:
            return None
        opvals = []
        idx = 0
        while True:
            opval = idc.get_operand_value(self._ea, idx)
            if opval==-1:
                break
            else:
                opvals.append(opval)
            idx += 1
        return opvals
        
    @property
    def opl(self):
        return len(self.opv)

# o_void     = ida_ua.o_void      # No Operand                           ----------
# o_reg      = ida_ua.o_reg       # General Register (al,ax,es,ds...)    reg
# o_mem      = ida_ua.o_mem       # Direct Memory Reference  (DATA)      addr
# o_phrase   = ida_ua.o_phrase    # Memory Ref [Base Reg + Index Reg]    phrase
# o_displ    = ida_ua.o_displ     # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
# o_imm      = ida_ua.o_imm       # Immediate Value                      value
# o_far      = ida_ua.o_far       # Immediate Far Address  (CODE)        addr
# o_near     = ida_ua.o_near      # Immediate Near Address (CODE)        addr
# o_idpspec0 = ida_ua.o_idpspec0  # Processor specific type
# o_idpspec1 = ida_ua.o_idpspec1  # Processor specific type
# o_idpspec2 = ida_ua.o_idpspec2  # Processor specific type
# o_idpspec3 = ida_ua.o_idpspec3  # Processor specific type
# o_idpspec4 = ida_ua.o_idpspec4  # Processor specific type
# o_idpspec5 = ida_ua.o_idpspec5  # Processor specific type
                                # # There can be more processor specific types
# # x86
# o_trreg  =       ida_ua.o_idpspec0      # trace register
# o_dbreg  =       ida_ua.o_idpspec1      # debug register
# o_crreg  =       ida_ua.o_idpspec2      # control register
# o_fpreg  =       ida_ua.o_idpspec3      # floating point register
# o_mmxreg  =      ida_ua.o_idpspec4      # mmx register
# o_xmmreg  =      ida_ua.o_idpspec5      # xmm register

# # arm
# o_reglist  =     ida_ua.o_idpspec1      # Register list (for LDM/STM)
# o_creglist  =    ida_ua.o_idpspec2      # Coprocessor register list (for CDP)
# o_creg  =        ida_ua.o_idpspec3      # Coprocessor register (for LDC/STC)
# o_fpreglist  =   ida_ua.o_idpspec4      # Floating point register list
# o_text  =        ida_ua.o_idpspec5      # Arbitrary text stored in the operand
# o_cond  =        (ida_ua.o_idpspec5+1)  # ARM condition as an operand

# # ppc
# o_spr  =         ida_ua.o_idpspec0      # Special purpose register
# o_twofpr  =      ida_ua.o_idpspec1      # Two FPRs
# o_shmbme  =      ida_ua.o_idpspec2      # SH & MB & ME
# o_crf  =         ida_ua.o_idpspec3      # crfield      x.reg
# o_crb  =         ida_ua.o_idpspec4      # crbit        x.reg
# o_dcr  =         ida_ua.o_idpspec5      # Device control register

    @property
    def opt(self):
        if self._ea==bad:
            return None
        ret = []
        idx = 0
        while True:
            tmp = idc.get_operand_type(self._ea, idx)
            if not tmp:
                break
            else:
                ret.append(['void', 'reg', 'mem', 'phrase', 'displ', 'imm', 'far', 'near', 'sp0', 'sp1', 'sp2', 'sp3', 'sp4', 'sp5'][tmp])
            idx += 1
        return ret
        
    @property
    def opx(self):
        return tuple(zip(self.opt, self.opv))
        
    def isok(self, *rules):
        for rule in rules:
            if type(rule)==str:
                if not list(filter(lambda x:x[0].lower().startswith(rule.lower()), self.opx)):
                    return False
            if type(rule)==tuple or type(rule)==list:
                if not list(filter(lambda x:x[0].lower().startswith(rule[0].lower()) and x[1]==rule[1], self.opx)):
                    return False
        return True
                
        
        
    def dye(self, index=0):
        if self._ea==bad:
            return
        color_table = [0xffffff, 0x00ff00, 0x1E90FF, 0xFFB90F, 0xD15FEE, 0xFF1493]
        idc.set_color(self._ea, idc.CIC_ITEM, color_table[index%len(color_table)])
    
    @property
    def iscall(self):
        if self._ea==bad:
            return False
        return ida_idp.is_call_insn(self._ea)
    
    @property
    def isret(self):
        if self._ea==bad:
            return False
        return ida_idp.is_ret_insn(self._ea)
        
    @property
    def isij(self):
        if self._ea==bad:
            return False
        return ida_idp.is_indirect_jump_insn(self._ea)
        
    @property
    def isdc(self):
        if self._ea==bad:
            return False
        return bool(self.iscall and not cf(self._ea))
        
    @property
    def isic(self):
        if self._ea==bad:
            return False
        return bool(self.iscall and (self.opt[0]=='displ' or self.opt[0]=='phrase' or self.opt[0]=='mem' or self.opt[0]=='reg'))

def fnx(*x):
    return map(fn, idautils.Functions(*x))

class fn_err(ValueError):
    pass

class fn(object):
    def __init__(self, ea=-1):
        if ea==-1:
            self._ea = idc.get_func_attr(cea(), idc.FUNCATTR_START)
        else:
            self._ea = idc.get_func_attr(va_unpack(ea), idc.FUNCATTR_START)
        if self._ea==bad:
            raise fn_err('Invalid Function Address!')
            
    def __repr__(self):
        return 'fn: ' + hex(self.ea)
    
    @property
    def ea(self):
        return va(idc.get_func_attr(self._ea, idc.FUNCATTR_START))
        
    @property
    def rva(self):
        return self.ea.rva
    
    @property     
    def op(self):
        return self.ea
        
    @property
    def ed(self):
        return it(idc.get_func_attr(self._ea, idc.FUNCATTR_END)).p
        
    @property
    def len(self):
        return idc.get_func_attr(self._ea, idc.FUNCATTR_END)-self.op

    @property
    def itx(self):
        return list(map(va, list(idautils.FuncItems(self._ea))))
    
    @property
    def it(self):
        return [it(i) for i in self.itx]
        
    @property
    def ro(self):
        return list(filter(cro, self.itx))
        
    @property
    def call(self):
        return nem([i.ea if i.iscall else None for i in self.it])
        
    @property
    def ret(self):
        return nem([i.ea if i.isret else None for i in self.it])
        
    @property
    def ij(self):
        return nem([i.ea if i.isij else None for i in self.it])
        
    @property
    def dc(self):
        return nem([i.ea if i.isdc else None for i in self.it])
        
    @property
    def ic(self):
        return nem([i.ea if i.isic else None for i in self.it])
        
    def ok(self, *rules):
        return list(filter(lambda itx:itx.it.isok(*rules), self.itx))
     
    # @property
    # def of(self):
        # return idc.get_func_off_str(self._ea)
    
    @property
    def nm(self):
        return idc.get_func_name(self._ea)
        
    @property
    def bb(self):
        if self._ea==bad:
            return []
        return [bb(i) for i in idaapi.FlowChart(idaapi.get_func(self._ea), flags=idaapi.FC_PREDS)]
        
    def dye(self, index=0):
        for i in self.it:
            i.dye(index)
        
    def xt(self, *opt):
        return va(self.op).xt(*opt)
        
    def xf(self, *opt):
        opt_cnt = 0
        color = 0
        ban_color = False
        filter = ''
        for i in opt:
            opt_cnt += 1
            if opt_cnt>3:
                break
            if type(i)==int:
                color = i
            if type(i)==bool:
                ban_color = i
            if type(i)==str:
                filter = i
        ret = ['='*80]
        for j in self.itx:
            for i in idautils.XrefsFrom(j.i):
                if i.type==idc.fl_F or i.type==idc.fl_JN:
                    continue
                if not ban_color:
                    it(i.frm).dye(color)
                frm_site = hex(i.frm).ljust(20)
                ref_type = idautils.XrefTypeName(i.type).ljust(20)
                to_site = hex(i.to).ljust(20)
                to_name = symnm(i.to)
                item = frm_site+ref_type+to_site+to_name
                ret.append(item if filter.lower() in item.lower() else '')
        ret.extend(['='*80])
        return en(nem(ret))
    
    # @property
    # def flg(self):
        # flag_dict = {
            # idc.FUNC_NORET:'FUNC_NORET',
            # idc.FUNC_FAR:'FUNC_FAR',
            # idc.FUNC_LIB:'FUNC_LIB',
            # idc.FUNC_STATIC:'FUNC_STATIC',
            # idc.FUNC_FRAME:'FUNC_FRAME',
            # idc.FUNC_USERFAR:'FUNC_USERFAR',
            # idc.FUNC_HIDDEN:'FUNC_HIDDEN',
            # idc.FUNC_THUNK:'FUNC_THUNK',
            # idc.FUNC_BOTTOMBP:'FUNC_BOTTOMBP'
        # }
        # flag_list = {
            # idc.FUNC_NORET,
            # idc.FUNC_FAR,
            # idc.FUNC_LIB,
            # idc.FUNC_STATIC,
            # idc.FUNC_FRAME,
            # idc.FUNC_USERFAR,
            # idc.FUNC_HIDDEN,
            # idc.FUNC_THUNK,
            # idc.FUNC_BOTTOMBP
        # }
        # flg = idc.GetFunctionFlags(self._ea)
        # new_flag_list = filter(lambda x:x&flg, flag_list)
        # return [flag_dict[i] for i in new_flag_list]
    
    # @property
    # def flag(self):
        # return idc.GetFunctionFlags(self._ea)

def sgx():
    return list(map(seg, idautils.Segments()))

class seg(object):
    def __init__(self, ea=-1):
        if ea==-1:
            self._ea = idc.get_segm_start(cea())
        else:
            self._ea = idc.get_segm_start(va_unpack(ea))
            
    def __repr__(self):
        return 'seg: ' + hex(self.ea)
    
    @property
    def ea(self):
        if self._ea==bad:
            return va(bad)
        return va(self._ea)
        
    @property
    def rva(self):
        if self._ea==bad:
            return bad
        return self.ea.rva
    
    @property
    def op(self):
        if self._ea==bad:
            return va(bad)
        return va(idc.get_segm_start(self._ea))
        
    @property
    def ed(self):
        if self._ea==bad:
            return va(bad)
        return va(idc.get_segm_end(self._ea))
        
    @property
    def nm(self):
        if self._ea==bad:
            return ''
        return idc.get_segm_name(self._ea)

    @property
    def n(self):
        if self._ea==bad:
            return va(bad)
        return va(idc.get_next_seg(self._ea))
    
            
class bb(object):
    def __init__(self, bb=-1):
        if type(bb)==idaapi.BasicBlock:
            self.bb = bb
            return
        if bb==-1:
            bb = cea()
        for i in idaapi.FlowChart(idaapi.get_func(fn(bb).ea.i), flags=idaapi.FC_PREDS):
            if bb>=i.start_ea and bb<i.end_ea:
                self.bb = i
                
    def __repr__(self):
        return 'bb: ' + hex(self.ea)

    @property
    def rva(self):
        return self.op.rva
    
    @property
    def op(self):
        return va(self.bb.start_ea)
        
    @property
    def ea(self):
        return self.op
        
    @property
    def ed(self):
        return it(self.bb.end_ea).p
        
    @property
    def id(self):
        return self.bb.id
        
    @property
    def n(self):
        return list(map(bb, self.bb.succs()))
        
    @property
    def p(self):
        return list(map(bb, self.bb.preds()))
        
    @property
    def itx(self):
        ret = []
        p_cur = self.op
        while p_cur<=self.ed:
            ret.append(p_cur)
            p_cur = it(p_cur).n
        return list(map(va, ret))
        
    @property
    def it(self):
        return [it(i) for i in self.itx]
        
    @property
    def fn(self):
        return fn(self.op)
        
    def dye(self, color=0):
        for i in self.it:
            i.dye(color)
        
    @property
    def ro(self):
        return list(filter(cro, self.itx))
        
    @property
    def call(self):
        return nem([i.ea if i.iscall else None for i in self.it])
        
    @property
    def ret(self):
        return nem([i.ea if i.isret else None for i in self.it])
        
    @property
    def ij(self):
        return nem([i.ea if i.isij else None for i in self.it])
        
    @property
    def dc(self):
        return nem([i.ea if i.isdc else None for i in self.it])
        
    @property
    def ic(self):
        return nem([i.ea if i.isic else None for i in self.it])
        
    def ok(self, *rules):
        return list(filter(lambda itx:itx.it.isok(*rules), self.itx))
        
    def xt(self, *opt):
        return va(self.op).xt(*opt)
        
    def xf(self, *opt):
        opt_cnt = 0
        color = 0
        ban_color = False
        filter = ''
        for i in opt:
            opt_cnt += 1
            if opt_cnt>3:
                break
            if type(i)==int:
                color = i
            if type(i)==bool:
                ban_color = i
            if type(i)==str:
                filter = i
        ret = ['='*80]
        for j in self.itx:
            for i in idautils.XrefsFrom(j.i):
                if i.type==idc.fl_F and i.frm!=self.ed.i:
                    continue
                if not ban_color:
                    it(i.frm).dye(color)
                frm_site = hex(i.frm).ljust(20)
                ref_type = idautils.XrefTypeName(i.type).ljust(20)
                to_site = hex(i.to).ljust(20)
                to_name = symnm(i.to)
                item = frm_site+ref_type+to_site+to_name
                ret.append(item if filter.lower() in item.lower() else '')
        ret.extend(['='*80])
        return en(nem(ret))

# class ex(object):
    # pass

# # List of tuples (index, ordinal, ea, name)
# ex.inf = ['{}{}{}{}'.format('idx'.ljust(20), 'ord'.ljust(20), 'ea'.ljust(20), 'name'.ljust(20)), '='*80]\
        # + ['{}{}{}{}'.format(hex(i[0]).ljust(20), hex(i[1]).ljust(20), hex(i[2]).ljust(20), i[3].ljust(20)) for i in idautils.Entries()]\
        # + ['='*80]
# ex.ea = [va(i[2]) for i in idautils.Entries()]

# class im(object):
    # pass

# im.inf = ['{}{}{}{}'.format('mod'.ljust(20), 'iat'.ljust(20), 'ord'.ljust(20), 'name'.ljust(20)), '='*80]
# im.dl = []
# im.ea = []

# def set_im_info(ea, name, ord):
    # im.ea.append(ea)
    # im.inf.append('{}{}{}{}'.format(im.dl[-1].ljust(20), hex(ea).ljust(20), hex(ord).ljust(20), name.ljust(20)))
    # return True

# for i in range(idaapi.get_import_module_qty()):
    # im.dl.append(ida_nalt.get_import_module_name(i))
    # idaapi.enum_import_names(i, set_im_info)
    
# im.inf.append('='*80)

def smart_name(ea=-1):
    if ea==-1:
        ea = cea()
    ea = va_unpack(ea)
    ret_name = ''
    ret_ea = bad
    try:
        ret_name = fn(ea).nm
        ret_ea = hex(fn(ea).op).ljust(20)
    except:
        ret_name = symnm(ea)
        ret_ea = hex(ea).ljust(20)
    if dman(ret_name):
        return ret_ea+dman(ret_name)
    else:
        return ret_ea+ret_name

class va_list(object):
    def __init__(self, va_list):
        self.cur_va_ptr = 0
        self.va_list = list(map(va, va_list))
        
    @property
    def _print(self):
        ret = sio()
        print('='*80, file=ret)
        half_print_window_size = 10
        
        if self.cur_va_ptr-half_print_window_size<0:
            print_window_op = 0
        else:
            print_window_op = self.cur_va_ptr-half_print_window_size
            
        if self.cur_va_ptr+half_print_window_size>=len(self.va_list):
            print_window_ed = len(self.va_list)
        else:
            print_window_ed = self.cur_va_ptr+half_print_window_size
            
        tmp_va_list = self.va_list[print_window_op:print_window_ed]
        print_window_md = self.cur_va_ptr-print_window_op
        
        cnt = 0
        for i in tmp_va_list:
            try:
                print(('[*] ' if cnt==print_window_md else ' '*4)+hex(i).ljust(20)+hex(fn(i).op).ljust(20)+fn(i).nm, file=ret)
            except fn_err:
                print(('[*] ' if cnt==print_window_md else ' '*4)+hex(i).ljust(20)+' '*20+symnm(i), file=ret)
            cnt += 1
        print('='*80, file=ret)
        print('idx: {}'.format(hex(self.cur_va_ptr)).ljust(20)+
            'total: {}'.format(hex(len(self.va_list))), file=ret)
        print('='*80, file=ret)
        print(ret.getvalue())
        
    @property
    def e(self):
        if self.cur_va_ptr>=0 and self.cur_va_ptr<len(self.va_list):
            jmp(self.va_list[self.cur_va_ptr])
        clear_output_window()
        self._print
            
    @property
    def n(self):
        if self.cur_va_ptr+1<len(self.va_list):
            self.cur_va_ptr += 1
        self.e
            
    @property
    def p(self):
        if self.cur_va_ptr-1>-1:
            self.cur_va_ptr -= 1
        self.e
            
    @property
    def op(self):
        self.cur_va_ptr = 0
        self.e
        
    @property
    def ed(self):
        self.cur_va_ptr = len(self.va_list)-1
        self.e
        
    @property
    def r(self):
        self.va_list = self.va_list[::-1]
        self.cur_va_ptr = len(self.va_list)-1-self.cur_va_ptr
        self.e

key_ctx_list = [
    'ctx_shift_p',
    'ctx_shift_n',
    'ctx_shift_j',
    'ctx_shift_k',
    'ctx_shift_m',
    'ctx_shift_r',
    
    'ctx_shift_o',
    'ctx_shift_comma',
    'ctx_shift_dot',
    
    'ctx_shift_h',
    'ctx_shift_l',
    'ctx_shift_slash',
    'ctx_ctrl_slash'
]
for i in key_ctx_list:
    if i in locals():
        idaapi.del_hotkey(eval(i))
    exec('{}=None'.format(i))

ctx_shift_h = idaapi.add_hotkey('Shift+h', lambda :fn().op.jmp)
ctx_shift_l = idaapi.add_hotkey('Shift+l', lambda :fn().ed.jmp)
ctx_shift_slash = idaapi.add_hotkey('Shift+\\', lambda :clear_output_window())
ctx_ctrl_slash = idaapi.add_hotkey('Ctrl+\\', lambda :clear_output_window())

def set_act_va_list(data):
    global act_va_list
    global ctx_shift_p, ctx_shift_n
    global ctx_shift_j, ctx_shift_k
    global ctx_shift_m, ctx_shift_r
    
    act_va_list = va_list(data)
    idaapi.del_hotkey(ctx_shift_p)
    idaapi.del_hotkey(ctx_shift_n)
    idaapi.del_hotkey(ctx_shift_j)
    idaapi.del_hotkey(ctx_shift_k)
    idaapi.del_hotkey(ctx_shift_m)
    idaapi.del_hotkey(ctx_shift_r)
    
    ctx_shift_p = idaapi.add_hotkey('Shift+p', lambda :act_va_list.p)
    ctx_shift_n = idaapi.add_hotkey('Shift+n', lambda :act_va_list.n)
    ctx_shift_j = idaapi.add_hotkey('Shift+j', lambda :act_va_list.ed)
    ctx_shift_k = idaapi.add_hotkey('Shift+k', lambda :act_va_list.op)
    ctx_shift_m = idaapi.add_hotkey('Shift+m', lambda :act_va_list.e)
    ctx_shift_r = idaapi.add_hotkey('Shift+r', lambda :act_va_list.r)
    
    jmp()
    
def rva_to_va_with_adjust_call_site(data):
    ret = []
    for i in rva_to_va(data):
        try:
            fn(i)
            ret.append(it(i).p)
        except fn_err:
            ret.append(i)
    return ret
    
class bb_trace(object):
    def __init__(self, ea):
        self.start_ea = ea
        self.start_bb = bb(ea)
        
    def _op_handler(self, bb):
        if bb.op==self.start_bb.op:
            cur_it = it(self.start_ea).p.it
            while cur_it.ea>=self.start_bb.op:
                if self.find_handler(cur_it, *self.pattern):
                    self._resolve.append(cur_it)
                    return True
                cur_it = cur_it.p.it
            return False
        else:
            for i in bb.it[::-1]:
                if self.find_handler(i, *self.pattern):
                    self._resolve.append(i)
                    return True
            return False
        
    def dfs(self, op_handler=lambda bb:False, ed_handler=None):
        bb_set = set()
        def _dfs(bb):
            bb_set.add(bb.op)
            if op_handler(bb):
                if ed_handler:
                    ed_handler(bb)
                return
            for i in bb.p:
                if i.op not in bb_set:
                    _dfs(i)
            if ed_handler:
                ed_handler(bb)
        _dfs(self.start_bb)
        return bb_set
        
    def backward(self, find_handler, *pattern):
        self.find_handler = find_handler
        self.pattern = pattern
        self._resolve = []
        self._bb_set = self.dfs(self._op_handler)
        return self._resolve
        
    def forward(self, find_handler, *pattern):
        return
        
def wt_reg(it, reg_name, volatile=False):
    if volatile and it.op=='call':
        return True
        
    wt_reg_op_set = set(['mov', 'lea', 'add', 'sub', 'adc', 'sbb', 'pop', 'and', 'or', 'xor'])
    if it.opl>0 and it.opt[0]=='reg' and rid(reg_name)==it.opv[0]:
        for i in wt_reg_op_set:
            if i in it.op:
                return True
    return False
    
def wt_displ(it, displ):
    wt_displ_op_set = set(['mov', 'lea', 'add', 'sub', 'adc', 'sbb', 'pop', 'and', 'or', 'xor'])
    if it.opl<=0:
        return False
        
    if (displ==0 and it.opt[0]=='phrase') or (it.opt[0]=='displ' and it.opv[0]==displ):
        for i in wt_displ_op_set:
            if i in it.op:
                return True
    return False
    
def set_act_bb_trace(find_handler, *pattern):
    global act_bb_trace, act_bb_trace_found_list
    global ctx_shift_o, ctx_shift_comma, ctx_shift_dot
    
    idaapi.del_hotkey(ctx_shift_o)
    idaapi.del_hotkey(ctx_shift_comma)
    idaapi.del_hotkey(ctx_shift_dot)
    
    act_bb_trace = bb_trace(cea())
    ret = act_bb_trace.backward(find_handler, *pattern)
    act_bb_trace_found_list = va_list([i.ea for i in ret])
    
    ctx_shift_o = idaapi.add_hotkey('Shift+o', lambda :jmp(act_bb_trace.start_ea))
    ctx_shift_comma = idaapi.add_hotkey('Shift+,', lambda :act_bb_trace_found_list.p)
    ctx_shift_dot = idaapi.add_hotkey('Shift+.', lambda :act_bb_trace_found_list.n)
    
    jmp()
    return ret
# --------------------------------------------------------------------------------

import sys

def log(log_file_name='x:\\log.txt'):
    return open(log_file_name, 'w')

sidx = idc.selector_by_name

isind = ida_idp.is_indirect_jump_insn

import sys

def fd(ea, file=sys.stdout, depth=5):
    call_chain = []
    ea = fn(ea).op
    
    def f(ea, depth):
        if depth<=0:
            print('-'*80, file=file)
            for i in call_chain:
                print(hex(i[0]), i[1], file=file)
            return
        fninsts = fn(ea).itx
        leaf_node = True
        if fninsts:
            for fninst in fninsts:
                if cro(fninst):
                    leaf_node = False
                    ea_child = fcf(fninst)
                    call_chain.append((fninst, symnm(ea_child)))
                    f(ea_child, depth-1)
                    call_chain.pop()
            if leaf_node:
                print('-'*80, file=file)
                for i in call_chain:
                    print(hex(i[0]), i[1], file=file)
        else:
            print('-'*80, file=file)
            for i in call_chain:
                print(hex(i[0]), i[1], file=file)
    f(ea, depth)
    print('-'*80, file=file)
    
# def fncf(ea, file=sys.stdout):
    # ret = []
    # for i in fn(ea).it:
        # ref = cf(i)
        # if not ref:
            # continue
        # else:
            # if ref[0]>=fnop(ea) and ref[0]<=fned(ea):
                # continue
            # else:
                # ret.append((i, ref[0]))
                
    # if file:
        # for i in ret:
            # print>>file, hex(i[0]), symnm(i[1])
    # else:
        # return ret
        
# def pe_main(x):
    # func_start = fn(x).op
    # data = fncf(func_start, 0)
    # data = list(filter(lambda i:i[1]%16==0 and sop(func_start)==sop(i[1]), data))
    # data = sorted(data, key=lambda x:x[1], reverse=True)
    # for i in data:
        # print hex(i[0]), symnm(i[1])