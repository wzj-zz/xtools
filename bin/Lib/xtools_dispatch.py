import re
from re import match
from re import search
from re import split

from shutil import which

p = print
en = lambda lst:'\n'.join(list(map(str, lst)))
nem = lambda target: list(filter(lambda x:x, target))

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
            
def wt(file_path='@@@bin@@@', mode='wb', encoding='utf-8'):
    def wt_(data):
        if 'b' in mode:
            with open(file_path, mode) as f:
                f.write(data)
        else:
            with open(file_path, mode, encoding=encoding) as f:
                f.write(data.replace('\r', ''))
    return wt_
            
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

def str_to_block(pattern, data, sep='-'):
    return en([sep*80+'\n'+line if search(pattern, line, re.I) else line for line in data.replace('\r', '').split('\n')])
    
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
    
def wsl(wsl_name):
    wsl_map = {
        'ub1':'ubuntu_1',
        'ub2':'ubuntu_2',
        'ka':'kali-linux'
    }
    if wsl_name in wsl_map:
        wsl_name = wsl_map[wsl_name]
    pp('wsl.exe', '--set-default', wsl_name)()
    
def parse_spec_blks(data):
    blks = str_to_block(r'\s*#@wsl\.[\w-]+\s*|\s*#@win\s*', data, '$')
    blks = nem([blk.strip() for blk in split(r'\${80,}', blks)])
    spec_blks = []
    
    for blk in blks:
        spec = blk.split('\n')[0].strip()
        spec_match = match(r'\s*#@wsl\.[\w-]+\s*|\s*#@win\s*', spec)
        if spec_match:
            spec = spec_match.group().strip('#@').split('.')
        else:
            spec = None
        spec_blks.append({'spec':spec, 'src':blk})
    return spec_blks
    
def dispatch_spec_blks(spec_blks):
    for spec_blk in spec_blks:
        spec = spec_blk['spec']
        if not spec:
            set_clip(spec_blk['src'])
            pp('p.bat', r'D:\tools\bin\Lib\xtools_exec.py', '-c')(stdin=None, stdout=None, stderr=None)
        else:
            if spec[0]=='win':
                set_clip(spec_blk['src'])
                pp('p.bat', r'D:\tools\bin\Lib\xtools_exec.py', '-c')(stdin=None, stdout=None, stderr=None)
            if spec[0]=='wsl':
                wsl(spec[1])
                set_clip(spec_blk['src'])
                pp('wsl.exe', 'xt', '-c')(stdin=None, stdout=None, stderr=None)

if __name__=='__main__':
    data = get_clip().replace('\r', '')
    spec_blks = parse_spec_blks(data)
    dispatch_spec_blks(spec_blks)
