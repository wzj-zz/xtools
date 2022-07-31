import frida
import inspect
import os
import sys

dirname = os.path.dirname
pin = os.path.join
rmfile = os.remove

class fa(object):
    def __init__(self, pid):
        self.pid = pid
        self.session = frida.attach(self.pid)
    
    def _base_js_path():
        return pin(dirname(__file__), 'frida.js')
        
    def _base_js_content():
        return open(fa._base_js_path(), 'r').read()+'\n'
        
    def cli(cmd, frida_js_name, frida_js_content):
        frida_cli_path = pin(dirname(sys.executable), 'Scripts', 'frida.exe')
        frida_js_path = pin(dirname(__file__), frida_js_name)
        frida_js_content = 'function main() {{{}\n}}\n'.format(frida_js_content)
        open(frida_js_path, 'w').write(frida_js_content+fa._base_js_content())
        os.system(frida_cli_path+' -l "{}" {}'.format(frida_js_path, cmd))
        rmfile(frida_js_path)
        
    def on(self, frida_js_content):
        frida_base_js_content = fa._base_js_content()
        
        frida_js_content = 'function main() {{{}\n}}\n'.format(frida_js_content)
        
        self.script = self.session.create_script(frida_js_content+frida_base_js_content+'main()')
        def set_on_recv(on_recv):
            def real_on_recv(msg, data):
                args_sig = inspect.getfullargspec(on_recv)[0]
                args = {}
                if 'obj' in args_sig:
                    args['obj'] = self
                if 'msg' in args_sig:
                    if(msg['type']=='send'):
                        class new_msg:
                            def __init__(self, tp, msg_data=None):
                                self.type = tp
                                self.data = msg_data
                                self.bytes = data
                            def p(self):
                                print('-'*80)
                                print('type:', self.type)
                                print('data:', self.data)
                                print('bytes:', self.bytes)
                                print('-'*80)
                        if 'payload' in msg.keys():
                            args['msg'] = new_msg(msg['type'], msg['payload'])
                        else:
                            args['msg'] = new_msg(msg['type'])
                    elif(msg['type']=='error'):
                        class new_msgx:
                            def __init__(self, tp, description, lineNumber):
                                self.type = tp
                                self.err = description
                                self.line = lineNumber
                            def p(self):
                                print('-'*80)
                                print('type:', self.type)
                                print('line: {} {}'.format(self.line, self.err))
                                print('-'*80)
                        args['msg'] = new_msgx(msg['type'], msg['description'], msg['lineNumber'])
                    
                on_recv(**args)
            self.script.on('message', real_on_recv)
            self.script.load()
            return self
        return set_on_recv
        
    def sd(self, data=b'', msg='input'):
        if type(data)==bytes:
            self.script.post({'type':msg, 'data':data.hex()})
        else:
            raise ValueError('data should be bytes')
        return self