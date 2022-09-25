;----------------------------------------------------------------------
Hotstring("EndChars", ";")
#Hotstring O
#WinActivateForce

EnvGet, SCOOP_ROOT, SCOOP

browser_path := "www.google.com"

python := A_ScriptDir "\..\..\utils\python3.7.4\python.exe"
pythonw := A_ScriptDir "\..\..\utils\python3.7.4\pythonw.exe"

python32 := A_ScriptDir "\..\..\utils\python3.7.4_x86\python.exe"
pythonw32 := A_ScriptDir "\..\..\utils\python3.7.4_x86\pythonw.exe"

java8 := SCOOP_ROOT "\apps\openjdk8-redhat\current\bin\java.exe"
java8w := SCOOP_ROOT "\apps\openjdk8-redhat\current\bin\javaw.exe"

java11 := SCOOP_ROOT "\apps\liberica11-full-jdk\current\bin\java.exe"
java11w := SCOOP_ROOT "\apps\liberica11-full-jdk\current\bin\javaw.exe"

java17 := SCOOP_ROOT "\apps\liberica17-full-jdk\current\bin\java.exe"
java17w := SCOOP_ROOT "\apps\liberica17-full-jdk\current\bin\javaw.exe"

java8_path := SCOOP_ROOT "\apps\openjdk8-redhat\current\bin"
java11_path := SCOOP_ROOT "\apps\liberica11-full-jdk\current\bin"
java17_path := SCOOP_ROOT "\apps\liberica17-full-jdk\current\bin"
;----------------------------------------------------------------------
;group-窗口组

GroupAdd, browser, ahk_exe msedge.exe
GroupAdd, browser, ahk_exe chrome.exe
GroupAdd, browser, ahk_exe firefox.exe

GroupAdd, ida, ahk_exe ida.exe
GroupAdd, ida, ahk_exe ida64.exe

GroupAdd, debugger, ahk_exe x32dbg.exe
GroupAdd, debugger, ahk_exe x64dbg.exe
GroupAdd, debugger, ahk_exe DbgX.Shell.exe
GroupAdd, debugger, ahk_exe windbg.exe
GroupAdd, debugger, ahk_exe kd.exe

GroupAdd, windbg, ahk_exe windbg.exe
GroupAdd, windbg, ahk_exe DbgX.Shell.exe
GroupAdd, windbg, ahk_exe kd.exe

GroupAdd, terminal_emulator, ahk_exe WindowsTerminal.exe
GroupAdd, terminal_emulator, ahk_exe mintty.exe

GroupAdd, terminal, ahk_exe cmd.exe
GroupAdd, terminal, ahk_exe wsl.exe
GroupAdd, terminal, ahk_exe mintty.exe
GroupAdd, terminal, ahk_exe WindowsTerminal.exe

GroupAdd, win_shell, ahk_exe cmd.exe
GroupAdd, win_shell, ahk_exe powershell.exe

GroupAdd, wsl_shell, ahk_exe mintty.exe
GroupAdd, wsl_shell, ahk_exe wsl.exe
GroupAdd, wsl_shell, ahk_exe cmd.exe
GroupAdd, wsl_shell, ahk_exe WindowsTerminal.exe

GroupAdd, lix_shell, ahk_group wsl_shell

GroupAdd, common_shell, ahk_group win_shell
GroupAdd, common_shell, ahk_group wsl_shell

GroupAdd, wsl, ahk_exe mintty.exe
GroupAdd, wsl, ahk_exe wsl.exe
GroupAdd, wsl, ahk_exe WindowsTerminal.exe

GroupAdd, auto, block_filter
GroupAdd, auto, neg_block_filter
GroupAdd, auto, line_filter
GroupAdd, auto, neg_line_filter

GroupAdd, cfg_editor, ahk_exe notepad++.exe
GroupAdd, cfg_editor, ahk_exe notepad.exe
GroupAdd, cfg_editor, ahk_exe notepad2.exe

GroupAdd, virtual_machine, ahk_exe vmware.exe
GroupAdd, virtual_machine, ahk_exe VirtualBox.exe
GroupAdd, virtual_machine, ahk_exe vmconnect.exe
GroupAdd, virtual_machine, ahk_exe mstsc.exe

GroupAdd, ahk_window, ahk_exe auto.exe
GroupAdd, ahk_window, ahk_exe KeyPatch64.exe
;----------------------------------------------------------------------
;ahk- ahk function

quotes := Chr(34)

py_exec_dispatch() {
	global python
	Run, cmd /k %python% %A_ScriptDir%\xtools_exec.py -c -d
}

pyw_eval() {
    global pythonw
    RunWait, %pythonw% %A_ScriptDir%\xtools_exec.py -c -e clip
}

pyw_eval_32() {
    global pythonw32
    RunWait, %pythonw32% %A_ScriptDir%\xtools_exec.py -c -e clip
}

pyw_exec() {
    global pythonw
    Run, %pythonw% %A_ScriptDir%\xtools_exec.py -c
}

pyw_exec_32() {
    global pythonw32
    Run, %pythonw32% %A_ScriptDir%\xtools_exec.py -c
}

pyw_exec_wait() {
    global pythonw
    RunWait, %pythonw% %A_ScriptDir%\xtools_exec.py -c
}

pyw_exec_wait_32() {
    global pythonw32
    RunWait, %pythonw32% %A_ScriptDir%\xtools_exec.py -c
}

py_exec_cmd() {
    global python
    Run, cmd /k %python% %A_ScriptDir%\xtools_exec.py -c
}

py_exec_cmd_32() {
    global python32
    Run, cmd /k %python32% %A_ScriptDir%\xtools_exec.py -c
}

line_filter() {
    global pythonw
    RunWait, %pythonw% %A_ScriptDir%\xtools_exec.py -f line
}

neg_line_filter() {
    global pythonw
    RunWait, %pythonw% %A_ScriptDir%\xtools_exec.py -f neg_line
}

block_filter() {
    global pythonw
    RunWait, %pythonw% %A_ScriptDir%\xtools_exec.py -f block
}

neg_block_filter() {
    global pythonw
    RunWait, %pythonw% %A_ScriptDir%\xtools_exec.py -f neg_block
}

clip_msg_box() {
    MsgBox, %clipboard%
}

append_text(path, data) {
    FileEncoding, UTF-8-RAW
    FileAppend, %data% , %path%
}

write_text(path, data) {
    FileDelete, %path%
    append_text(path, data)
}

read_text(path) {
    FileEncoding, UTF-8-RAW
    FileRead, data, %path%
    return data
}

isdir(path) {
    return InStr(FileExist(path), "D")
}

isfile(path) {
    return not isdir(path)
}

basename(path) {
    SplitPath, path, name
    return name
}

dirname(path) {
    SplitPath, path, , dir
    return dir
}

abspath(path) {
    cc := DllCall("GetFullPathName", "str", path, "uint", 0, "ptr", 0, "ptr", 0, "uint")
    VarSetCapacity(buf, cc*(A_IsUnicode?2:1))
    DllCall("GetFullPathName", "str", path, "uint", cc, "str", buf, "ptr", 0, "uint")
    return buf
}

remove(path) {
    if(isdir(path)) {
        FileRemoveDir, %path%, 1
    } else if(isfile(path)) {
        FileDelete, %path%
    }
}

clip_etxt() {
    write_text("@@@tmp_utf_8_txt@@@", clipboard)
    clipboard := "etxt(rd('@@@tmp_utf_8_txt@@@').decode())"
    pyw_eval()
    remove("@@@tmp_utf_8_txt@@@")
}

clip_dtxt() {
    clipboard := "dtxt(" clipboard ")"
    pyw_eval()
}

clip_check_op() {
	global tmp_clip := clipboard
	if(InStr(clipboard, "`n")) {
		clipboard := ""
	}
}

clip_check_ed() {
	global tmp_clip
	clipboard := tmp_clip
}
;----------------------------------------------------------------------
;script-脚本触发器，常用脚本补全热字串

#[::
pyw_eval()
clip_msg_box()
return

#+[::
pyw_eval_32()
clip_msg_box()
return

#]::
remove("@@@nasm_bin@@@")
core_asm_path := A_ScriptDir "\..\..\bin\Lib\core\core_asm\core.asm"
write_text("tmp_nasm_", "%include """ core_asm_path """`n")
append_text("tmp_nasm_", clipboard)
clipboard := "
(
pp('nasm', '-f', 'bin', 'tmp_nasm_', '-o', '@@@nasm_bin@@@')()
set_clip(rd('@@@nasm_bin@@@').hex())
)"
pyw_exec_wait()
remove("@@@nasm_bin@@@")
remove("tmp_nasm_")
clip_msg_box()
return

#o::
Gui +LastFound +OwnDialogs +AlwaysOnTop
InputBox, nothing, @Auto_Activate@, , , 300, 100
return

#=::
Gui +LastFound +OwnDialogs +AlwaysOnTop
InputBox, pattern, line_filter, , , 300, 100
write_text("@@@line_filter_pattern@@@", pattern)
line_filter()
remove("@@@line_filter_pattern@@@")
return

#+=::
Gui +LastFound +OwnDialogs +AlwaysOnTop
InputBox, pattern, neg_line_filter, , , 300, 100
write_text("@@@neg_line_filter_pattern@@@", pattern)
neg_line_filter()
remove("@@@neg_line_filter_pattern@@@")
return

#-::
Gui +LastFound +OwnDialogs +AlwaysOnTop
InputBox, pattern, block_filter, , , 300, 100
write_text("@@@block_filter_pattern@@@", pattern)
block_filter()
remove("@@@block_filter_pattern@@@")
return

#+-::
Gui +LastFound +OwnDialogs +AlwaysOnTop
InputBox, pattern, neg_block_filter, , , 300, 100
write_text("@@@neg_block_filter_pattern@@@", pattern)
neg_block_filter()
remove("@@@neg_block_filter_pattern@@@")
return

#+7::
clipboard := "shell()"
py_exec_cmd_32()
return

#7::
clipboard := "shell()"
py_exec_cmd()
return

<^RCtrl::
clipboard := "
(
def dec2hex(data):
    ret = hex(int(data.group())).lstrip('0x')
    ret = len(ret)%2*'0'+ret
    return ret
data = r'''" clipboard " '''
data = re.sub(r'\d+', dec2hex, data)
set_clip(data)
)"
pyw_exec_wait()
return

>^LCtrl::
return

<^Space::
if InStr(clipboard, "#@w") {
	py_exec_dispatch()
}
else {
	py_exec_cmd()
}
return

<^+Space::
py_exec_cmd_32()
return

CapsLock::
WinClose, @Auto_Activate@
clipboard := "
(
paths = r'''" clipboard " '''

try:
    set_clip(en(wcx(paths)))
except:
    set_clip('Error File List!')
)"
pyw_exec_wait()
Loop, parse, clipboard, `n, `r
{
	Run, %A_LoopField%
}
return

>!LAlt::
return

#IfWinActive @Auto_Activate@
::hb::
WinClose, @Auto_Activate@
clipboard := "fromhex(r'''" clipboard "'''.strip())"
pyw_eval()
return

::bh::
WinClose, @Auto_Activate@
clipboard := clipboard ".hex()"
pyw_eval()
return

::hl::
WinClose, @Auto_Activate@
clipboard := "list(fromhex(r'''" clipboard "'''.strip()))"
pyw_eval()
return

::lh::
WinClose, @Auto_Activate@
clipboard := "bytes(" clipboard ").hex()"
pyw_eval()
return

::l::
::bl::
WinClose, @Auto_Activate@
clipboard := "list(" clipboard ")"
pyw_eval()
return

::b::
::lb::
WinClose, @Auto_Activate@
clipboard := "bytes(" clipboard ")"
pyw_eval()
return

::sl::
::lsl::
::bsl::
WinClose, @Auto_Activate@
clipboard := "[c_int8(i).value for i in list(" clipboard ")]"
pyw_eval()
return

::sll::
WinClose, @Auto_Activate@
clipboard := "list(map(lambda x:x%256, " clipboard "))"
pyw_eval()
return

::slb::
WinClose, @Auto_Activate@
clipboard := "bytes(map(lambda x:x%256, " clipboard "))"
pyw_eval()
return

::slh::
WinClose, @Auto_Activate@
clipboard := "bytes(map(lambda x:x%256, " clipboard ")).hex()"
pyw_eval()
return

::hsl::
WinClose, @Auto_Activate@
clipboard := "[c_int8(i).value for i in list(fromhex('" clipboard "'.strip()))]"
pyw_eval()
return

::r::
WinClose, @Auto_Activate@
clipboard := clipboard "[::-1]"
pyw_eval()
return

::len::
WinClose, @Auto_Activate@
clipboard := "hex(len(" clipboard "))"
pyw_eval()
clip_msg_box()
return

::md5::
WinClose, @Auto_Activate@
clipboard := "md5(" clipboard ")"
pyw_eval()
return

::sha1::
WinClose, @Auto_Activate@
clipboard := "sha1(" clipboard ")"
pyw_eval()
return

::sha256::
WinClose, @Auto_Activate@
clipboard := "sha256(" clipboard ")"
pyw_eval()
return

::ba::
WinClose, @Auto_Activate@
clipboard := clipboard ".decode('ansi')"
pyw_eval()
return

::bu::
WinClose, @Auto_Activate@
clipboard := clipboard ".decode('utf-8')"
pyw_eval()
return

::bux::
WinClose, @Auto_Activate@
clipboard := clipboard ".decode('utf-16')"
pyw_eval()
return

::ab::
WinClose, @Auto_Activate@
write_text("@@@tmp_string@@@", clipboard)
clipboard := "
(
data = rd('@@@tmp_string@@@', 'r').encode('ansi')
set_clip(data)
)"
pyw_exec_wait()
remove("@@@tmp_string@@@")
return

::ub::
WinClose, @Auto_Activate@
write_text("@@@tmp_string@@@", clipboard)
clipboard := "
(
data = rd('@@@tmp_string@@@', 'r').encode('utf-8')
set_clip(data)
)"
pyw_exec_wait()
remove("@@@tmp_string@@@")
return

::uxb::
WinClose, @Auto_Activate@
write_text("@@@tmp_string@@@", clipboard)
clipboard := "
(
data = rd('@@@tmp_string@@@', 'r').encode('utf-16')
set_clip(data)
)"
pyw_exec_wait()
remove("@@@tmp_string@@@")
return

::md5x::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
mods = list(filter(isfile, fl(data)))
if len(mods)==1:
    try:
        set_clip(md5(mods[0]))
    except:
        pass
elif len(mods)>1:
    ret = sio()
    for i in mods:
        print(i, '>', md5(i), file=ret)
    set_clip(ret.getvalue())
else:
    set_clip('')
)"
pyw_exec_wait()
return

::sha1x::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
mods = list(filter(isfile, fl(data)))
if len(mods)==1:
    try:
        set_clip(sha1(mods[0]))
    except:
        pass
elif len(mods)>1:
    ret = sio()
    for i in mods:
        print(i, '>', sha1(i), file=ret)
    set_clip(ret.getvalue())
else:
    set_clip('')
)"
pyw_exec_wait()
return

::sha256x::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
mods = list(filter(isfile, fl(data)))
if len(mods)==1:
    try:
        set_clip(sha256(mods[0]))
    except:
        pass
elif len(mods)>1:
    ret = sio()
    for i in mods:
        print(i, '>', sha256(i), file=ret)
    set_clip(ret.getvalue())
else:
    set_clip('')
)"
pyw_exec_wait()
return

::e64::
WinClose, @Auto_Activate@
clipboard := "e64(" clipboard ")"
pyw_eval()
return

::e64x::
WinClose, @Auto_Activate@
write_text("@@@tmp_string@@@", clipboard)
clipboard := "
(
data = rd('@@@tmp_string@@@', 'r').encode('utf-8')
data = e64(data).decode()
set_clip(data)
)"
pyw_exec_wait()
remove("@@@tmp_string@@@")
return

::d64::
WinClose, @Auto_Activate@
clipboard := "d64(" clipboard ")"
pyw_eval()
return

::ezi::
WinClose, @Auto_Activate@
clipboard := "ezip(" clipboard ")"
pyw_eval()
return

::dzi::
WinClose, @Auto_Activate@
clipboard := "dzip(" clipboard ")"
pyw_eval()
return

::et::
WinClose, @Auto_Activate@
clip_etxt()
return

::dt::
WinClose, @Auto_Activate@
clip_dtxt()
return

::rdb::
WinClose, @Auto_Activate@
clipboard := "rd(fl(r'''" clipboard "''')[0])"
pyw_eval()
return

::rd::
WinClose, @Auto_Activate@
clipboard := "reduce(lambda x, y:x+y, [rd(i, 'r') for i in fl(r'''" clipboard "''')])"
pyw_eval()
return

::wb::
::wtb::
WinClose, @Auto_Activate@
clipboard := "wt('@@@bin@@@')(" clipboard ")"
pyw_eval()
return

::wt::
WinClose, @Auto_Activate@
write_text("@@@txt@@@", clipboard)
return

::lg::
WinClose, @Auto_Activate@
write_text("@@@log_txt@@@", clipboard)
clipboard =
(
if not exist('@@@log@@@'):
    mkdir('@@@log@@@')
data = fl(rd('@@@log_txt@@@', 'r'))
for i in data:
	cp(i, '@@@log@@@')
)
pyw_exec_wait()
return

::lgc::
WinClose, @Auto_Activate@
clipboard =
(
rm(r'@@@log@@@')
)
pyw_exec_wait()
return

::lgx::
WinClose, @Auto_Activate@
RunWait, %A_ScriptDir%\..\..\utils\TotalCMD64\Totalcmd64.exe /O /T "%A_WorkingDir%\@@@log@@@"
return

::un::
WinClose, @Auto_Activate@
write_text("@@@uniq_txt@@@", clipboard)
clipboard := "en(sorted(set(filter(lambda x:x, map(lambda x:x.strip(), rd('@@@uniq_txt@@@', 'r').split('\n')))), key=str.lower))"
pyw_eval()
remove("@@@uniq_txt@@@")
return

::bnx::
WinClose, @Auto_Activate@
write_text("@@@bnx_txt@@@", clipboard)
clipboard := "en(set(map(basename, fl(rd('@@@bnx_txt@@@', 'r')))))"
pyw_eval()
remove("@@@bnx_txt@@@")
return

::dnx::
WinClose, @Auto_Activate@
write_text("@@@dnx_txt@@@", clipboard)
clipboard := "en(set(map(dirname, fl(rd('@@@dnx_txt@@@', 'r')))))"
pyw_eval()
remove("@@@dnx_txt@@@")
return

::rb::
WinClose, @Auto_Activate@
clipboard := "rd('@@@bin@@@')"
pyw_eval()
return

::rr::
WinClose, @Auto_Activate@
clipboard := "rd('@@@txt@@@', 'r')"
pyw_eval()
return

::fm::
WinClose, @Auto_Activate@
clipboard := "fm(r'''" clipboard "'''.strip())"
pyw_eval()
return

::lr::
WinClose, @Auto_Activate@
clipboard := RegExReplace(clipboard, "m)(*BSR_ANYCRLF)^[[:blank:]]+\R+", "`n")
clipboard := RegExReplace(clipboard, "(*BSR_ANYCRLF)\R+", "`n")
return

::ls::
WinClose, @Auto_Activate@
clipboard := RegExReplace(clipboard, "m)(*ANYCRLF)^[[:blank:]]*(.*?)[[:blank:]]*$", "$1")
return

::lsr::
WinClose, @Auto_Activate@
clipboard := RegExReplace(clipboard, "m)(*BSR_ANYCRLF)^[[:blank:]]+\R+", "`n")
clipboard := RegExReplace(clipboard, "(*BSR_ANYCRLF)\R+", "`n")
clipboard := RegExReplace(clipboard, "m)(*ANYCRLF)^[[:blank:]]*(.*?)[[:blank:]]*$", "$1")
return

::rn::
WinClose, @Auto_Activate@
clipboard := StrReplace(clipboard, "`r")
return

::2b::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard "'''.split('\n')
set_clip(lr(str_to_block(data[0].strip(), en(data[1:]))))
)"
pyw_exec_wait()
return

::uuid::
WinClose, @Auto_Activate@
clipboard := "uuid().hex"
pyw_eval()
return

::xt.add::
WinClose, @Auto_Activate@
clip_etxt()
clipboard := "xt().add(dtxt(" clipboard ").strip())"
pyw_eval()
return

::xt.rm::
WinClose, @Auto_Activate@
clip_etxt()
clipboard := "xt().rm(dtxt(" clipboard ").strip().lstrip('id:').strip())"
pyw_eval()
return

::xt.set::
WinClose, @Auto_Activate@
clip_etxt()
clipboard := "
(
data = lsr(dtxt(" clipboard ")).lstrip('id:').strip().split('\n')
if len(data)!=2:
	exit()
code_id = data[0]
code_src = dtxt(eval(data[1])).strip()
if not (len(code_id)==32 and match(r'[0-9a-fA-F]{32}', code_id)):
	exit()
xt().set(code_id, code_src)
set_clip(code_id)
)"
pyw_exec()
return

::xt.get::
WinClose, @Auto_Activate@
clip_etxt()
clipboard := "xt().get(dtxt(" clipboard ").strip())"
pyw_eval()
return

::xt.getx::
WinClose, @Auto_Activate@
clip_etxt()
clipboard := "xt().get()"
pyw_eval()
return

::xt.call::
WinClose, @Auto_Activate@
clipboard := RegExReplace(clipboard, "m)(*ANYCRLF)^[[:blank:]]*(.*?)[[:blank:]]*$", "$1")
clipboard := "'''#@wsl.ub2\nargs_map = {}\nxt().call('" clipboard "')'''"
pyw_eval()
return

::xt.ug::
WinClose, @Auto_Activate@
clipboard := "
(
xtools_upgrade_src = ''
xtools_upgrade_src += dtxt(b'H4sIAMJL5mIC/3NITc7IV8hPS+PlSk7MyVFILFXIzoSys1MrgRwAuqDZuSIAAAA=')+'\n'
xtools_upgrade_src += 'cd /d d:/tools\n'
xtools_upgrade_src += 'git config --global core.autocrlf false\n'
xtools_upgrade_src += 'git stash push\n'
xtools_upgrade_src += 'git pull --rebase https://github.com/wzj-zz/xtools.git master\n'
xtools_upgrade_src += 'git stash pop\n'
xtools_upgrade_src += dtxt(b'H4sIAGZ27GIC/0tOzMlRSCxVyEst5+VKBnGyUyuReImlCGFeLofU5Ix8hfw8AA31zbg2AAAA')
rm('xtools_upgrade.bat')
wt('xtools_upgrade.bat', 'w')(xtools_upgrade_src)
)"
pyw_exec_wait()
Run, cmd /k xtools_upgrade.bat
return

::ec::
WinClose, @Auto_Activate@
clip_etxt()
clipboard := "exec(dtxt(" clipboard "))"
return

::esx::
WinClose, @Auto_Activate@
clip_etxt()
clipboard := "e64(dtxt(" clipboard ").encode()).decode()"
pyw_eval()
clipboard := "echo " clipboard " | base64 -d | sed 's/\r//g' | sh"
return

::es::
WinClose, @Auto_Activate@
clip_etxt()
clipboard := "e64(dtxt(" clipboard ").encode()).decode()"
pyw_eval()
clipboard := "echo " clipboard " | base64 -d | sed 's/\r//g' | sh"
clip_etxt()
clipboard := "data = dtxt(" clipboard ").replace('\r', '')"
return

::xt.tm::
::tm.xt::
WinClose, @Auto_Activate@
clip_etxt()
src_code := clipboard
clipboard := "
(
xtools_exec_src = ''
xtools_exec_src += dtxt(b'H4sIAFEJ5GIC/0tJTVNIqcos0EhJLEnUtOLlUgCCzNyC/KIShXSgOESgKLWktCgPLKCXkpqcn1tQlFpcDNEDUcHLlQIyycwELKijUFqUE1+cmJZq65aYU5yKZnBSYnGqmQlUKA2uFqoIyUKIQj2gApB8fJKZCcj2lFRkm1OB5uPUiaYDAN6hFb/uAAAA') + '\n\n'
xtools_exec_src += 'exec(dzip(d64(' + str(etxt(neg_block_filter('main-', rd(sys.argv[0], 'r')).replace('-'*80, ''))) + ')).decode())' + '\n\n'
xtools_exec_src += r'''exec(dtxt(" src_code "))'''
set_clip(xtools_exec_src)
)"
pyw_exec_wait()
return

::tm.ws1::
WinClose, @Auto_Activate@
clipboard := "dtxt(b'H4sIAFYMLGMC/wtwDPGwVQkAklb6Rfn5Jfp6Ppl5pRUh+fk5xfpJmXm8XAEEVFTwcvFypVYU5BeVKLh4Bgf4OEbaGhqZ6xkAoaEVkATJ+zjHO4dEBrjapubFhwbrhYa46VqARR19fJDFALy/rWaPAAAA').replace('\r', '')"
pyw_eval()
return

::tm.ws2::
WinClose, @Auto_Activate@
clipboard := "dtxt(b'H4sIADYMLGMC/wtwDPGwVQkAklb6Rfn5Jfp6Ppl5pRUh+fk5xfpJmXm8XAEEVFTwcvFypVYU5BeVKLh4Bgf4OEbaqmikF6UWKOjmKhgq5CXmphanFpWlFinop5Yk6xelFufnlOkl5+elKdQoJJZnK6hXFxRl5pUoqBjVqmtaGegZgEz0cY53DokMcLVNzYsPDdYLDXHTtQCLOvr4IIsBAKZxVj3BAAAA').replace('\r', '')"
pyw_eval()
return

::tm.arg::
WinClose, @Auto_Activate@
clipboard := "
(
data = dtxt(b'H4sIAHBCCGMC/0ssSi9WsFWoKEkEMjQ0ebkSIQIgSi8xJSU+t7QktSI+LScxXUM9O7VSXUdBPSM1pwBIpxfllxbYqkO0AvkpqWmJpTkltn75eak4DSpLzEE3Rz03tSSxLLGIdCOxuYqAFvz249EM1AgA48y3GywBAAA=')
set_clip(data)
)"
pyw_exec_wait()
return

::tm.jut::
WinClose, @Auto_Activate@
clipboard := "rd(r'D:\tools\bin\Lib\file_templete\java_util_template.jut', 'r')"
pyw_eval()
return

::tm.dll::
WinClose, @Auto_Activate@
clipboard := "
(
data = dtxt(b'H4sIAEkx5mIC/5VRXW+CMBR9J+E/3GQvmjh9n8sSJiySMCHA5qOp5TKa1ZZQGHGL/30t6EymZq4vbW/v+ei5N0xQ3mQI90smMtmqcfFgW7b1GIYBLP2FE/ngcv5MmBjYFug19xdJ6ixmHhRMqNoNghHAZAIFERlHqCXoEmxk1nDsEe4yjF3IszZGoqQYmZpBVN0VclkBJZwz8QZ5I2jNpOiBQfQa+i7wMkaF1QdmMNwD+6ttffWNuhZhpYk2QDq8gjVRul/T1wWeURr3QNWymhaDozkY9g97YrOoZjJ/WkVxOPOSZOWkqTOb3x079hZ8wWpGOPtErUuxk0NCCxDYQllJikqNT1Ax1k0l4MkJEs+klxPGuwi5JNmv9rX+yPvUzOfEXDqPPce96M2VOgiNzm5ViZTljAI72CUmsX8rud7VSpQjEU15vcQh6UsaP8MWWx2uyZVU2z9kzHnXb1UfeRq/eNOOL2moIckbfmbQmm/3Da33zB8nAwAA')
set_clip(data)
)"
pyw_exec_wait()
return

::tm.ddk::
WinClose, @Auto_Activate@
clipboard := "
(
data = dtxt(b'H4sIAHoz5mIC/8VXbW/bNhD+bAP+D1yKBTLqBOn2rW7TqRKdsJUpTS9Zt6YgFJtO1MiUJ9HJgiL77TvqrZJtJcG6ofkQSeTxXh7ec3d+FolZvJ5z9ErIaJEdXh0P+s/qtdv5MuOzfBGW53wRCY6IbfiWNlmLmYwSMUTwxQzbxNqEWJiZ+IwYmAX0PbV/oyNUyY3QFPuntsneBpMJdrEJW0pep78z3TCw5w2/miiVUH2KkbV3fm7ym2jGz89TfsPTjLPVrfjlxU8/7zVO2B7bPPXmza4Tg77pkjPsMkKJT3SL/IGRmUYghoVM78b1fkAtWzeR+iv2AxEn4fw0FPOYp2OlibF5esPmUbYK5ezKv1txjbgOm75jhot1Hw8fFLFsT0mU5kziObpvnCKSroyUh5IbcZLxp5krQzds6ru2tVtpASJJDBn/dzHkIjnkJnOI0xEPTSRZrmK+5ELyFoKD/plNzF0Aa4N+zyl12W/fYcMvpeyLz3wmB30w9QVkAkpU9jHPdwk9QWaSFYHScMnRa/QFHaH73FTP0U/AyzxVh7DSc2VMRCQDEc2SOfdkGolLbb+lYLSZWMNCFUlMHnPJvbvlRRJHMysS1xtHcxOVXLGsNQM4OC4Wi69cOuVynQp4u1dGqO/5uh94g34XggoiRgRDTulhhVND8aiWgStTd1EDB+8HxyTxZCjX2SERiyRdhoqqgNrReEugeMBe4RWjts+8wHFs18dmgUpAXay4TQ2VDboLePnY1bbi3LiIHCcjUeFJ7vI/1zyTGhgfQakBM0BUSLMppn4pXMDU5cc2dtts+q7AeUFe7r4jZF89aIG1u0gorAh9DCklsYlTYNlASOUnFNYkNoBkFUIOuAlGjffMsg3dJzZVJ70V7NPAspRI7dX/m3ilVZKccGms0xT4pdZkOLu2kll+rQrYks3tUPLDB8dOmALfJfSZwxq+Qu6wdaL0tUBFWFw8TYVYreXb9WLBUzhyKa/GtRJ7LZ+qBUQ71bi8VHNUeJjdRlDmkdZyHu60py4V+m24juVLeO2ZF5cOFE2p7X08+AQh3YRxNC/mA6TOvERHf/344VzsjdpZkIPZ27xXQs+gG5tVtXXxrwH2/Fz0Ahh8rd7uq0vbya/8ZfwIQ4tox/+WQZWNNnMaA8QjfUuRxdnoWS6/jDI46oTyqmbPA4R7CksCWrJ8EuSCm22y2eK6W2YHsZoOdxCro7k2zba76re04zp4uNK82Jf9Nk/SDfB7R/n/pivqe9fwurnuYSNw4UYcXO7ploeb2qrRpFf6FS2Q9gP1q4KrFX4OKy5tJVWR3/CEhEUaMAtFOS3h8QqCK2auqf6BTIMpmwTUUJUTdp8/r1W2R4xp+DlJqxH8Y/SpqBVd41hJr4dUtOa+Ut3OafVJWtQE/K1K2qNvqa1j1t3S2Jw74WTXnN9rXu/B8SQOLzO0/xr9bdqV/frXBLCrIykfGBZHaL89Oe6qOP8AXcvUEKwNAAA=')
set_clip(data)
)"
pyw_exec_wait()
return

::str::
WinClose, @Auto_Activate@
clip_etxt()
clipboard := "data = dtxt(" clipboard ").replace('\r', '')"
return

::strn::
WinClose, @Auto_Activate@
clip_etxt()
clipboard := "data = dtxt(" clipboard ").replace('\r', '').split('\n')"
clipboard := clipboard "`ndata = nem(data)"
return

::fmcc::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
db_path_list = fl(data)
if len(db_path_list)!=1 or not db_path_list[0].lower().endswith('json'):
    set_clip('failed')
    exit()
else:
    set_clip('success')
def convert_cmd_json(db_path_list):
    db_items = []
    for db_path in db_path_list:
        db_items.extend(ldjs(rd(db_path)))
    db_items = ldjs(re.sub('([a-zA-Z]):\\\\\\\\', lambda x:'/mnt/{}/'.format(x.group(1).lower()), dmjs(db_items)).replace('\\\\', '/'))
    return dmjs(db_items)
px.data = convert_cmd_json(db_path_list).encode()
wt(db_path_list[0])(px('jq.exe').val)
)"
pyw_exec_wait()
return

::fmcx::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
db_path_list = fl(data)
db_path_list = list(filter(lambda db_path:db_path.lower().endswith('json'), db_path_list))
if not len(db_path_list):
    set_clip('failed')
    exit()
else:
    set_clip('success')

def convert_cmd_json(db_path_list):
    db_items = []
    for db_path in db_path_list:
        db_items.extend(ldjs(rd(db_path)))
    db_items = ldjs(re.sub('([a-zA-Z]):\\\\\\\\', lambda x:'/mnt/{}/'.format(x.group(1).lower()), dmjs(db_items)).replace('\\\\', '/'))
    return dmjs(db_items)
px.data = convert_cmd_json(db_path_list).encode()
wt('@@@txt@@@')(px('jq.exe').val)
)"
pyw_exec_wait()
return

::nsg::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
ip_mask_list = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', data)
if len(ip_mask_list)%2!=0:
    set_clip('failed')
    exit()
net_seg_list = []
for i in range(len(ip_mask_list)//2):
    ns = eval_net_seg(ip_mask_list[i], ip_mask_list[i+1])
    ns_cidr = ns.split('/')[1]
    net_seg_list.append('{}/{} : {}'.format(ip_mask_list[i], ns_cidr, ns))
set_clip(en(net_seg_list))
)"
pyw_exec_wait()
return

::wcon::
WinClose, @Auto_Activate@
clipboard := "wc(r'''" clipboard "''')"
pyw_eval()
return

::wconx::
WinClose, @Auto_Activate@
clipboard := "pwc()"
pyw_eval()
return

::img::
WinClose, @Auto_Activate@
clipboard := "exe(rd(fl(r'''" clipboard "''')[0])).img"
pyw_eval()
return

::inf::
WinClose, @Auto_Activate@
clipboard := "exe(rd(fl(r'''" clipboard "''')[0])).inf"
pyw_eval()
clip_msg_box()
return

::2sc::
WinClose, @Auto_Activate@
clipboard := "pe2sc(" clipboard ")"
pyw_eval()
return

::cc::
WinClose, @Auto_Activate@
write_text("@@@cc_exe_src@@@", clipboard)
clipboard := "
(
cc_src = rd('@@@cc_exe_src@@@', 'r')
wt()(bav.gen(cc_src))
)"
py_exec_cmd()
return

::bav.se::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
paths = fl(data)
for path in paths:
    sc = rd(path)
    if ispe(path):
        sc = pe2sc(sc)
    wt(pin(dirname(path), basename(path)+'.@shell'))(bav.single_exe(sc))
)"
pyw_exec_wait()
return

::bav.gui::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
paths = fl(data)
for path in paths:
    bav.gui(path)
)"
pyw_exec_wait()
return

::bav.cui::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
paths = fl(data)
for path in paths:
    bav.cui(path)
)"
pyw_exec_wait()
return

::ki::
WinClose, @Auto_Activate@
Process, Close, %clipboard%
return

::cinx::
::cin::
WinClose, @Auto_Activate@
clipboard := "hex(at(" clipboard ").code_inject(rd('@@@bin@@@')))"
pyw_eval()
return

::dinx::
WinClose, @Auto_Activate@
clipboard := "at(" clipboard ").dll_inject(rd('@@@txt@@@', 'r'))"
pyw_exec_wait()
return

::din::
WinClose, @Auto_Activate@
clipboard := "at(" clipboard ").dll_inject(rd('@@@txt@@@', 'r'))"
pyw_exec_wait_32()
return

::dx::
WinClose, @Auto_Activate@
clipboard := "cs('x86').d(" clipboard ")"
pyw_eval()
return

::dxx::
WinClose, @Auto_Activate@
clipboard := "cs('x64').d(" clipboard ")"
pyw_eval()
return

::da::
WinClose, @Auto_Activate@
clipboard := "cs('a32').d(" clipboard ")"
pyw_eval()
return

::dax::
WinClose, @Auto_Activate@
clipboard := "cs('a64').d(" clipboard ")"
pyw_eval()
return

::dl::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
mods = fl(data)
if len(mods)==1:
    try:
        set_clip(en(exe(mods[0]).dlib))
    except:
        pass
elif len(mods)>1:
    ret = sio()
    for i in mods:
        try:
            dlib = en(exe(i).dlib)
            print('-'*80, file=ret)
            print(i, ':', file=ret)
            print(dlib, file=ret)
        except:
            continue
    print('-'*80, file=ret)
    set_clip(ret.getvalue())
else:
    set_clip('')
)"
pyw_exec_wait()
return

::ex::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
mods = fl(data)
if len(mods)==1:
    try:
        set_clip(exe(mods[0]).s_ex())
    except:
        pass
elif len(mods)>1:
    ret = sio()
    for i in mods:
        try:
            print(exe(i).s_ex(i+' >'), file=ret)
        except:
            continue
    set_clip(ret.getvalue())
else:
    set_clip('')
)"
pyw_exec_wait()
return

::im::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
mods = fl(data)
if len(mods)==1:
    try:
        set_clip(exe(mods[0]).s_im())
    except:
        pass
elif len(mods)>1:
    ret = sio()
    for i in mods:
        try:
            print(exe(i).s_im(i+' <'), file=ret)
        except:
            continue
    set_clip(ret.getvalue())
else:
    set_clip('')
)"
pyw_exec_wait()
return

::dd::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
mod = fl(data)[0]
ret = sio()
print('='*80, file=ret)
print(exe(mod).dd('ex'), file=ret)
print('='*80, file=ret)
print(exe(mod).dd('im'), file=ret)
print('='*80, file=ret)
print(exe(mod).dd('iat'), file=ret)
print('='*80, file=ret)
print(exe(mod).dd('dim'), file=ret)
print('='*80, file=ret)
print(exe(mod).dd('rel'), file=ret)
print('='*80, file=ret)
print(exe(mod).dd('tls'), file=ret)
print('='*80, file=ret)
print(exe(mod).dd('exc'), file=ret)
print('='*80, file=ret)
print(exe(mod).dd('res'), file=ret)
print('='*80, file=ret)
print(exe(mod).dd('cfg'), file=ret)
print('='*80, file=ret)
set_clip(ret.getvalue())
)"
pyw_exec_wait()
return

::dlfw::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
ret = sio()
mod = fl(data)
for i in mod:
    p(exe(i).dlfw(basename(i)), file=ret)
set_clip(ret.getvalue())
)"
pyw_exec_wait()
return

::dlfwx::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
ret = sio()
mod = fl(data)
for i in mod:
    p(exe(i).dlfw(i), file=ret)
set_clip(ret.getvalue())
)"
pyw_exec_wait()
return

::winsec::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''
mods = fl(data)

def win_check_sec(flist):
    ret = sio()
    print('='*80, file=ret)
    for i in flist:
        if not ispe(i):
            continue
        data = pp(r'D:\tools\re\WinCheckSec\winchecksec.exe', i)().decode('ansi')
        if data:
            print(data, file=ret)
            print('='*80, file=ret)
    return ret.getvalue()
    
set_clip(win_check_sec(mods))
)"
pyw_exec_wait()
return

::wss::
WinClose, @Auto_Activate@
clipboard := "
(
path = fl(r'''" clipboard "''')[0]
if 'ntdll' in path.lower():
    api_set = sorted(filter(lambda ex:ex.name.startswith('Zw'), exe(rd(path)).ex), key=lambda ex:ex.addr)
    ssn = (i for i in range(len(api_set)))
    set_clip(en(['{: <11}{}'.format(hex(next(ssn)), ex.name) for ex in api_set]))
else:
    api_set = sorted(filter(lambda ex:ex.name.startswith('Nt'), exe(rd(path)).ex), key=lambda ex:ex.addr)
    ssn = (i for i in range(len(api_set)))
    set_clip(en(['{: <11}{}'.format(hex(0x1000+next(ssn)), ex.name) for ex in api_set]))
)"
pyw_exec_wait()
return

::fl::
WinClose, @Auto_Activate@
clip_etxt()
clipboard := "files = fl(dtxt(" clipboard "))"
return

::fa::
WinClose, @Auto_Activate@
clipboard := "Thread(target=lambda:fa_cli(r'''" clipboard "'''.strip())).start();set_clip(r'''" clipboard "'''.strip())"
pyw_exec()
return

::ub1::
WinClose, @Auto_Activate@
RunWait, wsl.exe --set-default ubuntu_1, , Hide
return

::ub2::
WinClose, @Auto_Activate@
RunWait, wsl.exe --set-default ubuntu_2, , Hide
return

::ka::
WinClose, @Auto_Activate@
RunWait, wsl.exe --set-default kali-linux, , Hide
return

::wsl::
WinClose, @Auto_Activate@
Run, wsl.exe
return

::tml::
WinClose, @Auto_Activate@
Run, wsl.exe tml
return

::tmlx::
WinClose, @Auto_Activate@
Run, wsl.exe tmux kill-session -t tml, , Hide
return

::ems::
WinClose, @Auto_Activate@
Run, wsl.exe emacs --daemon
return

::emx::
WinClose, @Auto_Activate@
Run, wsl.exe pkill -SIGUSR2 -i emacs, , Hide
clipboard := "toggle-debug-on-quit"
return

::wfp::
WinClose, @Auto_Activate@
clipboard=
(
data = rd('@@@txt@@@', 'r')

def handler(obj):
    ret = [i for i in obj.groups()]
    fn_ptr = ret[0]+ret[1]+'('+ret[2]+' * _'+ret[3]+')'+ret[4]+'\n'
    fn_name = "char {}[] = {{'{}', 0}};\n".format('sz'+ret[3], "', '".join(ret[3]))
    return fn_ptr+fn_name

set_clip(re.sub(r'(\w+API\s+)(\w+\s+)(WINAPI)\s+(\w+)\s*(\(\s*[^;]*;)', handler, data))
)
pyw_exec_wait()
return

::wbx::
WinClose, @Auto_Activate@
clipboard := "
(
def hx(data):
    ret = []
    data = list(map(str, data))
    for i in data:
        try:
            x = hex(int(i.replace('``', ''), 0))
            ret.append(x)
        except:
            continue
    return ret
data = hx(" clipboard ")
ret = sio()
for i in data:
    print(' '.join(['bp', i, r'"".if(1){{.printf \""(0x%p, {}), \"", @$tid;gc}} .else{{gc}}""'.format(i)]), file=ret)
set_clip(ret.getvalue())
)"
pyw_exec_wait()
return

::lcx::
WinClose, @Auto_Activate@
clipboard := "
(
paths = r'''" clipboard " '''

try:
    set_clip(en(lcx(paths)))
except:
    set_clip('Error File List!')
)"
pyw_exec_wait()
return

::wcx::
WinClose, @Auto_Activate@
clipboard := "
(
paths = r'''" clipboard " '''

try:
    set_clip(en(wcx(paths)))
except:
    set_clip('Error File List!')
)"
pyw_exec_wait()
return
#IfWinActive
;----------------------------------------------------------------------
;apx-常用程序功能增强

;tc- TotalCMD64常用命令
#IfWinActive ahk_exe Totalcmd64.exe
<^LAlt::
clipboard := "
(
path = r'''" clipboard " '''

try:
    path = wcx(path)[0]
    if isdir(path):
        set_clip(path)
    elif isfile(path):
        set_clip(dirname(path))
    else:
        set_clip('Error File Path!')
except:
    set_clip('Error File Path!')
)"
pyw_exec_wait()
RunWait, %A_ScriptDir%\..\..\utils\TotalCMD64\Totalcmd64.exe /O /T "%clipboard%"
return
<!LCtrl::
SendInput, ^+c\{Enter}
return
::re::<(){Left 1}
::exe::<(\.exe$|\.dll$|\.sys$)
::cfg::<(\.yml$|\.xml$|\.json$|\.properties$|\.ini$)
::cpp::<(\.cpp$|\.c\+\+$|\.cxx$|\.hpp$|\.hh$|\.h\+\+$|\.hxx$|\.c$|\.cc$|\.h$)
#IfWinActive

#IfWinActive ahk_exe Everything.exe
<^LAlt::
RunWait, %A_ScriptDir%\..\..\utils\TotalCMD64\Totalcmd64.exe /O /T "%clipboard%"
return

#IfWinActive ahk_exe HxD64.exe
<^LAlt::
SendInput, !{Ins}
return

#IfWinActive ahk_group browser
<^LAlt::
SendInput, {f11}
return

#IfWinActive ahk_exe Code.exe
!d::
SendInput, {Click}{f12}
return
^3::
SendInput, ^p{#}
return

#IfWinActive ahk_exe idea64.exe
!d::
SendInput, {Click}^b
return
<^LAlt::
SendInput, ^+f
return
<^LWin::
SendInput, +{f4}
return

#IfWinActive ahk_group terminal
#c::
SendInput {Click, 2}^+c
return
^+v::SendInput, {Text}%clipboard%

#IfWinActive ahk_exe notepad++.exe
<^LAlt::SendInput, ^f^v!o
!f::SendInput, ^f^v{Enter}{Esc}
!w::Send, !ww
^Esc::
clipboard := "set_clip(len(r'''" clipboard "''')*' ')"
pyw_exec_wait()
return

#IfWinActive ahk_exe cmd.exe
!f::SendInput, ^f^v{Enter}{Esc}
<^LAlt::
SendInput, {Click}^a{Enter}
WinActivateBottom, ahk_exe notepad++.exe
SendInput, ^n^v
return

#IfWinActive ahk_exe devenv.exe
<^LAlt::SendInput, {Click}+{f12}
!d::SendInput, {Click}{F12}
!f::SendInput, ^f{Enter}{Esc}
^p::SendInput, ^;
!`;::SendInput, !dwi

#IfWinActive ahk_exe sourceinsight4.exe
<^LAlt::SendInput, ^/
!d::SendInput, {Click}^=
!f::SendInput, {f8}
!c::SendInput, {Click}^!c
!a::SendInput, ^l
!z::SendInput, +{F3}
!x::SendInput, +{F4}

#IfWinActive
#c::
SendInput {Click, 2}^c
return
#s::
RunWait, key.bat l, , Hide
RunWait, rundll32.exe user32.dll`, LockWorkStation`
RunWait, key.bat xl, , Hide
return

<!LCtrl::SendInput, {XButton1}
NumpadSub::RCtrl
;----------------------------------------------------------------------
;app-常用程序 热键/热字串 启动/激活

;apg- app global
;apk- app hotkey 全局热键 启动/激活
>^`;::
if WinExist("ahk_exe cmd.exe") {
	WinActivateBottom, ahk_group win_shell
	return
}
else {
    Run, cmd.exe
	return
}

>^'::
if WinExist("ahk_group browser") {
	WinActivateBottom, ahk_group browser
	return
}
else {
    Run, cmd.exe /c "start %browser_path%"
	return
}

#F::
if WinExist("ahk_exe Totalcmd64.exe") {
	WinActivate, ahk_exe Totalcmd64.exe
	return
}
else {
	Run, %A_ScriptDir%\..\..\utils\TotalCMD64\Totalcmd64.exe
	return	
}

#`;::
if WinExist("ahk_exe notepad++.exe") {
	WinActivate, ahk_exe notepad++.exe
	return
}
else {
    Run, %SCOOP_ROOT%\apps\notepadplusplus\current\notepad++.exe
	return
}

#+`;::
clipboard := "
(
paths = r'''" clipboard " '''

try:
    set_clip(en(wcx(paths)))
except:
    set_clip('Error File List!')
)"
pyw_exec_wait()
Loop, parse, clipboard, `n, `r
{
    Run, openw.exe "%SCOOP_ROOT%\apps\notepadplusplus\current\notepad++.exe" """%A_LoopField%""", , Hide
}
return

#l::
if WinExist("ahk_exe wsl.exe") {
	WinActivateBottom, ahk_exe wsl.exe
	return
}
else {
	RunWait, wsl.exe --set-default ubuntu_1
    Run, wsl.exe
	return
}

#m::
if WinExist("ahk_group terminal_emulator") {
	WinActivateBottom, ahk_group terminal_emulator
	return
}
else {
    Run, %SCOOP_ROOT%\apps\wsltty\current\bin\mintty.exe --WSL= --configdir="%A_ScriptDir%\..\..\config\wsltty" -
	return
}

#+m::
WinActivateBottom, ahk_group ahk_window
return

#y::
return

#+y::
return

#Enter::
Process, Exist, vcxsrv.exe
if(!ErrorLevel) {
	return
}
if WinExist("ahk_exe vcxsrv.exe") {
	WinActivateBottom, ahk_exe vcxsrv.exe
	return
}
else {
    Run, cmd.exe /c "wsl.exe bash -c "DISPLAY=:0 emacsclient -c" &", , Hide
	return
}

#+Enter::
WinActivateBottom, ahk_exe vcxsrv.exe
clipboard := "
(
path = r'''" clipboard " '''

try:
    set_clip(lcx(path)[0])
except:
    set_clip('Error File Path!')
)"
pyw_exec_wait()
Run, wsl.exe emacsclient "%clipboard%", , Hide
return

#n::
if WinExist("ahk_exe Code.exe") {
	WinActivate, ahk_exe Code.exe
	return
}
else {
    Run, openw.exe "%SCOOP_ROOT%\apps\vscode\current\Code.exe" --extensions-dir "%A_ScriptDir%\..\..\config\VScode\extensions", , Hide
	return
}

#+n::
clipboard := "
(
paths = r'''" clipboard " '''

try:
    set_clip(en(wcx(paths)))
except:
    set_clip('Error File List!')
)"
pyw_exec_wait()
Loop, parse, clipboard, `n, `r
{
    Run, openw.exe "%SCOOP_ROOT%\apps\vscode\current\Code.exe" """%A_LoopField%""" --extensions-dir "%A_ScriptDir%\..\..\config\VScode\extensions", , Hide
}
return


#b::
WinActivateBottom, ahk_group virtual_machine
return

#+b::
if WinExist("ahk_class MMCMainFrame") {
	WinActivateBottom, ahk_class MMCMainFrame
	return
}
else {
	Run, "C:\Windows\System32\mmc.exe" "C:\Windows\System32\virtmgmt.msc"
	return
}

<!LShift::
WinActivateBottom, ahk_group ida
return

#8::
WinActivateBottom, ahk_group debugger
return

;apl- app local 
;aps- app hotstring 局部热字串(仅在#o热键启动的对话框中生效) 启动/激活
#IfWinActive @Auto_Activate@
!`;::
SendInput, ^.{End}+{Home}{BS}
return

::h::
WinClose, @Auto_Activate@
if WinExist("ahk_exe HxD64.exe") {
	WinActivate, ahk_exe HxD64.exe
	return
}
else {
	Run, %SCOOP_ROOT%\apps\hxd\current\HxD.exe
	WinActivate, ahk_exe HxD64.exe
	return	
}

::wh::
WinClose, @Auto_Activate@
Run, %A_ScriptDir%\..\..\help\Win32.chm
return

::asm::
WinClose, @Auto_Activate@
FileRead, clipboard, %A_ScriptDir%\..\..\bin\Lib\core\core_asm\core.asm
return

::7z::
WinClose, @Auto_Activate@
clipboard := "
(
paths = r'''" clipboard " '''
try:
    for path in filter(lambda path:exist(path), wcx(paths)):
        pp('7z', 'x', '-r', '{}'.format(abspath(path)), '-aou', '-o{}'.format(abspath(path)+'@'))()
except:
    set_clip('Error File List!')
)"
pyw_exec_wait()
return

::jd2::
WinClose, @Auto_Activate@
clipboard := "
(
for i in glob(r'@@@jad_src@@@\**.jar'):
    pp('7z', 'x', '{}'.format(abspath(i)), '-aou', '-o{}'.format(''.join(abspath(i).split('.')[:-1])))()
    rm(abspath(i))
)"
pyw_exec_wait()
return

::jd1::
WinClose, @Auto_Activate@
clipboard := "
(
if not exist('@@@jad_src@@@'):
    md('@@@jad_src@@@')
paths = r'''" clipboard " '''

try:
    set_clip(en(wcx(paths)))
except:
    set_clip('Error File List!')
)"
pyw_exec_wait()
Loop, parse, clipboard, `n, `r
{
    Run, %java11% -jar %A_ScriptDir%\..\..\re\fernflower.jar %A_LoopField% @@@jad_src@@@
}
return

::jdx::
WinClose, @Auto_Activate@
Run, %java11w% -jar %A_ScriptDir%\..\..\re\recaf.jar
return

::cd1::
WinClose, @Auto_Activate@
clipboard := "
(
paths = r'''" clipboard " '''

try:
    set_clip(en(wcx(paths)))
except:
    set_clip('Error File List!')
)"
pyw_exec_wait()
Loop, parse, clipboard, `n, `r
{
    base_name := basename(A_LoopField)
    Run, %A_ScriptDir%\..\..\re\dnspy\dnSpy-net-win64\dnSpy.Console.exe -o @@@csd_src@@@/%base_name% -r %A_LoopField%
}
return

::cd::
WinClose, @Auto_Activate@
if WinExist("ahk_exe dnSpy.exe") {
	WinActivate, ahk_exe dnSpy.exe
	return
}
else {
	Run, %A_ScriptDir%\..\..\re\dnspy\dnSpy-net-win32\dnSpy.exe
	WinActivate, ahk_exe dnSpy.exe
	return	
}

::cdx::
WinClose, @Auto_Activate@
if WinExist("ahk_exe dnSpy.exe") {
	WinActivate, ahk_exe dnSpy.exe
	return
}
else {
	Run, %A_ScriptDir%\..\..\re\dnspy\dnSpy-net-win64\dnSpy.exe
	WinActivate, ahk_exe dnSpy.exe
	return	
}

::df::
WinClose, @Auto_Activate@
if WinExist("ahk_exe WinMergeU.exe") {
	WinActivate, ahk_exe WinMergeU.exe
	return
}
else {
	Run, %SCOOP_ROOT%\apps\winmerge\current\WinMergeU.exe
	return	
}
return

::si::
WinClose, @Auto_Activate@
if WinExist("ahk_exe sourceinsight4.exe") {
	WinActivate, ahk_exe sourceinsight4.exe
	return
}
else {
	Run, %A_ScriptDir%\..\..\utils\si\si\sourceinsight4.exe
	return	
}
return

::i::
WinClose, @Auto_Activate@
Run, %A_ScriptDir%\..\..\re\IDA\IDA7.5\ida.exe
return

::ix::
WinClose, @Auto_Activate@
Run, %A_ScriptDir%\..\..\re\IDA\IDA7.5\ida64.exe
return

::cr::
WinClose, @Auto_Activate@
Loop, %A_ScriptDir%\..\..\re\CyberChef\CyberChef*.html, F
    Run, %A_LoopFileFullPath%
return

::d::
WinClose, @Auto_Activate@
WinActivate ahk_exe devenv.exe
return

::s::
WinClose, @Auto_Activate@
WinActivate ahk_exe understand.exe
return

::m::
WinClose, @Auto_Activate@
if WinExist("ahk_exe Typora.exe") {
	WinActivate, ahk_exe Typora.exe
	return
}
else {
    Run, %A_ScriptDir%\..\..\utils\Typora\bin\typora.exe
	return
}

::v::
WinClose, @Auto_Activate@
if WinExist("ahk_exe PotPlayerMini64.exe") {
	WinActivate, ahk_exe PotPlayerMini64.exe
    WinActivate, ahk_exe PotPlayerMini64.exe
	return
}
else {
    Run, %A_ScriptDir%\..\..\utils\PotPlayer64\PotPlayerMini64.exe
	return
}

::rc::
WinClose, @Auto_Activate@
if WinExist("ahk_exe mstsc.exe") {
	WinActivateBottom, ahk_exe mstsc.exe
	return
}
else {
    Run, mstsc.exe
	return
}

::w::
WinClose, @Auto_Activate@
Run, %A_ScriptDir%\..\..\re\WinDbg\x86\windbg.exe
return

::wi::
WinClose, @Auto_Activate@
Run, %A_ScriptDir%\..\..\re\WinDbg\x86\windbg.exe -I
return

::wx::
WinClose, @Auto_Activate@
Run, %A_ScriptDir%\..\..\re\WinDbg\x64\windbg.exe
return

::wix::
WinClose, @Auto_Activate@
Run, %A_ScriptDir%\..\..\re\WinDbg\x64\windbg.exe -I
return

::wd::
WinClose, @Auto_Activate@
RegDelete, HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug
return

::wdx::
WinClose, @Auto_Activate@
RegDelete, HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
return

::kni::
WinClose, @Auto_Activate@
clipboard := "
(
data = r'''" clipboard " '''.strip()
wt('@@@kdnet_key@@@', 'w')(r'D:\tools\re\WinDbg\x64\windbg.exe -k net:port=5364,key='+data)
)"
pyw_exec_wait()
return

::kn::
WinClose, @Auto_Activate@
FileRead, kdnet_key, @@@kdnet_key@@@
Run, %kdnet_key%
return

::kc::
WinClose, @Auto_Activate@
kdcom_key := "D:\tools\re\WinDbg\x64\windbg.exe -k com:pipe,port=\\.\pipe\com_kd,resets=0,reconnect"
Run, %kdcom_key%
return

::e::
WinClose, @Auto_Activate@
if WinExist("ahk_exe imhex.exe") {
	WinActivate, ahk_exe imhex.exe
	return
}
else {
    Run, %SCOOP_ROOT%\apps\imhex\current\imhex.exe
	return
}

::ws::
WinClose, @Auto_Activate@
if WinExist("ahk_exe Wireshark.exe") {
	WinActivate, ahk_exe Wireshark.exe
	return
}
else {
    Run, %SCOOP_ROOT%\apps\wireshark\current\Wireshark.exe
	return
}

::id::
WinClose, @Auto_Activate@
if WinExist("ahk_exe idea64.exe") {
    WinActivate, ahk_exe idea64.exe
    return
}
else {
    Run, %SCOOP_ROOT%\apps\idea-ultimate\current\IDE\bin\idea64.exe
	return
}

::cl::
WinClose, @Auto_Activate@
if WinExist("ahk_exe clion64.exe") {
    WinActivate, ahk_exe clion64.exe
    return
}
else {
    Run, %SCOOP_ROOT%\apps\clion\current\IDE\bin\clion64.exe
	return
}

::php::
WinClose, @Auto_Activate@
if WinExist("ahk_exe phpstorm64.exe") {
    WinActivate, ahk_exe phpstorm64.exe
    return
}
else {
    Run, %SCOOP_ROOT%\apps\phpstorm\current\IDE\bin\phpstorm64.exe
	return
}

::jetop::
WinClose, @Auto_Activate@
Run, powershell.exe %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\jet_op.ps1
return

::jeted::
WinClose, @Auto_Activate@
Run, powershell.exe %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\jet_ed.ps1
return

::jetid::
WinClose, @Auto_Activate@
FileCopy, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\template\idea.vmoptions, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\user\idea.vmoptions, 1
clipboard := "
(
key_db = ldjs(rd(r'D:\tools\config\JetBrain\key_db', 'r'))
key_map = {
    'IDEA':key_db['II']['2022.1.x'],
    'CLion':key_db['CL']['2022.1.x'],
    'GoLand':key_db['GO']['2022.1.x'],
    'RubyMine':key_db['RM']['2022.1.x'],
    'PhpStorm':key_db['PS']['2022.1.x'],
    'PyCharm':key_db['PC']['2022.1.x']
}
set_clip(key_map['IDEA'])
)"
pyw_exec_wait()
return

::jetcl::
WinClose, @Auto_Activate@
FileCopy, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\template\clion.vmoptions, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\user\clion.vmoptions, 1
clipboard := "
(
key_db = ldjs(rd(r'D:\tools\config\JetBrain\key_db', 'r'))
key_map = {
    'IDEA':key_db['II']['2022.1.x'],
    'CLion':key_db['CL']['2022.1.x'],
    'GoLand':key_db['GO']['2022.1.x'],
    'RubyMine':key_db['RM']['2022.1.x'],
    'PhpStorm':key_db['PS']['2022.1.x'],
    'PyCharm':key_db['PC']['2022.1.x']
}
set_clip(key_map['CLion'])
)"
pyw_exec_wait()
return

::jetgo::
WinClose, @Auto_Activate@
FileCopy, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\template\goland.vmoptions, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\user\goland.vmoptions, 1
clipboard := "
(
key_db = ldjs(rd(r'D:\tools\config\JetBrain\key_db', 'r'))
key_map = {
    'IDEA':key_db['II']['2022.1.x'],
    'CLion':key_db['CL']['2022.1.x'],
    'GoLand':key_db['GO']['2022.1.x'],
    'RubyMine':key_db['RM']['2022.1.x'],
    'PhpStorm':key_db['PS']['2022.1.x'],
    'PyCharm':key_db['PC']['2022.1.x']
}
set_clip(key_map['GoLand'])
)"
pyw_exec_wait()
return

::jetrb::
WinClose, @Auto_Activate@
FileCopy, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\template\rubymine.vmoptions, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\user\rubymine.vmoptions, 1
clipboard := "
(
key_db = ldjs(rd(r'D:\tools\config\JetBrain\key_db', 'r'))
key_map = {
    'IDEA':key_db['II']['2022.1.x'],
    'CLion':key_db['CL']['2022.1.x'],
    'GoLand':key_db['GO']['2022.1.x'],
    'RubyMine':key_db['RM']['2022.1.x'],
    'PhpStorm':key_db['PS']['2022.1.x'],
    'PyCharm':key_db['PC']['2022.1.x']
}
set_clip(key_map['RubyMine'])
)"
pyw_exec_wait()
return

::jetphp::
WinClose, @Auto_Activate@
FileCopy, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\template\phpstorm.vmoptions, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\user\phpstorm.vmoptions, 1
clipboard := "
(
key_db = ldjs(rd(r'D:\tools\config\JetBrain\key_db', 'r'))
key_map = {
    'IDEA':key_db['II']['2022.1.x'],
    'CLion':key_db['CL']['2022.1.x'],
    'GoLand':key_db['GO']['2022.1.x'],
    'RubyMine':key_db['RM']['2022.1.x'],
    'PhpStorm':key_db['PS']['2022.1.x'],
    'PyCharm':key_db['PC']['2022.1.x']
}
set_clip(key_map['PhpStorm'])
)"
pyw_exec_wait()
return

::jetpy::
WinClose, @Auto_Activate@
FileCopy, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\template\pycharm.vmoptions, %A_ScriptDir%\..\..\config\JetBrain\ja-netfilter-all\vmoptions\user\pycharm.vmoptions, 1
clipboard := "
(
key_db = ldjs(rd(r'D:\tools\config\JetBrain\key_db', 'r'))
key_map = {
    'IDEA':key_db['II']['2022.1.x'],
    'CLion':key_db['CL']['2022.1.x'],
    'GoLand':key_db['GO']['2022.1.x'],
    'RubyMine':key_db['RM']['2022.1.x'],
    'PhpStorm':key_db['PS']['2022.1.x'],
    'PyCharm':key_db['PC']['2022.1.x']
}
set_clip(key_map['PyCharm'])
)"
pyw_exec_wait()
return

::cs::
WinClose, @Auto_Activate@
Run, %java17w% -Dfile.encoding=utf-8 -XX:ParallelGCThreads=4 -XX:+AggressiveHeap -XX:+UseParallelGC -Xms512M -Xmx1024M -javaagent:%A_ScriptDir%\..\..\re\cs4\hook.jar -jar %A_ScriptDir%\..\..\re\cs4\cobaltstrike.jar
return

::x::
WinClose, @Auto_Activate@
Run, %SCOOP_ROOT%\apps\x64dbg\current\release\x32\x32dbg.exe
return

::xx::
WinClose, @Auto_Activate@
Run, %SCOOP_ROOT%\apps\x64dbg\current\release\x64\x64dbg.exe
return

::bc::
WinClose, @Auto_Activate@
Run, %SCOOP_ROOT%\apps\bochs\current\bochs.exe
return

::bcd::
WinClose, @Auto_Activate@
Run, %SCOOP_ROOT%\apps\bochs\current\bochsdbg.exe
return

::pdb::
WinClose, @Auto_Activate@
clipboard =
(
pp(r'D:\tools\re\WinDbg\x64\symchk.exe', '/r', r'{}'.format(pin(cwd(), '@@@log@@@')), '/s', r'SRV*{}*https://msdl.microsoft.com/download/symbols'.format(pin(cwd(), '@@@pdb@@@')))()
)
pyw_exec_wait()
MsgBox, PDB download completed
return

::ps::
WinClose, @Auto_Activate@
Run, %SCOOP_ROOT%\apps\processhacker-nightly\current\ProcessHacker.exe
return

::res::
WinClose, @Auto_Activate@
Run, %SCOOP_ROOT%\apps\resource-hacker\current\ResourceHacker.exe
return

::pe::
WinClose, @Auto_Activate@
clipboard := "pe_path=fl(r'''" clipboard "''')[0].strip();set_clip(pe_path);os.popen('""'+abspath(r'''" A_ScriptDir "\..\..\re\Stud_PE\Stud_PE.exe''')+'"" {}'.format(pe_path))"
pyw_exec()
return

::pex::
WinClose, @Auto_Activate@
clipboard := "
(
paths = r'''" clipboard " '''

try:
    set_clip(en(wcx(paths)))
except:
    set_clip('Error File List!')
)"
pyw_exec_wait()
pe_file_list := ""
Loop, parse, clipboard, `n, `r
{
    pe_file_list := pe_file_list " """ A_LoopField """"
}
Run, openw.exe "%SCOOP_ROOT%\apps\pe-bear\current\PE-bear.exe" %pe_file_list%, , Hide
return

::bs::
WinClose, @Auto_Activate@
Run, %java17w% --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED -jar %A_ScriptDir%\..\..\re\burp.jar
return

::gd::
WinClose, @Auto_Activate@
EnvSet, PATH, %java11_path%;%PATH%
Run, %SCOOP_ROOT%\apps\ghidra\current\ghidraRun.bat, , Hide
return

::cm::
WinClose, @Auto_Activate@
Run, cmd.exe
return

::cx::
WinClose, @Auto_Activate@
Run, powershell.exe
return

::ed::
WinClose, @Auto_Activate@
Run, notepad.exe
return

#IfWinActive
;----------------------------------------------------------------------
;gdb-相关命令和结构

#IfWinActive ahk_group wsl
::db::x/112xb{Space}
::dw::x/56xh{Space}
::dd::x/28xw{Space}
::dq::x/14xg{Space}
::da::x/5s{Space}
::u::x/10i{Space}
::d::x/10i $pc
::r::info reg{Space}

::ctx::context
#IfWinActive
;----------------------------------------------------------------------
;windbg- wd- 命令 结构 插件

#IfWinActive ahk_exe cmd.exe
::tag::type D:\tools\re\WinDbg\x64\triage\pooltag.txt | peco --rcfile D:\tools\bin\peco.cfg | clip.exe
::asm::type D:\tools\bin\Lib\core\core_asm\core.asm | peco --rcfile D:\tools\bin\peco.cfg --query "`;`; " | clip.exe
::wdx::
Run, WinDbgX
return
::knk::bcdedit /dbgsettings | findstr.exe /i "key" | clip.exe
::gfhpa::D:\tools\re\WinDbg\x64\gflags.exe /i "" {+}hpa{Left 6}
::gfcl::D:\tools\re\WinDbg\x64\gflags.exe /i "" {+}ffffffff{Left 11}
::versp::
clipboard = verifier /volatile /flags 0x1 /adddriver
return

#IfWinActive ahk_group windbg
::c::{Home}{!}{Home}
::a::
clipboard := "
(
r''' " clipboard " '''.strip().replace('\\', '\\\\').replace('""', '\\""')
)"
pyw_eval()
SendInput, ^v
return
::if::".if(){{}{}}"{Left 4}
::el::.else{{}{}}{Left 1}
::lg::.logopen /u c:\windbg.log`;`;.logclose{Left 10}
::lgop::.logopen /u c:\windbg.log
::lged::.logclose
::rdl::
clipboard := "rd(r'C:\windbg.log').decode('utf-16')"
pyw_eval()
return
::rdb::
clipboard := "rd(r'c:\memdump.bin')"
pyw_eval()
return
::wtb::
clipboard := "wt(r'c:\memdump.bin')(" clipboard ")"
pyw_eval()
return
::s::{Home}dx @$windbg.exec_log("{End}", ""){Left 2}
::sx::{Home}.shell -ci "{End}" findstr.exe /i ".*"{Space}{Left 4}
::sv::{Home}.shell -ci "{End}" findstr.exe /V /i ""{Space}{Left 2}
::ws:: | findstr.exe /i ""{Space}{Left 2}
::wsv:: | findstr.exe /V /i ""{Space}{Left 2}
::fz:: | clip.exe{Space}
::ifz::{Home}.shell -ci "{End}" findstr.exe /i "." | clip.exe{Space}
::cc::.cls
::ki::.kill{Space}
::ee::dx @$windbg.eva(""){Space}{Left 3}
::ss::.open -a{Space}
::tt::.trap{Space}
::ex::.exr -1+{Left 2}
::exc::{!}exchain{Space}
::exeh::da poi(poi(poi({+}0xC){+}0x4){+}0x4){+}8{Left 17}
::pc::{!}pcr{Space}
::irpx::{!}irp{Space}
::sep::poi(PsInitialSystemProcess)
::kdt::KeServiceDescriptorTable
::kdtx::KeServiceDescriptorTableShadow
::idt::{!}idt -a{Space}
::ver::vertarget
::veplg::{!}verifier 80{Space}
::dm::{!}dml_proc{Space}
::kk::{!}uext.findstack  3{Left 2}
::tm::{Home}r @$t19= @$ip{;}{Left 1}+{Left 4}
::tmx::r @$t19;u @$t19 l1
::xm8::rx xmm:2uq{Left 4}
::xm4::rx xmm:4ud{Left 4}
::ym8::rx ymm:4uq{Left 4}
::ym4::rx ymm:8ud{Left 4}
::ra::r @$t19= @$ra {;}ub @$t19 {;}.printf "@@@@@@@@@@@@\n"{;}u @$t19{Space}{Left 45}^+{Left 2}
::mop::dx @$windbg.eva("Mm.init()")
::bop::dx @$windbg.eva("Bp.op()")
::bls::dx @$windbg.eva("Bp.ls()")
::brm::dx @$windbg.eva("Bp.rm()"){Left 3}
::bps::dx @$windbg.eva("new Bp($(\"@$t19\")).ps()")
::btag::dx @$windbg.eva("new Bp().ps_tag(\"''\")"){Left 6}
::bret::dx @$windbg.eva("new Bp($(\"@$t19\")).ps_ret('', 0x1000)"){Left 12}
::barg::dx @$windbg.eva("new Bp($(\"@$t19\")).ps_arg(0, '', 0x1000)"){Left 12}
::barg0::dx @$windbg.eva("new Bp($(\"@$t19\")).ps_arg(0, '')"){Left 4}
::barg1::dx @$windbg.eva("new Bp($(\"@$t19\")).ps_arg(1, '')"){Left 4}
::barg2::dx @$windbg.eva("new Bp($(\"@$t19\")).ps_arg(2, '')"){Left 4}
::barg3::dx @$windbg.eva("new Bp($(\"@$t19\")).ps_arg(3, '')"){Left 4}
::rva::dx @$windbg.eva("\"[\"{+}'@$ip'.split(/\\s{+}/).map($).map(rva){+}\"]\""){Left 39}+{Left 4}
::rvk::dx @$windbg.eva("\"[\"{+}rvk(\"\"){+}\"]\""){Left 11}
::rdc::dx @$windbg.eva("$(\"@$t19\").rdi()"){Left 3}
::rds::dx @$windbg.eva("$(\"@$t19\").rdi(, true)"){Left 9}
::fn::new fn($('')).{Left 4}
::bb::new bb($('')).{Left 4}
::it::new it($('')).{Left 4}
::scx::$$>< "D:\tools\bin\Lib\windbg\windbg.dbg"
::sc::.scriptrun D:\tools\bin\Lib\windbg\windbg.js
::scp::.scriptproviders
::scop::.scriptload D:\tools\bin\Lib\windbg\windbg.js{Space}
::sced::.scriptunload D:\tools\bin\Lib\windbg\windbg.js{Space}
::db::.scriptunload D:\tools\bin\Lib\windbg\windbg.js`;.scriptload D:\tools\bin\Lib\windbg\windbg.js`;dx @$windbg = Debugger.State.Scripts.windbg.Contents{Space}
::scls::.scriptlist
::dmm::.writemem c:\memdump.bin  l{Left 2}
::rdm::.writemem c:\memdump.bin  l{Left 2}
::ldm::.readmem c:\memdump.bin  l{Left 2}
::wtm::.readmem c:\memdump.bin  l{Left 2}
::lck::{!}locks{Space}
::d::u @$ip^+{Left 2}
::dd::ub @$ip^+{Left 2}
::df::uf @$ip^+{Left 2}
::br::ba r1{Space}
::bw::ba w1{Space}
::be::ba e1{Space}
::sb::s-b @$t19 L?0x2000{Space}
::sbv::s-b @$t19 L-0x2000{Space}
::sw::s-w @$t19 L?0x2000{Space}
::swv::s-w @$t19 L-0x2000{Space}
::sd::s-d @$t19 L?0x2000{Space}
::sdv::s-d @$t19 L-0x2000{Space}
::sq::s-q @$t19 L?0x2000{Space}
::sqv::s-q @$t19 L-0x2000{Space}
::sa::s-a @$t19 L?0x2000 ""{Left 1}
::sav::s-a @$t19 L-0x2000 ""{Left 1}
::su::s-u @$t19 L?0x2000 ""{Left 1}
::suv::s-u @$t19 L-0x2000 ""{Left 1}
::dl::dl  0xffffffff 2{Left 13}
::ds::dps{Space}
::da::dpa{Space}
::du::dpu{Space}
::dp::dpp{Space}
::dk::dps @$csp l5+{Left 1}
::ebp::sxe -c "" bpe{Left 5}
::eld::sxe ld:
::eud::sxe ud:
::ecp::sxe cpr
::eep::sxe epr
::ect::sxe ct
::eet::sxe et
::rbt::.reboot{Space}
::abd::.abandon{Space}
::kil::.kill{Space}
::ld::.load{Space}
::adre::{!}address{Space}
::hp::{!}heap{Space}
::hpa::{!}heap -a{Space}
::hpx::{!}heap -x{Space}
::hpxv::{!}heap -x -v{Space}
::hppa::{!}heap -p -a{Space}
::cx::@@c{+}{+}(){Left 1}
::as::@@masm(){Left 1}
::sf::??sizeof(){Left 1}
::po::poi(){Left 1}
::rd::dps  l1{Left 3}
::wow::{!}wow64exts.sw
::at::.attach{Space}
::dat::.detach{Space}
::cre::.create{Space}
::dma::.dump /ma{Space}
::odm::.opendump{Space}
::pr::.process{Space}
::ps::{!}process @$proc 0{Left 2}+{Left 6}
::psx::{!}process @$proc 1{Left 2}+{Left 6}
::vd::{!}vad{Space}
::prp::
clipboard := "set_clip(r'''.process /r /p '''+r'''" clipboard "'''.strip().split()[-1])"
pyw_exec_wait()
clip_check_op()
SendInput, {Text}%clipboard%
clip_check_ed()
return
::pri::
clipboard := "set_clip(r'''.process /i '''+r'''" clipboard "'''.strip().split()[-1])"
pyw_exec_wait()
clip_check_op()
SendInput, {Text}%clipboard%
clip_check_ed()
return
::sen::{!}session{Space}
::sprr::{!}sprocess{Space}
::prr::{!}process{Space}
::pra::{!}process 0 0{Left 2}
::tr::.thread{Space}
::trr::{!}thread{Space}
::cdb::.childdbg 1+{Left}
::tk::{!}token{Space}
::re::.restart
::rld::.reload{Space}
::rlu::.reload /user{Space}
::ldx::.reload /u{Space}
::noi::{!}sym noisy{Space}
::qui::{!}sym quiet{Space}
::pth::.sympath{Space}
::sym::srv*c:\Symbols*http://msdl.microsoft.com/download/symbols`;{Left 44}+{Left 10}
::md::lmona (@$ip){Left 1}+{Left 4}
::gf::{!}gflag{Space}
:T:bc::.foreach /pS 1 (place {dp /c5 NT!KiBugCheckData L5}) {.printf "0x%x ", ${place}};.printf "\n"
::alv::.reload{;}{!}analyze -v
::als::{!}analyze -show{Space}
::pl::{!}pool{Space}
::pf::{!}poolfind{Space}
::pu::{!}poolused{Space}
::pup::{!}poolused 4{Space}
::pun::{!}poolused 2{Space}
::pte::{!}pte{Space}
::pfn::{!}pfn{Space}
::tp::.trap{Space}
::ob::{!}object{Space}
::drv::{!}drvobj  7{Left 2}
::hdl::{!}handle{Space}
::dev::{!}devobj{Space}
::xnd::x ntdll{!}**{Left 1}
::nd::ntdll{!}
::xker::x kernel32{!}**{Left 1}
::ker::kernel32{!}
::xkeb::x kernelbase{!}**{Left 1}
::keb::kernelbase{!}
::xnt::x nt{!}**{Left 1}
::nt::nt{!}
::xuer::x user32{!}**{Left 1}
::uer::user32{!}
::xwk::x win32k{!}**{Left 1}
::wk::win32k{!}
::xwb::x win32kbase{!}**{Left 1}
::wb::win32kbase{!}
::xwf::x win32kfull{!}**{Left 1}
::wf::win32kfull{!}
::xsk::x ws2_32{!}**{Left 1}
::sk::ws2_32{!}

::pid::?@$tpid
::tid::?@$tid
::k::@$csp
::i::@$ip
::r::@$ra
::t::@$t
::etr::@$exentry

::hplk::_HEAP_LIST_LOOKUP
::lfh::_LFH_HEAP
::le::_LIST_ENTRY
::sle::_SINGLE_LIST_ENTRY
::kp::_KPROCESS
::kt::_KTHREAD
::ep::_EPROCESS
::et::_ETHREAD
::wt::_W32THREAD
::kc::_KPCR
::kcb::_KPRCB 
::peb::_PEB
::teb::_TEB
::tib::_NT_TIB
::hep::_HEAP
::hps::_HEAP_SEGMENT
::hpe::_HEAP_ENTRY
::hpfe::_HEAP_FREE_ENTRY
::hpue::_HEAP_UNPACKED_ENTRY
::tok::_TOKEN
::tf::_KTRAP_FRAME
::er::_EXCEPTION_RECORD
::err::_EXCEPTION_REGISTRATION_RECORD
::ph::_POOL_HEADER
::oh::_OBJECT_HEADER
::ohq::_OBJECT_HEADER_QUOTA_INFO
::ot::_OBJECT_TYPE
::oti::_OBJECT_TYPE_INITIALIZER
::ott::ObTypeIndexTable
::ptag::PoolHitTag
::pins::ExpInsertPoolTracker
::prm::ExpRemovePoolTracker
::irpsp::_IO_STACK_LOCATION
::irp::_IRP
::mdl::_MDL
::apch::_KAPC_STATE
::apc::_KAPC

<!LCtrl Up::
SendInput, !{Del}
return

!`;::
SendInput, !1{Esc}
return

<^LAlt::
Send, !er
WinActivateBottom, ahk_exe notepad++.exe
SendInput, ^n^v
return

!c::
SendInput, {RButton}c

;windbgext- idasync-
::ida::.load D:\tools\bin\Lib\extension\windbg\ida_sync\x86\sync.dll`;{!}sync `;{!}idblist
::idax::.load D:\tools\bin\Lib\extension\windbg\ida_sync\x64\sync.dll`;{!}sync `;{!}idblist
::ids::{!}sync{Space}
::idx::{!}syncoff{Space}
::idh::{!}synchelp{Space}
::idls::{!}idblist{Space}
::idg::{!}jmpto{Space}
::idc::{!}bc on
::idcx::{!}bc off
::idsm::{!}syncmodauto on{Space}
::idsmx::{!}syncmodauto off{Space}
#IfWinActive

;----------------------------------------------------------------------
;code-片段

::lcip::
SendInput, 127.0.0.1
return

<!RShift::SendInput, (){Left 1}
::zz::set_clip(){Left 1}
::en::set_clip(en()){Left 2}
::enr::sset(get_clip())
::ens::sset(get_clip(), 0)
;----------------------------------------------------------------------
;nasm-汇编语言相关命令

#IfWinActive ahk_group terminal
::pe::nasm -f win32{Space}
::pex::nasm -f win64{Space}
::elf::nasm -f elf32{Space}
::elfx::nasm -f elf64{Space}
::gle::GoLink /entry main{Space}
::glc::GoLink /console /entry main{Space}
::gld::GoLink /dll /export{Space}
#IfWinActive
;----------------------------------------------------------------------
;sys- SysInternal常用命令

#IfWinActive ahk_group terminal
;Ps Tools
::pse::psexec.exe -d -i -s cmd.exe
::psl::pslist.exe{Space}
::pss::pssuspend.exe{Space}
::psr::pssuspend.exe -r{Space}

::xdl::listdlls.exe{Space}
::xpl::pipelist.exe{Space}
::xvm::vmmap.exe -p{Space}
::xhd::handle.exe{Space}
::xs::strings.exe -o{Space}
::xsg::sigcheck.exe{Space}
::xdm::procdump.exe{Space}
::xdma::procdump.exe -accepteula -ma  @@@tmp@@@.dmp{Left 14}
::xmd::tasklist.exe /M:
::xkd::cd /d D:\tools\re\WinDbg\x64 && livekd.exe -w windbg.exe

::xreg::
Run, %SCOOP_ROOT%\apps\sysinternals\current\regjump.exe -c
return
::xtcp::
Run, %SCOOP_ROOT%\apps\sysinternals\current\tcpview64.exe
return
::xpm::
Run, %SCOOP_ROOT%\apps\sysinternals\current\Procmon64.exe
return
::xps::
Run, %SCOOP_ROOT%\apps\sysinternals\current\procexp64.exe
return
::xatr::
Run, %SCOOP_ROOT%\apps\sysinternals\current\autoruns64.exe
return
::xdv::
Run, %SCOOP_ROOT%\apps\sysinternals\current\dbgview64.exe
return
::xob::
Run, %SCOOP_ROOT%\apps\sysinternals\current\winobj64.exe
return
#IfWinActive 
;----------------------------------------------------------------------
;dbi- fuzz-

#IfWinActive ahk_group terminal
;frida-
::faver::frida --version
::fawver::
SendInput, %A_ScriptDir%\..\..\utils\python3.7.4\Scripts\frida.exe --version
return
::fa::frida{Space}
::faw::
SendInput, %A_ScriptDir%\..\..\utils\python3.7.4\Scripts\frida.exe{Space}
return
::ft::frida-trace{Space}
::ftw::
SendInput, %A_ScriptDir%\..\..\utils\python3.7.4\Scripts\frida-trace.exe -O "%A_WorkingDir%\@@@txt@@@"{Space}
return
::fcv::p D:\tools\bin\Lib\frida\frida-drcov.py{Space}

;dr-
::drcv::D:\tools\re\DynamoRIO\bin32\drrun.exe -t drcov --{Space}
::drcvx::D:\tools\re\DynamoRIO\bin64\drrun.exe -t drcov --{Space}
::drc::D:\tools\re\DynamoRIO\bin32\drrun.exe -c{Space}
::drcx::D:\tools\re\DynamoRIO\bin64\drrun.exe -c{Space}
#IfWinActive
;----------------------------------------------------------------------
;prox-常用proxy设置命令

#IfWinActive ahk_group terminal
::lpx::export ALL_PROXY=socks5://
::wpx::set https_proxy=socks5://127.0.0.1:1080 & set http_proxy=socks5://127.0.0.1:1080
::spx::reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d  /f{Left 3}
::lpc::proxychains4{Space}
::lpcx::
SendInput, {TEXT}echo H4sIANlbI2MC/ysuKcpMLolPzkjMzOMqKMqvqIxPySvmKkrNzS9JBTHji0uT8lJLFIyMTLhKkgvii1ITU+JLMnNT4/NLSxQMTQ0MDMDiyfl5ealAk+BSFiCZ6ACQkT6ZxSWxAInSm/BqAAAA | base64 -d  | gzip -d | sed -r "s/^(\[ProxyList\])\s*$/\1\nsocks5  1080/g" > /etc/proxychains4.conf
SendInput, {Left 33}
return
::wpc::proxychains{Space}
#IfWinActive
;----------------------------------------------------------------------
;gen-linux & windows通用命令

#IfWinActive ahk_group common_shell
::dns::nslookup{Space}
::ipx::curl www.httpbin.org/ip
::fz:: | clip.exe
::zt::powershell.exe Get-Clipboard{Space}
#IfWinActive
;----------------------------------------------------------------------
;win-常用命令

#IfWinActive ahk_exe cmd.exe
::ce::type @@@bin@@@ > shell_.exe
::ee::wsl ./@@@bin@@@{Space}
::cex::del shell_.exe
#IfWinActive

#IfWinActive ahk_exe cmd.exe
::cxw::
clipboard := "
(
path = r'''" clipboard " '''

try:
    path = wcx(path)[0]
    if isdir(path):
        set_clip(path)
    elif isfile(path):
        set_clip(dirname(path))
    else:
        set_clip('Error File Path!')
except:
    set_clip('Error File Path!')
)"
pyw_exec_wait()
SendInput, {TEXT}cd /d "%clipboard%"
return

#IfWinActive ahk_exe powershell.exe
::cxw::
clipboard := "
(
path = r'''" clipboard " '''

try:
    path = wcx(path)[0]
    if isdir(path):
        set_clip(path)
    elif isfile(path):
        set_clip(dirname(path))
    else:
        set_clip('Error File Path!')
except:
    set_clip('Error File Path!')
)"
pyw_exec_wait()
SendInput, {TEXT}cd "%clipboard%"
return

#IfWinActive ahk_group win_shell
::rex::
RunWait, %A_ScriptDir%\..\..\utils\TotalCMD64\Totalcmd64.exe /O /T ::{645FF040-5081-101B-9F08-00AA002F954E}
return
::rec::
RunWait, cmd.exe /c "echo Y|PowerShell.exe -NoProfile -Command Clear-RecycleBin"
return
::wsh::powershell.exe{Space}
::wim::Import-Module{Space}
::wls::Get-Module{Space}
::kied::taskkill.exe /f /im notepad.exe{Space}
::kiwd::taskkill.exe /f /im windbg.exe{Space}
::kicm::taskkill.exe /f /im cmd.exe{Space}
::kicx::taskkill.exe /f /im powershell.exe{Space}
::kihh::taskkill.exe /f /im hh.exe{Space}
::whow::whoami.exe /all
::kiw::taskkill.exe /f /im{Space}
::kitw::taskkill.exe /t /f /im{Space}
::fnw::netstat.exe -ano{Space}
::fpw::tasklist.exe /svc{Space}
::zmw::cd /d C:/Users/%username%/Desktop{Space}
::fpwx::wmic.exe process get SessionId,ProcessID,ExecutablePath,commandline,caption /value{Space}

::ww:: | wsl.exe {Space}
::wfl::dir /s /b /a:
::ws:: | findstr.exe /i ""{Space}{Left 2}
::wsv:: | findstr.exe /V /i ""{Space}{Left 2}
::wss:: | peco --rcfile D:\tools\bin\peco.cfg{Space}
::pwd::echo %cd% | clip.exe

::sck::driverquery.exe{Space}
::scls::sc.exe query type= service{Space}
::sclx::sc.exe query type= service state= inactive{Space}
::scla::sc.exe query type= service state= all{Space}
::sckls::sc.exe query type= driver{Space}
::scklx::sc.exe query type= driver state= inactive{Space}
::sckla::sc.exe query type= driver state= all{Space}
::scop::sc.exe start{Space}
::sced::sc.exe stop{Space}
::sci::sc.exe create XDriver binPath= "" type= kernel start= demand{Space}{Home}{Right 32}
::scu::sc.exe delete{Space}
#IfWinActive
;----------------------------------------------------------------------
;wsl-常用命令
;1. dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
;2. dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
;3. DISM /Online /Enable-Feature /All /FeatureName:Microsoft-Hyper-V
;wsl_1 运行 1; wsl_2 运行 1, 2; Hyper-V 运行3

#IfWinActive ahk_group wsl_shell
::wsip::$(grep -m 1 nameserver /etc/resolv.conf | awk '{{}print $2{}}')

::cx::
clipboard := "
(
path = r'''" clipboard " '''

try:
    path = wcx(path)[0]
    if isdir(path):
        set_clip(lcx(path)[0])
    elif isfile(path):
        set_clip(lcx(dirname(path))[0])
    else:
        set_clip('Error File Path!')
except:
    set_clip('Error File Path!')
)"
pyw_exec_wait()
SendInput, {TEXT}cd "%clipboard%"
return

::lcc::
clipboard := "
(
path = r'''" clipboard " '''

try:
    set_clip(lcx(path)[0])
except:
    set_clip('Error File Path!')
)"
pyw_exec_wait()
SendInput, {TEXT}'%clipboard%'
return

::mmx::'/mnt/x'
::mmz::'/mnt/z'
::mmc::'/mnt/c'
::mmd::'/mnt/d'
::mme::'/mnt/e'
::mmf::'/mnt/f'
::mnt::read mnt_drive;sudo mount -t drvfs $mnt_drive: /mnt/$mnt_drive
::umnt::read mnt_drive;sudo umount /mnt/$mnt_drive

::zk::powershell.exe Get-Clipboard | sed 's/\r//g' | awk ''{Space}{Left 2}
::zf::powershell.exe Get-Clipboard | sed 's/\r//g' | awk -F '' ''{Left 4}
::ztm::my_tmp_var=$(powershell.exe Get-Clipboard | sed 's/\r//g')
::dfx::diff <(echo -E $my_tmp_var) <(powershell.exe Get-Clipboard | sed 's/\r//g') --color=auto{Space}
::dfo::diff <(echo -E $my_tmp_var) <(powershell.exe Get-Clipboard | sed 's/\r//g') --color=auto --suppress-common-lines -y{Space}
::zrn::
clipboard := "
(
paths = r'''" clipboard " '''

try:
    set_clip(en(lcx(paths)))
except:
    set_clip('Error File List!')
)"
pyw_exec_wait()
SendInput, {Text}powershell.exe Get-Clipboard | sed 's/\r//g' | awk 'NF>0 {print $0}'
SendInput, {Space}
return

::rb::
clipboard := "'cat ""' + lcx(os.path.join(os.path.expanduser(""~""), 'Desktop', '@@@bin@@@'))[0] + '"" '"
pyw_eval()
SendInput, {TEXT}%clipboard%
return

::wb::
::wtb::
clipboard := "' > ""' + lcx(os.path.join(os.path.expanduser(""~""), 'Desktop', '@@@bin@@@'))[0] + '"" '"
pyw_eval()
SendInput, {TEXT}%clipboard%
return

::wsx::lxrunoffline{Space}

::wsls::wsl.exe --list --verbose{Space}
::wsud::wsl.exe --update{Space}
::wski::wsl.exe -t{Space}
::wskix::wsl.exe --shutdown{Space}
::wshh::wsl.exe --help{Space}
::wshlp::wsl.exe --help{Space}
::wscx::wsl.exe --set-default{Space}
::wsps::wsl.exe -l --running{Space}
::wsim::wsl.exe --import{Space}
::wsim1::wsl.exe --import ubuntu_1 D:\ubuntu_1 ubuntu_1.tar
::wsim2::wsl.exe --import ubuntu_2 D:\ubuntu_2 ubuntu_2.tar
::wsimka::wsl.exe --import kali-linux D:\kali-linux kali-linux.tar
::wsst::wsl.exe --set-version{Space}
::wssd::wsl.exe --set-default-version{Space}
::wsu::wsl.exe --unregister{Space}
::wsex::
clipboard := "r'''" clipboard "'''.strip()"
pyw_eval()
SendInput, wsl.exe --export %clipboard% %clipboard%.tar
return
#IfWinActive
;----------------------------------------------------------------------
;emacs- doom-

#IfWinActive ahk_exe vcxsrv.exe
<^LAlt::
clipboard := "
(
data = r'''" clipboard " '''

try:
    path = wcx(data)[0]
    if isdir(path):
        set_clip(lcx(path)[0])
    elif isfile(path):
        set_clip(lcx(dirname(path))[0])
    else:
        set_clip('Error File List!')
except:
    set_clip('Error File List!')
)"
pyw_exec_wait()
SendInput, ^g^g:cd^y{Enter}
return

<!RAlt::^!h

XButton1::SendInput, {#}zz
XButton2::SendInput, *zz

#c::
SendInput, {Click 2}y
return

#IfWinActive ahk_group wsl_shell
::dmhh::~/.emacs.d/bin/doom help{Space}
::dmhlp::~/.emacs.d/bin/doom help{Space}
::dms::~/.emacs.d/bin/doom sync{Space}
::dmug::~/.emacs.d/bin/doom upgrade{Space}
::dmchk::~/.emacs.d/bin/doom doctor{Space}
::dmrm::~/.emacs.d/bin/doom purge{Space}
::dmbd::~/.emacs.d/bin/doom build{Space}
;----------------------------------------------------------------------
;lix-常用命令

#IfWinActive ahk_group lix_shell
::aslr::cat /proc/sys/kernel/randomize_va_space
::aslrx::echo 0 > /proc/sys/kernel/randomize_va_space{Home}{Right 6}
::tre::tree -f -P "*"{Space}{Left 2}
::trec::tree -f -P "*.cpp|*.c++|*.cxx|*.hpp|*.hh|*.h++|*.hxx|*.c|*.cc|*.h"{Space}
::dif::diff{Space}
::hh::--help{Space}
::hlp::--help{Space}
::fp::ps -e | egrep --color=auto -i ""{Space}{Left 2}
::fpx::ps -ef | egrep --color=auto -i ""{Space}{Left 2}
::cps::cd /proc/$(echo ){Left 1}
::fn::netstat -tuanp | egrep --color=auto -i ""{Left 1}
::ki::kill -9{Space}
::kin::pkill{Space}
::lc::locate -i -e --regex ""{Left 1}
::lcud::updatedb{Space}
::cxl::
clip_check_op()
SendInput, {TEXT}if [ -d "%clipboard%" ];then cd "%clipboard%";else cd "$(dirname "%clipboard%")"; fi; pwd;
clip_check_ed()
return
::ct:: | xargs -r -d '\n' cat{Space}
::wtx::
clip_check_op()
clipboard := "lcx(r'''" clipboard "''')[0]"
pyw_eval()
SendInput, watch -n 0.1 "cat \"%clipboard%\" | nl | tail -n 50"
clip_check_ed()
return
::wt::watch -n 0.1 ""{Space}{Left 2}
::hd:: | head{Space}
::tl:: | tail{Space}
::bh:: | xxd -p | tr -d '\n'{Space}
::hb:: | xxd -r -p{Space}
::e64:: | base64 | tr -d '\n'{Space}
::d64:: | base64 -d{Space}
::ezi:: | gzip -f{Space}
::dzi:: | gzip -d{Space}
::dn::
SendInput, dirname ""{Space}{Left 2}
return
::dnx::
SendInput, {Space}| xargs -r -d '\n' dirname{Space}
return
::bn::
SendInput, basename ""{Space}{Left 2}
return
::bnx::
SendInput, {Space}| xargs -r -d '\n' basename -a{Space}
return
::un:: | sort | uniq{Space}
::uni:: | uniq{Space}
::st:: | sort{Space}
::re:: | rev{Space}
::wc:: | wc{Space}
::te:: | tee{Space}
::ar:: | xargs -r{Space}
::arn:: | xargs -r -d '\n'{Space}
::ari:: | xargs -r -d '\n' -I{Space}
::7z:: | xargs -r -d '\n' -I xxx 7z x -aou -o"xxx@" "xxx"
::md5:: | xargs -r -d '\n' md5sum -b{Space}
::sha1:: | xargs -r -d '\n' sha1sum -b{Space}
::sha256:: | xargs -r -d '\n' sha256sum -b{Space}
::cp:: | xargs -r -d '\n' -i cp -r {{}{}}{Space}
::cpx:: | xargs -r -d '\n' realpath --relative-to=$(pwd) | cpio -pdm{Space}
::mv:: | xargs -r -d '\n' -i mv {{}{}}{Space}
::rm:: | xargs -r -d '\n' rm -rf{Space}
::tm::{Home}my_tmp_var=$({End}){Space}
::tmx::echo -E $my_tmp_var{Space}
::a3::-A3
::b3::-B3
::c3::-C3
::s:: | egrep --color=auto "" -i{Left 4}
::sv:: | egrep --color=auto -v "" -i{Left 4}
::so:: | egrep --color=auto -o "" -i{Left 4}
::sx:: | xargs -r -d '\n' egrep --color=auto -i -r -n ""{Space}{Left 2}
::sxl:: | xargs -r -d '\n' egrep --color=auto -i -r -l ""{Space}{Left 2}
::sxv:: | xargs -r -d '\n' egrep --color=auto -i -r -L ""{Space}{Left 2}
::rel:: | xargs -r -d '\n' realpath --relative-to=$(pwd){Space}
::abs:: | xargs -r -d '\n' realpath{Space}
::dl::find "$(pwd)" -mindepth 1 -maxdepth 1 -type d | egrep --color=auto -i ""{Space}{Left 2}
::dlr::find "$(pwd)" -type d | egrep --color=auto -i ""{Space}{Left 2}
::flr::find "$(pwd)" -type f | egrep --color=auto -i ""{Space}{Left 2}
::flrv::find "$(pwd)" -type f | egrep --color=auto -i -v ""{Space}{Left 2}
::fl::find "$(pwd)" -mindepth 1 -maxdepth 1 | egrep --color=auto -i ""{Space}{Left 2}
::flv::find "$(pwd)" -mindepth 1 -maxdepth 1 | egrep --color=auto -i -v ""{Space}{Left 2}
::flx::find "$(pwd)" -mindepth 1 -maxdepth 1 | xargs -r -d '\n' file  | egrep --color=auto -i ""{Space}{Left 2}
::flxv::find "$(pwd)" -mindepth 1 -maxdepth 1 | xargs -r -d '\n' file  | egrep --color=auto -i -v ""{Space}{Left 2}
::flrx::find "$(pwd)" -type f | xargs -r -d '\n' file | egrep --color=auto -i ""{Space}{Left 2}
::flrxv::find "$(pwd)" -type f | xargs -r -d '\n' file | egrep --color=auto -i -v ""{Space}{Left 2}
::fil:: | xargs -r -d '\n' file  | egrep --color=auto -i ""{Space}{Left 2}
::flrc::find "$(pwd)" -type f | egrep --color=auto -i "\.cpp$|\.c\{+}\{+}$|\.cxx$|\.hpp$|\.hh$|\.h\{+}\{+}$|\.hxx$|\.c$|\.cc$|\.h$"{Space}
::flrj::find "$(pwd)" -type f | egrep -i "\.jsp$|\.jspx$|\.java$|\.class$"{Space}
::nm::
SendInput, {Text} | awk -F ':' '/^(\/[^\/:]+)+/ {print $1}' | awk '$1=$1' | sort | uniq
SendInput, {Space}
return
::ake::
SendInput, {Text}{print $()}
SendInput, {Left 2}
return
::akee::
SendInput, {Text}{print $(NF)}
SendInput, {Left 2}
return
::akb::BEGIN{{}{}}{Left}
::ak:: | awk ''{Space}{Left 2}
::akf:: | awk -F '' ''{Left 4}
::aks:: | sed 's/\r//g' | awk '$1=$1'{Space}
::akr::
SendInput, {Text} | sed 's/\r//g' | awk 'NF>0 {print $0}'
SendInput, {Space}
return
::bb::
SendInput, {Text} | sed 's/\r//g' | awk 'BEGIN{tmp="";IGNORECASE=1;} {if(match($0, /^--|^==|----|====/)){if(match(tmp, //))print tmp$0;tmp="";}else{tmp=tmp$0"\n";}}'
SendInput, {Space}{Left 46}
return
::bv::
SendInput, {Text} | sed 's/\r//g' | awk 'BEGIN{tmp="";IGNORECASE=1;} {if(match($0, /^--|^==|----|====/)){if(!match(tmp, //))print tmp$0;tmp="";}else{tmp=tmp$0"\n";}}'
SendInput, {Space}{Left 46}
return
::rn:: | sed 's/\r//g'{Space}
::cm::chmod {+}777 -R{Space}
::ic:: | iconv -f GBK -t UTF-8{Space}
::bs::strings -tx{Space}
::bsx:: | xargs -r -d '\n' strings -tx -f{Space}
::tsa::find "$(pwd)" -mindepth 1 -maxdepth 1 | xargs -r -d '\n' egrep --color=auto -i -r -I -n ""{Space}{Left 2}
::bsa::find "$(pwd)" -type f | xargs -r -d '\n' strings -tx -f{Space}
::nl:: | nl{Space}
::fe::fg emacs

::ss:: | fzf
::lss:: | peco --rcfile /mnt/d/tools/bin/peco.cfg{Space}
::fr::"$(find "$(pwd)" -type f | fzf --preview 'cat -n  {{}{}}')"{Space}
::fd::"$(find "$(pwd)" -type d | fzf)"{Space}
::f::"$(pwd)$(echo /)$(ls -a | fzf --preview 'cat -n  {{}{}}')"{Space}
::ff::cat -n "$(pwd)$(echo /)$(ls -a | fzf --preview 'cat -n  {{}{}}')"{Space}
::hx::echo -E $(history | fzf) | sed 's/{^}[0-9]*//'{Space}

::man::tldr{Space}
::cman::cppman{Space}
::dman:: | xargs -r dman{Space}
#IfWinActive
;----------------------------------------------------------------------
; alt- update-alt-

#IfWinActive ahk_group lix_shell
::altls::update-alternatives --list{Space}
::altlsc::update-alternatives --get-selections{Space}
::altad::update-alternatives --install{Space}
::altrm::update-alternatives --remove{Space}
::altrmx::update-alternatives --remove-all{Space}
::altcfg::update-alternatives --config{Space}
#IfWinActive
;----------------------------------------------------------------------
; sc- search code

#IfWinActive ahk_group lix_shell
::scc::calltree.pl '' '' 0 1 3{Space}{Left 11}
::scr::calltree.pl '' '' 1 1 3{Space}{Left 11}
::sct::cpptree.pl '' '' 1 3{Space}{Left 9}
::sjc::java_calltree.pl '' '' 0 1 3{Space}{Left 11}
::sjr::java_calltree.pl '' '' 1 1 3{Space}{Left 11}
::sjt::javatree.pl '' '' 1 3{Space}{Left 9}
::scdr::deptree.pl '' '' 1 1 3{Space}{Left 11}
::scd::deptree.pl '' '' 0 1 3{Space}{Left 11}
:T:srm::find "$(pwd)" -type f | egrep --color=auto -i "tree\.result\.cached\." | xargs -r -d '\n' rm -rf
#IfWinActive
;----------------------------------------------------------------------
;cfg-

#IfWinActive ahk_group terminal
;lixcfg- linux 配置文件编辑
::edlpc::vi /etc/proxychains4.conf
::edapt::vi /etc/apt/sources.list
::edhst::vi /etc/hosts

;wincfg- windows 配置文件编辑
::edwpc::ed %SCOOP%\apps\proxychains\current\proxychains.conf
::edhstw::ed %SystemRoot%\system32\drivers\etc\hosts
#IfWinActive
;----------------------------------------------------------------------
;pentest- test- 渗透测试原语

;wtest- windows 下的渗透测试原语
#IfWinActive ahk_group terminal
:T:xwwifi::for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear
::xwdh::certutil -f -decodehex{Space}
::xweh::certutil -f -encodehex{Space}
::xwd64::certutil -f -decode{Space}
::xwe64::certutil -f -encode{Space}
#IfWinActive
;----------------------------------------------------------------------
;tmux-常用命令

#IfWinActive ahk_group terminal
!,::SendInput, ^b!{Up}
!.::SendInput, ^b!{Down}
!u::SendInput, ^b!{Left}
!o::SendInput, ^b!{Right}
!q::SendInput, ^bq
!w::SendInput, ^bw
::m::tmux{Space}
!n::SendInput, ^bn
!p::SendInput, ^bp
!`;::SendInput, ^b`%
!h::SendInput, ^b"
!k::SendInput, ^b{Down}
!i::SendInput, ^b{Up}
!j::SendInput, ^b{Left}
!l::SendInput, ^b{Right}
::mat::
SendInput, tmux attach -t{Space}
return
::mls::
SendInput, tmux ls
return
::mks::
SendInput, tmux kill-session -t{Space}
return
::mns::
SendInput, tmux new -s{Space}
return
#IfWinActive
;----------------------------------------------------------------------
;openssl- ssl- ssh- git- 常用命令
#IfWinActive ahk_group common_shell
::sshk::ssh-keygen -t rsa -b 2048 -C ""{Left 1}
::ssht::ssh -T git@github.com

::gipx::git config --global http.proxy http://127.0.0.1:1080
::girn::git config --global core.autocrlf false
::gig::git config --global{Space}
::gigls::git config --global --list
::gigrm::git config --global --unset{Space}
::gil::git config --local{Space}
::gills::git config --local --list
::gigc::git gc --prune=now{Space}
::gilg::git log{Space}
::giad::git add .
::gist::git status{Space}
::gizz::git stash push{Space}
::gizp::git stash pop{Space}

;查看PEM
::sslp::openssl x509 -text -noout -in{Space}

;查看DER
::ssld::openssl x509 -inform der -text -noout -in{Space}

;PEM转DER
::ssl2d::openssl x509 -outform der -in{Space}

;DER转PEM
::ssl2p::openssl x509 -inform der -outform pem -in{Space}
#IfWinActive
;----------------------------------------------------------------------
;docker-常用命令

#IfWinActive ahk_group terminal
::dkver::docker version
::dkinf::docker info
::dkop::sudo service docker start
::dked::sudo service docker stop
::dks::docker search{Space}
::dkit::docker exec -it  /bin/bash{Left 10}
::dcls::docker container ls{Space}
::dcla::docker container ls --all{Space}
::dcst::docker container start{Space}
::dclg::docker container logs{Space}
::dccp::docker container cp{Space}
::dcki::docker container stop{Space}
::dckix::docker container kill{Space}
::dcr::docker container run{Space}
::dcrrm::docker container run --rm{Space}
::dcrit::docker container run -it{Space}
::dcrm::docker container rm{Space}
::dce::docker container exec{Space}
::dils::docker image ls{Space}
::dirm::docker image rm -f{Space}
::dipl::docker image pull{Space}
::dibd::docker image build -t  .{Left 2}
#IfWinActive
;----------------------------------------------------------------------
;go-常用命令

#IfWinActive ahk_group terminal
;GOOS：目标平台的操作系统(darwin、freebsd、linux、windows)
;GOARCH：目标平台的体系架构(386、amd64、arm)
::gow::CGO_ENABLED=0 GOOS=windows GOARCH=386{Space}
::gowx::CGO_ENABLED=0 GOOS=windows GOARCH=amd64{Space}
::gol::CGO_ENABLED=0 GOOS=linux GOARCH=386{Space}
::golx::CGO_ENABLED=0 GOOS=linux GOARCH=amd64{Space}
::godl::go build -buildmode=c-shared{Space}
::gobd::go build{Space}
#IfWinActive
;----------------------------------------------------------------------
;java-常用命令 idea-代码块补全

#IfWinActive ahk_group terminal
::j8w::
SendInput, set path="%java8_path%"`;`%path`%
return
::j11w::
SendInput, set path="%java11_path%"`;`%path`%
return
::j17w::
SendInput, set path="%java17_path%"`;`%path`%
return
::jcls::java -verbose:class{Space}
#IfWinActive
;----------------------------------------------------------------------
;msvc-常用命令和代码片段

::vclib::
clipboard =
(
#pragma comment(lib, "")
)
return

::vcex::
clipboard =
(
__declspec(dllexport)
)
return

::vcexc::
clipboard =
(
extern "C" __declspec(dllexport)
)
return

::vcim::
clipboard =
(
__declspec(dllimport)
)
return

::vcimc::
clipboard =
(
extern "C" __declspec(dllimport)
)
return

::vcc::
clipboard =
(
extern "C"
)
return

::vcsec::
clipboard =
(
#pragma section(".mem")
__declspec(allocate(".mem"))
UCHAR mem_buf[0x30000];
#pragma comment(linker, "/SECTION:.mem,RWEP")
)
return

::vcfw::
clipboard =
(
#pragma comment(linker, "/export:api=dll.api, @ord")
)
return

::vcb::
clipboard =
(
__debugbreak();
)
return

;winmake-常用命令
#IfWinActive ahk_group terminal
::mgw::set PATH=%scoop%\apps\mingw-winlibs\current\bin;%PATH%
::mgb::mingw32-make.exe{Space}
::vcd::cl.exe /Zi /LD{Space}
::vcdu::cl.exe /Zi /LD /D "_UNICODE" /D "UNICODE"{Space}
::vcx::cl.exe /Zi{Space}
::vcxu::cl.exe /Zi /D "_UNICODE" /D "UNICODE"{Space}
::msb::msbuild -p:configuration="release"{Space}
::msba::msbuild -p:configuration="release" ALL_BUILD.vcxproj{Space}
::winb::cmake . -G "NMake Makefiles" -Bbuild -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=True -DCMAKE_USER_MAKE_RULES_OVERRIDE=D:\tools\bin\Lib\build\c_cpp\cmake\msvc_static_link_flag.cmake && cd build && nmake
#IfWinActive
;----------------------------------------------------------------------
;cmake-常用命令
#IfWinActive ahk_group terminal
::cmk::md build && cd build && cmake ..{Space}
;----------------------------------------------------------------------
;xmake- 常用命令
#IfWinActive ahk_group terminal
::xm::xmake{Space}
::xmh::xmake --help{Space}
::xmb::xmake -rv{Space}
::xmc::xmake clean{Space}
::xmn::xmake create{Space}
::xmnh::xmake create --help{Space}
::xmne::xmake create -t console{Space}
::xmns::xmake create -t static{Space}
::xmnd::xmake create -t shared{Space}
::xmnt::xmake create -t{Space}
::xms::xmake show{Space}
::xmsh::xmake show --help{Space}
::xmsl::xmake show -l{Space}
::xmst::xmake show -t{Space}
::xmr::xmake run{Space}
::xmf::xmake config{Space}
::xmim::xmake f --import=
::xmex::xmake f --export=
::xmg::xmake global{Space}
::xmrd::xmake run -d{Space}
::xmug::xmake update{Space}
::xmdb::xmake project -k compile_commands

::xr::xrepo{Space}
::xrh::xrepo --help{Space}
::xrc::xrepo clean{Space}
::xrbls::xrepo list-repo{Space}
::xrbad::xrepo add-repo{Space}
::xrbrm::xrepo rm-repo{Space}
::xrbud::xrepo update-repo{Space}
::xrbug::xrepo update-repo{Space}
::xri::xrepo install{Space}
::xru::xrepo remove{Space}
::xrs::xrepo search{Space}
::xrim::xrepo import{Space}
::xrex::xrepo export{Space}
::xrls::xrepo scan{Space}
::xrinf::xrepo info{Space}

::xmgw::--mingw=%SCOOP%\apps\mingw-winlibs\current
::xpx::--proxy=socks5://127.0.0.1:1080
#IfWinActive
;----------------------------------------------------------------------
;binutils常用命令

#IfWinActive ahk_group terminal
::dbin::dumpbin.exe{Space}
::dbld::dumpbin.exe /LOADCONFIG ""{Left 1}
::dbim::dumpbin.exe /IMPORTS ""{Left 1}
::dbex::dumpbin.exe /EXPORTS ""{Left 1}
::dbdp::dumpbin.exe /DEPENDENTS ""{Left 1}
#IfWinActive
;----------------------------------------------------------------------
;vim-常用命令 vi-

#IfWinActive ahk_group terminal
::vizt::powershell.exe Get-Clipboard  | sed 's/\r//g' | vi -{Space}
::vixd::%{!}xxd -g 1
::vixdr::%{!}xxd -r
::vif::set ft=
::viex::Explore
::vi:: | xargs -r -d '\n' -o vi{Space}
::nu::set nu
#IfWinActive
;----------------------------------------------------------------------
;ida-常用脚本

#IfWinActive ahk_group ida
::ida::(r'D:\tools\bin\Lib\ida' not in sys.path) and sys.path.insert(0, r'D:\tools\bin\Lib\ida');import idabase,importlib;importlib.reload(idabase);from idabase import *;
::it::it().
::fn::fn().
::b::bb().
::v::va(cea()).
::sg::seg().
::vs::rva_to_va(){Left 1}
::vl::set_act_va_list(){Left 1}
::ol::set_act_va_list(off_to_va()){Left 2}
::rvl::set_act_va_list(rva_to_va()){Left 2}
::rvk::set_act_va_list(rva_to_va_with_adjust_call_site()){Left 2}
::bb::set_act_bb_trace(){Left 1}
::wtr::set_act_bb_trace(wt_reg, ''){Left 2}
::wtv::set_act_bb_trace(wt_reg, '', True){Left 8}
::wtm::set_act_bb_trace(wt_displ, ){Left 1}
::dye::va(cea()).dye(1, 1){Left 4}+{Left 1}
::dyx::va(cea()).dye(1, 0){Left 4}+{Left 1}
::dm::
Send, !om
return
::kk::^!k
::ks::!epp
::cs::{Click}+{f9}{Ins}
!w::SendInput, !wl{Enter}
::rs::!wr{Enter}
::ld::!w{Enter}
::sv::!ws
::sop::jmp(seg().op)
::sed::jmp(seg().ed)
::st::!og
::op::fn().op.jmp
::ed::fn().ed.jmp
::nm::smart_name(){Left 1}
::rdc::va(cea()).rdi(){Left 1}
::rds::va(cea()).rdi(, 1){Left 4}
::fx::fnx()
::va::hex(here())
::rva::hex(here()-idaapi.get_imagebase())
::off::hex(va(cea()).o)
::rvx::[i.rva for i in fnx()]
::gr::jmp_rva(){Left 1}
::go::jmp_off(){Left 1}
::g::jmp(){Left}
::gg::jmp(cea(){+}){Left}
::exi::print(en(filter(lambda ent:''.strip().lower() in ent.lower(), ex.inf))){Left 43}
::imi::print(en(filter(lambda ent:''.strip().lower() in ent.lower(), im.inf))){Left 43}
::xt::print(va(cea()).xt(False, )){Left 2}
::xtl::va(cea()).xt(){Left 1}
::ixt::set_clip(va(cea()).xt(False, )){Left 2}
::ft::print(fn(cea()).xt(False, )){Left 2}
::ift::set_clip(fn(cea()).xt(False, )){Left 2}
::ftl::fn(cea()).xt(){Left 1}
::bt::print(bb(cea()).xt(False, )){Left 2}
::btl::bb(cea()).xt(){Left 1}
::ibt::set_clip(bb(cea()).xt(False, )){Left 2}
::xf::print(fn(cea()).xf()){Left 2}
::xfl::fn(cea()).xf(){Left 1}
::ff::print(fn(cea()).xf()){Left 2}
::ffl::fn(cea()).xf(){Left 1}
::bf::print(bb(cea()).xf()){Left 2}
::bfl::bb(cea()).xf(){Left 1}
::rb::
SendInput, !esr
return
::bs::idaapi.get_imagebase()
::pdb::
SendInput, !flp
return
::ifz::{Home}set_clip({End})
::izt::print(get_clip())
::ien::{Home}set_clip(en({End}))
::hx::{Home}[hex(i) for i in {End}]
::l::{Home}[ for i in {End}]{Home}{Right 1}
!`;::
SendInput, ^.{End}+{Home}{BS}
return
#c::
SendInput, {Click}^c
return
^+v::SendInput, ^.^v
<^LAlt::SendInput, ^.fn().op.jmp{Enter}{Esc}
<+LAlt::SendInput, ^+{Ins}
<+LWin::SendInput, !{f3}
::sc::exec(open(r'D:\tools\bin\Lib\ida\ida.py').read())
::z::[]{Left 1}
#IfWinActive
;----------------------------------------------------------------------
;pkg- 常见包管理器

#IfWinActive ahk_group terminal
;scoop- co-
;Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
;$env:SCOOP='D:\Scoop\Scoop'
;[Environment]::SetEnvironmentVariable('SCOOP', $env:SCOOP, 'User')
;$env:SCOOP_GLOBAL='D:\Scoop\GlobalScoopApps'
;[Environment]::SetEnvironmentVariable('SCOOP_GLOBAL', $env:SCOOP_GLOBAL, 'Machine')
;$env:SCOOP_CACHE='D:\Scoop\ScoopCache'
;[Environment]::SetEnvironmentVariable('SCOOP_CACHE', $env:SCOOP_CACHE, 'Machine')
;iwr -useb get.scoop.sh -outfile 'install.ps1'
;.\install.ps1 -RunAsAdmin

::coex::scoop export{Space}
::cors::scoop reset{Space}
::cos::scoop search{Space}
::coi::scoop install{Space}
::coix::scoop install -g{Space}
::coinf::scoop info{Space}
::cols::scoop list{Space}
::cou::scoop uninstall{Space}
::coud::scoop update{Space}
::coux::scoop uninstall -g{Space}
::cock::scoop checkup{Space}
::coh::scoop home{Space}
::cohh::scoop help{Space}
::cobk::scoop bucket known{Space}
::cobls::scoop bucket list{Space}
::cobad::scoop bucket add{Space}
::cobrm::scoop bucket rm{Space}
::cocls::scoop cache show{Space}
::cocrm::scoop cache rm{Space}
::coct::scoop cat{Space}
::cohd::scoop hold{Space}
::couhd::scoop unhold{Space}
::cowh::scoop which{Space}
::cost::scoop status{Space}
::cocr::scoop create{Space}
::cocl::scoop cleanup{Space}
::cosls::scoop shim list{Space}
::cosad::scoop shim add{Space}
::cosrm::scoop shim rm{Space}
::copx::scoop config proxy 127.0.0.1:1080

;apt- ap-
::apls::apt list --installed{Space}
::api::apt install{Space}
::apu::apt purge{Space}
::apud::apt update{Space}
::apug::apt upgrade{Space}
::aps::apt search{Space}
::apinf::apt show{Space}
::apsrc::apt edit-sources{Space}
::apkad::apt-key adv --keyserver keyserver.ubuntu.com --recv-keys{Space}
::apkls::apt-key list{Space}

;apt-get- ag-
::agi::apt-get install{Space}
::agu::apt-get purge{Space}
::agud::apt-get update{Space}
::agug::apt-get upgrade{Space}
::ags::apt-cache search{Space}
::aginf::apt-cache show{Space}

;dpkg- dg-
::dgls::dpkg -l{Space}
::dgi::dpkg -i{Space}
::dgu::dpkg -r{Space}
#IfWinActive
;----------------------------------------------------------------------
;py- python 常用命令

#IfWinActive ahk_group terminal
::ia::{!}echo "$"{Left}
::pyexe::pyinstaller -F{Space}
::pyenv::virtualenv --no-site-packages
::pyac::source ./bin/activate
::pydac::deactivate

::pys::p -m pip show --files{Space}{Home}{Right 1}
::pyo::p -m pip list --outdated{Space}{Home}{Right 1}
::pyug::p -m pip install --upgrade{Space}{Home}{Right 1}
::pyi::p -m pip install{Space}{Home}{Right 1}
::pyls::p -m pip list{Space}{Home}{Right 1}
::pyu::p -m pip uninstall{Space}{Home}{Right 1}
::pyex::p -m pip freeze > requirements.txt{Space}{Home}{Right 1}
::pyim::p -m pip install -r requirements.txt{Space}{Home}{Right 1}

::pyqh::-i https://pypi.tuna.tsinghua.edu.cn/simple{Space}
#IfWinActive
;----------------------------------------------------------------------
;js- node- nvm- npm- 常用命令

#IfWinActive ahk_group terminal
::nvi::nvm install{Space}
::nvls::nvm ls{Space}
::nvs::nvm ls-remote{Space}
::nvst::nvm use{Space}
::nvcur::nvm current{Space}
::nvpx::export NVM_NODEJS_ORG_MIRROR=https://npm.taobao.org/mirrors/node/
#IfWinActive

;java- jenv- 常用命令

#IfWinActive ahk_group terminal
::jvi::jenv add{Space}
::jvu::jenv remove{Space}
::jvls::jenv versions{Space}
::jvcur::jenv version{Space}
::jvst::jenv local{Space}
::jvstx::jenv global{Space}
#IfWinActive
;----------------------------------------------------------------------
;tcp- tcpdump常用命令

#IfWinActive ahk_group terminal
::td::tcpdump{Space}
::tdls::tcpdump -D{Space}
::tdi::tcpdump -nvvv -i{Space}
::tdx::tcpdump -nvvv -XX -i{Space}
::tda::tcpdump -nvvv -A -i{Space}
#IfWinActive
;----------------------------------------------------------------------
; neo4j- neo- gd- 图数据库neo4j相关指令

#IfWinActive ahk_group terminal
::gdi::D:\tools\utils\neo4j\bin\neo4j.bat install-service
::gdu::D:\tools\utils\neo4j\bin\neo4j.bat uninstall-service
::gdop::D:\tools\utils\neo4j\bin\neo4j.bat start
::gded::D:\tools\utils\neo4j\bin\neo4j.bat stop
::gdver::D:\tools\utils\neo4j\bin\neo4j.bat -Verbose
::gdhh::D:\tools\utils\neo4j\bin\neo4j.bat -Verbose
::gdhlp::D:\tools\utils\neo4j\bin\neo4j.bat -Verbose
::gdim::D:\tools\utils\neo4j\bin\neo4j-admin.bat load --from=./neo4j.db.dump --database=neo4j --force
::gdex::D:\tools\utils\neo4j\bin\neo4j-admin.bat dump --database=neo4j --to=./neo4j.db.dump
::gdsh::D:\tools\utils\neo4j\bin\cypher-shell.bat -u neo4j -p{Space}
#IfWinActive
;----------------------------------------------------------------------
;cs- cobaltstrike 常用命令
#IfWinActive ahk_group win_shell
::tserw::cd /d D:\tools\re\cs4 && D:\tools\re\cs4\teamserver.bat  root D:\tools\re\cs4\baidu.profile{Left 35}
;----------------------------------------------------------------------
;msf- metasploit 常用命令

#IfWinActive ahk_group terminal
;在linux shell环境中使用
;/opt/metasploit-framework/embedded/framework/modules/exploits
;/opt/metasploit-framework/embedded/framework/modules/payloads

::msf::msfconsole{Space}

::msfh::use exploit/multi/handler
::msfg::generate -f{Space}

::msfew:: | msfvenom -p - -a x86 --platform win -b "\x09\x0A\x0B\x0C\x0D\x20\x00" -f{Space}
::msfewx:: | msfvenom -p - -a x64 --platform win -b "\x09\x0A\x0B\x0C\x0D\x20\x00" -f{Space}
::msfel:: | msfvenom -p - -a x86 --platform linux -b "\x09\x0A\x0B\x0C\x0D\x20\x00" -f{Space}
::msfelx:: | msfvenom -p - -a x64 --platform linux -b "\x09\x0A\x0B\x0C\x0D\x20\x00" -f{Space}

::mwrt::windows/meterpreter_reverse_tcp
::mwrtx::windows/x64/meterpreter_reverse_tcp
::mwrh::windows/meterpreter_reverse_http
::mwrhx::windows/x64/meterpreter_reverse_http
::mwrs::windows/meterpreter_reverse_https
::mwrsx::windows/x64/meterpreter_reverse_https

::mlrt::linux/x86/meterpreter_reverse_tcp
::mlrtx::linux/x64/meterpreter_reverse_tcp
::mlrh::linux/x86/meterpreter_reverse_http
::mlrhx::linux/x64/meterpreter_reverse_http
::mlrs::linux/x86/meterpreter_reverse_https
::mlrsx::linux/x64/meterpreter_reverse_https
#IfWinActive
;----------------------------------------------------------------------
;aud- 代码审计
#IfWinActive ahk_group terminal

;fortify-
::audop::set vul_scan= vul_scan
::audhh::D:\fortify\bin\sourceanalyzer.exe --help
::audhlp::D:\fortify\bin\sourceanalyzer.exe --help
::auded::D:\fortify\bin\sourceanalyzer.exe -b %vul_scan% -clean{Space}
::audbd::D:\fortify\bin\sourceanalyzer.exe -b %vul_scan%{Space}
::audsc::
SendInput, D:\fortify\bin\sourceanalyzer.exe -rules "%A_WorkingDir%`\@@@txt@@@" -b `%vul_scan`% -scan -f `%vul_scan`%.fpr -no-default-rules
return

;javaweb-
::fuja::
clipboard = 
(
search_list = [
	echo(r'File Upload'.center(80, '-')),
	echo(r'1. DiskFileItemFactory, parseRequest, FileItem, getInputStream|write:'),
    grep(r'\bDiskFileItemFactory\b', r'\bparseRequest\b', r'\bFileItem\b', r'\bgetInputStream\b|\bwrite\b')(r'\.jsp$|\.jspx$|\.java$'),
	
	echo(r'2. SmartUpload, save:'),
    grep(r'\bSmartUpload\b', r'\bsave\b')(r'\.jsp$|\.jspx$|\.java$'),
	
	# echo(r'3. MultipartHttpServletRequest, getFile|getFiles|getFileMap|getMultiFileMap, MultipartFile, getBytes|getInputStream|transferTo:'),
    # grep(r'\bMultipartHttpServletRequest\b', r'\bgetFile\b|\bgetFiles\b|\bgetFileMap\b|\bgetMultiFileMap\b|\bMultipartFile\b', r'\bgetBytes\b|\bgetInputStream\b|\btransferTo\b')(r'\.jsp$|\.jspx$|\.java$'),
	
	echo(r'3. MultipartHttpServletRequest, getFile|getFiles|getFileMap|getMultiFileMap, MultipartFile, getBytes|getInputStream|transferTo:\n   MultipartFile|CommonsMultipartFile, getBytes|getInputStream|transferTo|getFileItem:'),
    grep(r'\bMultipartFile\b|\bCommonsMultipartFile\b', r'\bgetBytes\b|\bgetInputStream\b|\btransferTo\b|\bgetFileItem\b')(r'\.jsp$|\.jspx$|\.java$'),
	
	echo(r'4. FormFile, getFileData|getInputStream:'),
	grep(r'\bFormFile\b', r'\bgetFileData\b|\bgetInputStream\b')(r'\.jsp$|\.jspx$|\.java$'),
	
	echo(r'5. extends ActionSupport, File, FileUtils.copyFile|InputStream:'),
	grep(r'\bextends\s+ActionSupport\b', r'\bFile\b', r'\bFileUtils\s*\.\s*copyFile\b|\bInputStream\b')(r'\.jsp$|\.jspx$|\.java$'),
	
	echo(r'6. new URL, openConnection, getInputStream'),
	grep(r'\bnew\s+URL\b', r'\bopenConnection\b', r'\bgetInputStream\b')(r'\.jsp$|\.jspx$|\.java$'),
	
	echo(r'7. HttpServletRequest, getInputStream, FileOutputStream|FileUtils.copyInputStreamToFile|FileUtils.copyToFile:'),
	grep(r'\bHttpServletRequest\b', r'\bgetInputStream\b', r'\bFileOutputStream\b|\bFileUtils\s*\.\s*copyInputStreamToFile\b|\bFileUtils\s*\.\s*copyToFile\b')(r'\.jsp$|\.jspx$|\.java$')
]

search_str = ';'.join(search_list)
set_clip(search_str)
)
pyw_exec_wait()
return

::execja::
clipboard = 
(
search_list = [
	echo(r'Cmd Exec'.center(80, '-')),
	echo(r'1. Runtime, getRuntime(), exec:'),
    grep(r'\bRuntime\s*\.\s*getRuntime\b\(\)', r'\.\s*\bexec\b')(r'\.jsp$|\.jspx$|\.java$'),
	
	echo(r'2. ScriptEngine|CompiledScript, eval:'),
	grep(r'\bScriptEngine\b|\bCompiledScript\b', r'\s*\.\s*\beval\b')(r'\.jsp$|\.jspx$|\.java$')
]

search_str = ';'.join(search_list)
set_clip(search_str)
)
pyw_exec_wait()
return

::fltja::
clipboard = 
(
search_list = [
    grep(r'extends\s+zuulfilter')('\.java$'),
	grep(r'@WebFilter')('\.java$'),
	grep(r'implements\s+filter')('\.java$')
]

search_str = ';'.join(search_list)
set_clip(search_str)
)
pyw_exec_wait()
return
#IfWinActive
;----------------------------------------------------------------------
;regx- regex- zz- 常用正则表达式

#IfWinActive ahk_group auto
!`;::
SendInput, ^.{End}+{Home}{BS}
return
:T:ip::\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b
:T:ip6::(?<![:.\w])(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}(?![:.\w])
:T:url::https?:/(?:/[^/\s]+)+
::d::{{}{}}{Left 1}
::z::[]{Left 1}
::i::.*.*{Left 2}
::ne::(?{!}){Left 1}
::eq::(?=){Left 1}
::del::(?:.*delete.*)|(?:.*remove.*)|(?:.*clear.*)|(?:.*release.*)|(?:.*free.*)|(?:.*clean.*)|(?:.*deinit.*)
::new::(?:.*new.*)|(?:.*get.*)|(?:.*create.*)|(?:.*add.*)|(?:.*init.*)|(?:.*alloc.*)|(?:.*build.*)
::g::(?:){Left 1}
::h::[a-fA-F0-9]{+}{Left 12}
::h4::[a-fA-F0-9]{{}8{}}{Left 14}
::h8::[a-fA-F0-9]{{}16{}}{Left 15}
::hx::[a-fA-F0-9]{{}8{}}``[a-fA-F0-9]{{}8{}}{Left 29}
::win::[a-zA-Z]:(?:[\\/][{^}\\/\n\r:\*"<>\|\?]{+})*
::lix::(?:/[{^}/\n\r]{+}){+}
::atr::[dl\-][rwx\-]{{}9{}}
:T:wapi::\w+API\s+\w+\s+WINAPI\s+(\w+)\s*\(\s*[^;]*;
:T:wapix::\w+API\s+\w+\s+WINAPI\s+\w+\s*\(\s*[^;]*;
#IfWinActive
;----------------------------------------------------------------------
;registry- zc- reg-常用注册表项

#IfWinActive ahk_exe cmd.exe
::rgls::reg query ""{Space}{Left 2}
::kdll::
clipboard = HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
return
::service::
clipboard = HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
return
::lsappl::
clipboard = HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
return
::aedbg::
clipboard = HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug
return
::aedbgx::
clipboard = HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
return
::keymap::
clipboard = HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layout
return
::apun::
clipboard = HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
return
::apunx::
clipboard = HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall
return

::wdws::
clipboard = HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windbg\Workspaces
return
#IfWinActive
;----------------------------------------------------------------------
;pdb- 软件符号

;Firefox http://symbols.mozilla.org/firefox
;Crhome https://chromium-browser-symsrv.commondatastorage.googleapis.com
;----------------------------------------------------------------------
