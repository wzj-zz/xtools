#SingleInstance force
#MaxHotkeysPerInterval 500
#WinActivateForce

wnd_stack := Array()

hVirtualDesktopAccessor := DllCall("LoadLibrary", Str, "VirtualDesktopAccessor.dll", "Ptr") 
MoveWindowToDesktopNumberProc := DllCall("GetProcAddress", Ptr, hVirtualDesktopAccessor, AStr, "MoveWindowToDesktopNumber", "Ptr")
GetCurrentDesktopNumberProc := DllCall("GetProcAddress", Ptr, hVirtualDesktopAccessor, AStr, "GetCurrentDesktopNumber", "Ptr")
GoToDesktopNumberProc := DllCall("GetProcAddress", Ptr, hVirtualDesktopAccessor, AStr, "GoToDesktopNumber", "Ptr")
GetDesktopCountProc := DllCall("GetProcAddress", Ptr, hVirtualDesktopAccessor, AStr, "GetDesktopCount", "Ptr")

GroupAdd, virtual_machine, ahk_exe vmware.exe
GroupAdd, virtual_machine, ahk_exe VirtualBox.exe
GroupAdd, virtual_machine, ahk_exe vmconnect.exe
GroupAdd, virtual_machine, ahk_exe mstsc.exe

#UseHook

MouseSpeed = 10
MouseAccelerationSpeed = 8
MouseMaxSpeed = 50

MouseWheelSpeed = 1
MouseWheelAccelerationSpeed = 1
MouseWheelMaxSpeed = 10

MouseRotationAngle = 0

#InstallKeybdHook

Temp = 0
Temp2 = 0

MouseRotationAnglePart = %MouseRotationAngle%
MouseRotationAnglePart /= 45

MouseCurrentAccelerationSpeed = 0
MouseCurrentSpeed = %MouseSpeed%

MouseWheelCurrentAccelerationSpeed = 0
MouseWheelCurrentSpeed = %MouseSpeed%

SetKeyDelay, -1
SetMouseDelay, -1

Hotkey, *a, ButtonLeftClick, Off
Hotkey, *NumpadIns, ButtonLeftClickIns, Off
Hotkey, *x, ButtonMiddleClick, Off
Hotkey, *NumpadClear, ButtonMiddleClickClear, Off
Hotkey, *s, ButtonRightClick, Off
Hotkey, *NumpadDel, ButtonRightClickDel, Off
Hotkey, *`,, ButtonX1Click, Off
Hotkey, *., ButtonX2Click, Off

Hotkey, *f, ButtonWheelUp, Off
Hotkey, *d, ButtonWheelDown, Off

Hotkey, *i, ButtonUp, Off
Hotkey, *k, ButtonDown, Off
Hotkey, *j, ButtonLeft, Off
Hotkey, *l, ButtonRight, Off
Hotkey, *u, ButtonUpLeft, Off
Hotkey, *n, ButtonUpRight, Off
Hotkey, *o, ButtonDownLeft, Off
Hotkey, *m, ButtonDownRight, Off

Hotkey, !i, BinButtonUp, Off
Hotkey, !k, BinButtonDown, Off
Hotkey, !j, BinButtonLeft, Off
Hotkey, !l, BinButtonRight, Off
Hotkey, !u, BinButtonUpLeft, Off
Hotkey, !n, BinButtonDownLeft, Off
Hotkey, !o, BinButtonUpRight, Off
Hotkey, !m, BinButtonDownRight, Off

Hotkey, 8, ButtonSpeedUp, Off
Hotkey, 2, ButtonSpeedDown, Off
Hotkey, 7, ButtonAccelerationSpeedUp, Off
Hotkey, 1, ButtonAccelerationSpeedDown, Off
Hotkey, 9, ButtonMaxSpeedUp, Off
Hotkey, 3, ButtonMaxSpeedDown, Off

Hotkey, 6, ButtonRotationAngleUp, Off
Hotkey, 4, ButtonRotationAngleDown, Off

Hotkey, !8, ButtonWheelSpeedUp, Off
Hotkey, !2, ButtonWheelSpeedDown, Off
Hotkey, !7, ButtonWheelAccelerationSpeedUp, Off
Hotkey, !1, ButtonWheelAccelerationSpeedDown, Off
Hotkey, !9, ButtonWheelMaxSpeedUp, Off
Hotkey, !3, ButtonWheelMaxSpeedDown, Off

Hotkey, *`;, MoveMiddle, off

>^LWin::
Hotkey, *a, Toggle
Hotkey, *NumpadIns, Toggle
Hotkey, *x, Toggle
Hotkey, *s, Toggle
Hotkey, *NumpadDel, Toggle
Hotkey, *`,, Toggle
Hotkey, *., Toggle

Hotkey, *f, Toggle
Hotkey, *d, Toggle

Hotkey, *i, Toggle
Hotkey, *k, Toggle
Hotkey, *j, Toggle
Hotkey, *l, Toggle
Hotkey, *u, Toggle
Hotkey, *n, Toggle
Hotkey, *o, Toggle
Hotkey, *m, Toggle

Hotkey, !i, Toggle
Hotkey, !k, Toggle
Hotkey, !j, Toggle
Hotkey, !l, Toggle
Hotkey, !u, Toggle
Hotkey, !n, Toggle
Hotkey, !o, Toggle
Hotkey, !m, Toggle

Hotkey, 8, Toggle
Hotkey, 2, Toggle
Hotkey, 7, Toggle
Hotkey, 1, Toggle
Hotkey, 9, Toggle
Hotkey, 3, Toggle

Hotkey, 6, Toggle
Hotkey, 4, Toggle

Hotkey, !8, Toggle
Hotkey, !2, Toggle
Hotkey, !7, Toggle
Hotkey, !1, Toggle
Hotkey, !9, Toggle
Hotkey, !3, Toggle

Hotkey, *`;, Toggle

return

BinButtonUp:
CoordMode, Mouse, Screen
MouseGetPos, pos_x, pos_y
MouseMove, (pos_x), (pos_y // 2)
return

BinButtonDown:
CoordMode, Mouse, Screen
MouseGetPos, pos_x, pos_y
MouseMove, (pos_x), (pos_y // 2 + A_ScreenHeight // 2)
return

BinButtonLeft:
CoordMode, Mouse, Screen
MouseGetPos, pos_x, pos_y
MouseMove, (pos_x // 2), (pos_y)
return

BinButtonRight:
CoordMode, Mouse, Screen
MouseGetPos, pos_x, pos_y
MouseMove, (pos_x // 2 + A_ScreenWidth // 2), (pos_y)
return

BinButtonUpLeft:
CoordMode, Mouse, Screen
MouseGetPos, pos_x, pos_y
MouseMove, (pos_x // 2), (pos_y // 2)
return

BinButtonDownLeft:
CoordMode, Mouse, Screen
MouseGetPos, pos_x, pos_y
MouseMove, (pos_x // 2), (pos_y // 2 + A_ScreenHeight // 2)
return

BinButtonUpRight:
CoordMode, Mouse, Screen
MouseGetPos, pos_x, pos_y
MouseMove, (pos_x // 2 + A_ScreenWidth // 2), (pos_y // 2 )
return

BinButtonDownRight:
CoordMode, Mouse, Screen
MouseGetPos, pos_x, pos_y
MouseMove, (pos_x // 2 + A_ScreenWidth // 2), (pos_y // 2 + A_ScreenHeight // 2)
return

MoveMiddle:
CoordMode, Mouse, Screen
MouseMove, (A_ScreenWidth // 2), (A_ScreenHeight // 2)
return

ButtonLeftClick:
GetKeyState, already_down_state, LButton
If already_down_state = D
	return
Button2 = a
ButtonClick = Left
Goto ButtonClickStart
ButtonLeftClickIns:
GetKeyState, already_down_state, LButton
If already_down_state = D
	return
Button2 = NumpadIns
ButtonClick = Left
Goto ButtonClickStart

ButtonMiddleClick:
GetKeyState, already_down_state, MButton
If already_down_state = D
	return
Button2 = x
ButtonClick = Middle
Goto ButtonClickStart
ButtonMiddleClickClear:
GetKeyState, already_down_state, MButton
If already_down_state = D
	return
Button2 = NumpadClear
ButtonClick = Middle
Goto ButtonClickStart

ButtonRightClick:
GetKeyState, already_down_state, RButton
If already_down_state = D
	return
Button2 = s
ButtonClick = Right
Goto ButtonClickStart
ButtonRightClickDel:
GetKeyState, already_down_state, RButton
If already_down_state = D
	return
Button2 = NumpadDel
ButtonClick = Right
Goto ButtonClickStart

ButtonX1Click:
GetKeyState, already_down_state, XButton1
If already_down_state = D
	return
Button2 = `,
ButtonClick = X1
Goto ButtonClickStart

ButtonX2Click:
GetKeyState, already_down_state, XButton2
If already_down_state = D
	return
Button2 = .
ButtonClick = X2
Goto ButtonClickStart

ButtonClickStart:
MouseClick, %ButtonClick%,,, 1, 0, D
SetTimer, ButtonClickEnd, 10
return

ButtonClickEnd:
GetKeyState, kclickstate, %Button2%, P
if kclickstate = D
	return

SetTimer, ButtonClickEnd, Off
MouseClick, %ButtonClick%,,, 1, 0, U
return

ButtonSpeedUp:
MouseSpeed++
ToolTip, Mouse speed: %MouseSpeed% pixels
SetTimer, RemoveToolTip, 1000
return
ButtonSpeedDown:
If MouseSpeed > 1
	MouseSpeed--
If MouseSpeed = 1
	ToolTip, Mouse speed: %MouseSpeed% pixel
else
	ToolTip, Mouse speed: %MouseSpeed% pixels
SetTimer, RemoveToolTip, 1000
return
ButtonAccelerationSpeedUp:
MouseAccelerationSpeed++
ToolTip, Mouse acceleration speed: %MouseAccelerationSpeed% pixels
SetTimer, RemoveToolTip, 1000
return
ButtonAccelerationSpeedDown:
If MouseAccelerationSpeed > 1
	MouseAccelerationSpeed--
If MouseAccelerationSpeed = 1
	ToolTip, Mouse acceleration speed: %MouseAccelerationSpeed% pixel
else
	ToolTip, Mouse acceleration speed: %MouseAccelerationSpeed% pixels
SetTimer, RemoveToolTip, 1000
return

ButtonMaxSpeedUp:
MouseMaxSpeed++
ToolTip, Mouse maximum speed: %MouseMaxSpeed% pixels
SetTimer, RemoveToolTip, 1000
return
ButtonMaxSpeedDown:
If MouseMaxSpeed > 1
	MouseMaxSpeed--
If MouseMaxSpeed = 1
	ToolTip, Mouse maximum speed: %MouseMaxSpeed% pixel
else
	ToolTip, Mouse maximum speed: %MouseMaxSpeed% pixels
SetTimer, RemoveToolTip, 1000
return

ButtonRotationAngleUp:
MouseRotationAnglePart++
If MouseRotationAnglePart >= 8
	MouseRotationAnglePart = 0
MouseRotationAngle = %MouseRotationAnglePart%
MouseRotationAngle *= 45
ToolTip, Mouse rotation angle: %MouseRotationAngle%?
SetTimer, RemoveToolTip, 1000
return
ButtonRotationAngleDown:
MouseRotationAnglePart--
If MouseRotationAnglePart < 0
	MouseRotationAnglePart = 7
MouseRotationAngle = %MouseRotationAnglePart%
MouseRotationAngle *= 45
ToolTip, Mouse rotation angle: %MouseRotationAngle%?
SetTimer, RemoveToolTip, 1000
return

ButtonUp:
ButtonDown:
ButtonLeft:
ButtonRight:
ButtonUpLeft:
ButtonUpRight:
ButtonDownLeft:
ButtonDownRight:

If Button <> 0
{
	IfNotInString, A_ThisHotkey, %Button%
	{
		MouseCurrentAccelerationSpeed = 0
		MouseCurrentSpeed = %MouseSpeed%
	}
}
StringReplace, Button, A_ThisHotkey, *

ButtonAccelerationStart:
If MouseAccelerationSpeed >= 1
{
	If MouseMaxSpeed > %MouseCurrentSpeed%
	{
		Temp = 0.001
		Temp *= %MouseAccelerationSpeed%
		MouseCurrentAccelerationSpeed += %Temp%
		MouseCurrentSpeed += %MouseCurrentAccelerationSpeed%
	}
}

{
	MouseCurrentSpeedToDirection = %MouseRotationAngle%
	MouseCurrentSpeedToDirection /= 90.0
	Temp = %MouseCurrentSpeedToDirection%

	if Temp >= 0
	{
		if Temp < 1
		{
			MouseCurrentSpeedToDirection = 1
			MouseCurrentSpeedToDirection -= %Temp%
			Goto EndMouseCurrentSpeedToDirectionCalculation
		}
	}
	if Temp >= 1
	{
		if Temp < 2
		{
			MouseCurrentSpeedToDirection = 0
			Temp -= 1
			MouseCurrentSpeedToDirection -= %Temp%
			Goto EndMouseCurrentSpeedToDirectionCalculation
		}
	}
	if Temp >= 2
	{
		if Temp < 3
		{
			MouseCurrentSpeedToDirection = -1
			Temp -= 2
			MouseCurrentSpeedToDirection += %Temp%
			Goto EndMouseCurrentSpeedToDirectionCalculation
		}
	}
	if Temp >= 3
	{
		if Temp < 4
		{
			MouseCurrentSpeedToDirection = 0
			Temp -= 3
			MouseCurrentSpeedToDirection += %Temp%
			Goto EndMouseCurrentSpeedToDirectionCalculation
		}
	}
}
EndMouseCurrentSpeedToDirectionCalculation:

{
	MouseCurrentSpeedToSide = %MouseRotationAngle%
	MouseCurrentSpeedToSide /= 90.0
	Temp = %MouseCurrentSpeedToSide%
	Transform, Temp, mod, %Temp%, 4

	if Temp >= 0
	{
		if Temp < 1
		{
			MouseCurrentSpeedToSide = 0
			MouseCurrentSpeedToSide += %Temp%
			Goto EndMouseCurrentSpeedToSideCalculation
		}
	}
	if Temp >= 1
	{
		if Temp < 2
		{
			MouseCurrentSpeedToSide = 1
			Temp -= 1
			MouseCurrentSpeedToSide -= %Temp%
			Goto EndMouseCurrentSpeedToSideCalculation
		}
	}
	if Temp >= 2
	{
		if Temp < 3
		{
			MouseCurrentSpeedToSide = 0
			Temp -= 2
			MouseCurrentSpeedToSide -= %Temp%
			Goto EndMouseCurrentSpeedToSideCalculation
		}
	}
	if Temp >= 3
	{
		if Temp < 4
		{
			MouseCurrentSpeedToSide = -1
			Temp -= 3
			MouseCurrentSpeedToSide += %Temp%
			Goto EndMouseCurrentSpeedToSideCalculation
		}
	}
}

EndMouseCurrentSpeedToSideCalculation:

MouseCurrentSpeedToDirection *= %MouseCurrentSpeed%
MouseCurrentSpeedToSide *= %MouseCurrentSpeed%

Temp = %MouseRotationAnglePart%
Transform, Temp, Mod, %Temp%, 2

If Button = i
{
	if Temp = 1
	{
		MouseCurrentSpeedToSide *= 2
		MouseCurrentSpeedToDirection *= 2
	}

	MouseCurrentSpeedToDirection *= -1
	MouseMove, %MouseCurrentSpeedToSide%, %MouseCurrentSpeedToDirection%, 0, R
}
else if Button = k
{
	if Temp = 1
	{
		MouseCurrentSpeedToSide *= 2
		MouseCurrentSpeedToDirection *= 2
	}

	MouseCurrentSpeedToSide *= -1
	MouseMove, %MouseCurrentSpeedToSide%, %MouseCurrentSpeedToDirection%, 0, R
}
else if Button = j
{
	if Temp = 1
	{
		MouseCurrentSpeedToSide *= 2
		MouseCurrentSpeedToDirection *= 2
	}

	MouseCurrentSpeedToSide *= -1
	MouseCurrentSpeedToDirection *= -1

	MouseMove, %MouseCurrentSpeedToDirection%, %MouseCurrentSpeedToSide%, 0, R
}
else if Button = l
{
	if Temp = 1
	{
		MouseCurrentSpeedToSide *= 2
		MouseCurrentSpeedToDirection *= 2
	}

	MouseMove, %MouseCurrentSpeedToDirection%, %MouseCurrentSpeedToSide%, 0, R
}
else if Button = u
{
	Temp = %MouseCurrentSpeedToDirection%
	Temp -= %MouseCurrentSpeedToSide%
	Temp *= -1
	Temp2 = %MouseCurrentSpeedToDirection%
	Temp2 += %MouseCurrentSpeedToSide%
	Temp2 *= -1
	MouseMove, %Temp%, %Temp2%, 0, R
}
else if Button = o
{
	Temp = %MouseCurrentSpeedToDirection%
	Temp += %MouseCurrentSpeedToSide%
	Temp2 = %MouseCurrentSpeedToDirection%
	Temp2 -= %MouseCurrentSpeedToSide%
	Temp2 *= -1
	MouseMove, %Temp%, %Temp2%, 0, R
}
else if Button = n
{
	Temp = %MouseCurrentSpeedToDirection%
	Temp += %MouseCurrentSpeedToSide%
	Temp *= -1
	Temp2 = %MouseCurrentSpeedToDirection%
	Temp2 -= %MouseCurrentSpeedToSide%
	MouseMove, %Temp%, %Temp2%, 0, R
}
else if Button = m
{
	Temp = %MouseCurrentSpeedToDirection%
	Temp -= %MouseCurrentSpeedToSide%
	Temp2 *= -1
	Temp2 = %MouseCurrentSpeedToDirection%
	Temp2 += %MouseCurrentSpeedToSide%
	MouseMove, %Temp%, %Temp2%, 0, R
}

SetTimer, ButtonAccelerationEnd, 10
return

ButtonAccelerationEnd:
GetKeyState, kstate, %Button%, P
if kstate = D
{
	if(GetKeyState("LShift", "P")) 
	{
		MouseAccelerationSpeed = 8
		MouseCurrentAccelerationSpeed = 0
		MouseCurrentSpeed = 1
		Goto ButtonAccelerationStart
	}
	else if (GetKeyState("A", "P") && GetKeyState("RCtrl", "P")) {
		MouseAccelerationSpeed = 8
		MouseCurrentAccelerationSpeed = 0
		MouseCurrentSpeed = 1
		Goto ButtonAccelerationStart
	}
	else
	{
		Goto ButtonAccelerationStart
	}
}

SetTimer, ButtonAccelerationEnd, Off
MouseCurrentAccelerationSpeed = 0
MouseCurrentSpeed = %MouseSpeed%
Button = 0
return

ButtonWheelSpeedUp:
MouseWheelSpeed++
RegRead, MouseWheelSpeedMultiplier, HKCU, Control Panel\Desktop, WheelScrollLines
If MouseWheelSpeedMultiplier <= 0
	MouseWheelSpeedMultiplier = 1
MouseWheelSpeedReal = %MouseWheelSpeed%
MouseWheelSpeedReal *= %MouseWheelSpeedMultiplier%
ToolTip, Mouse wheel speed: %MouseWheelSpeedReal% lines
SetTimer, RemoveToolTip, 1000
return
ButtonWheelSpeedDown:
RegRead, MouseWheelSpeedMultiplier, HKCU, Control Panel\Desktop, WheelScrollLines
If MouseWheelSpeedMultiplier <= 0
	MouseWheelSpeedMultiplier = 1
If MouseWheelSpeedReal > %MouseWheelSpeedMultiplier%
{
	MouseWheelSpeed--
	MouseWheelSpeedReal = %MouseWheelSpeed%
	MouseWheelSpeedReal *= %MouseWheelSpeedMultiplier%
}
If MouseWheelSpeedReal = 1
	ToolTip, Mouse wheel speed: %MouseWheelSpeedReal% line
else
	ToolTip, Mouse wheel speed: %MouseWheelSpeedReal% lines
SetTimer, RemoveToolTip, 1000
return

ButtonWheelAccelerationSpeedUp:
MouseWheelAccelerationSpeed++
RegRead, MouseWheelSpeedMultiplier, HKCU, Control Panel\Desktop, WheelScrollLines
If MouseWheelSpeedMultiplier <= 0
	MouseWheelSpeedMultiplier = 1
MouseWheelAccelerationSpeedReal = %MouseWheelAccelerationSpeed%
MouseWheelAccelerationSpeedReal *= %MouseWheelSpeedMultiplier%
ToolTip, Mouse wheel acceleration speed: %MouseWheelAccelerationSpeedReal% lines
SetTimer, RemoveToolTip, 1000
return
ButtonWheelAccelerationSpeedDown:
RegRead, MouseWheelSpeedMultiplier, HKCU, Control Panel\Desktop, WheelScrollLines
If MouseWheelSpeedMultiplier <= 0
	MouseWheelSpeedMultiplier = 1
If MouseWheelAccelerationSpeed > 1
{
	MouseWheelAccelerationSpeed--
	MouseWheelAccelerationSpeedReal = %MouseWheelAccelerationSpeed%
	MouseWheelAccelerationSpeedReal *= %MouseWheelSpeedMultiplier%
}
If MouseWheelAccelerationSpeedReal = 1
	ToolTip, Mouse wheel acceleration speed: %MouseWheelAccelerationSpeedReal% line
else
	ToolTip, Mouse wheel acceleration speed: %MouseWheelAccelerationSpeedReal% lines
SetTimer, RemoveToolTip, 1000
return

ButtonWheelMaxSpeedUp:
MouseWheelMaxSpeed++
RegRead, MouseWheelSpeedMultiplier, HKCU, Control Panel\Desktop, WheelScrollLines
If MouseWheelSpeedMultiplier <= 0
	MouseWheelSpeedMultiplier = 1
MouseWheelMaxSpeedReal = %MouseWheelMaxSpeed%
MouseWheelMaxSpeedReal *= %MouseWheelSpeedMultiplier%
ToolTip, Mouse wheel maximum speed: %MouseWheelMaxSpeedReal% lines
SetTimer, RemoveToolTip, 1000
return
ButtonWheelMaxSpeedDown:
RegRead, MouseWheelSpeedMultiplier, HKCU, Control Panel\Desktop, WheelScrollLines
If MouseWheelSpeedMultiplier <= 0
	MouseWheelSpeedMultiplier = 1
If MouseWheelMaxSpeed > 1
{
	MouseWheelMaxSpeed--
	MouseWheelMaxSpeedReal = %MouseWheelMaxSpeed%
	MouseWheelMaxSpeedReal *= %MouseWheelSpeedMultiplier%
}
If MouseWheelMaxSpeedReal = 1
	ToolTip, Mouse wheel maximum speed: %MouseWheelMaxSpeedReal% line
else
	ToolTip, Mouse wheel maximum speed: %MouseWheelMaxSpeedReal% lines
SetTimer, RemoveToolTip, 1000
return

ButtonWheelUp:
ButtonWheelDown:

If Button <> 0
{
	If Button <> %A_ThisHotkey%
	{
		MouseWheelCurrentAccelerationSpeed = 0
		MouseWheelCurrentSpeed = %MouseWheelSpeed%
	}
}
StringReplace, Button, A_ThisHotkey, *

ButtonWheelAccelerationStart:
If MouseWheelAccelerationSpeed >= 1
{
	If MouseWheelMaxSpeed > %MouseWheelCurrentSpeed%
	{
		Temp = 0.001
		Temp *= %MouseWheelAccelerationSpeed%
		MouseWheelCurrentAccelerationSpeed += %Temp%
		MouseWheelCurrentSpeed += %MouseWheelCurrentAccelerationSpeed%
	}
}

If Button = f
	MouseClick, WheelUp,,, %MouseWheelCurrentSpeed%, 0, D
else if Button = d
	MouseClick, WheelDown,,, %MouseWheelCurrentSpeed%, 0, D

SetTimer, ButtonWheelAccelerationEnd, 100
return

ButtonWheelAccelerationEnd:
GetKeyState, kstate, %Button%, P
if kstate = D
	Goto ButtonWheelAccelerationStart

MouseWheelCurrentAccelerationSpeed = 0
MouseWheelCurrentSpeed = %MouseWheelSpeed%
Button = 0
return

RemoveToolTip:
SetTimer, RemoveToolTip, Off
ToolTip
return

dec2hex(d) {
	SetFormat, integer, hex
	h :=d+0
	h=%h%
	SetFormat, integer, dec
	return %h%
}

RepeatSendKey(first) {
	Input, x, , jkhluiyonmbe/pdft'vzsrw{space}
	Err := ErrorLevel
	
	if(Err=="EndKey:Space") {
		Err := ""
	} else {
		Err := SubStr(Err, 0)
		if(Err=="/") {
			Err := "/"
		} else if(Err=="'") {
			Err := "'"
		} else {
			StringLower, Err, Err
		}
	}
	
	x = %first%%x%%Err%
	
	if(RegExMatch(x, "^\d+$")!=0) {
		SendInput, {Right %x%}
		return
	}
	if(RegExMatch(x, "^[\d]+[jkhluiyonmbe/pdft'vzsrw]$")==0) {
		return
	}
	
	num := SubStr(x, 1, -1)
	flag := SubStr(x, 0)
	if(flag=="j") {
		SendInput, {Down %num%}
	} else if (flag=="k") {
		SendInput, {Up %num%}
	} else if (flag=="h") {
		SendInput, {Left %num%}
	} else if (flag=="l") {
		SendInput, {Right %num%}
	} else if (flag=="u") {
		SendInput, ^{Left %num%}
	} else if (flag=="i") {
		SendInput, ^{Right %num%}
	} else if (flag=="y") {
		SendInput, {BS %num%}
	} else if (flag=="o") {
		SendInput, ^{BS %num%}
	} else if (flag=="n") {
		SendInput, ^+{Left %num%}
	} else if (flag=="m") {
		SendInput, ^+{Right %num%}
	} else if (flag=="b") {
		SendInput, +{Left %num%}
	} else if (flag=="e") {
		SendInput, +{Right %num%}
	} else if (flag=="/") {
		SendInput, +{Down %num%}
	} else if (flag=="p") {
		SendInput, +{Up %num%}
	} else if(flag=="d") {
		SendInput, {PgDn %num%}
	} else if(flag=="f") {
		SendInput, {PgUp %num%}
	} else if(flag=="t") {
		SendInput, {Del %num%}
	} else if(flag=="'") {
		SendInput, ^{Del %num%}
	} else if(flag=="v") {
		SendInput, ^{v %num%}
	} else if(flag=="z") {
		SendInput, ^{z %num%}
	} else if (flag=="s") {
		SendInput, {Enter %num%}
	} else if (flag=="r") {
        tmp_remove_line =
		Loop, %num% {
			tmp_remove_line = %tmp_remove_line%x{End}+{Home 2}{BS}{Del}
		}
        SendInput, %tmp_remove_line%
	} else if(flag=="w") {
		SendInput, ^{y %num%}
	} else {
		return
	}
}

#IfWinNotActive ahk_group virtual_machine
Esc:: SendInput, {Esc}
Esc & a:: SendInput, {Home}
Esc & `;:: SendInput, {End}
Esc & j:: SendInput, {Down}
Esc & k:: SendInput, {Up}
Esc & h:: SendInput, {Left}
Esc & l:: SendInput, {Right}
Esc & u:: SendInput, ^{Left}
Esc & i:: SendInput, ^{Right}
Esc & y:: SendInput, {BS}
Esc & o:: SendInput, ^{BS}
Esc & n:: SendInput, ^+{Left}
Esc & m:: SendInput, ^+{Right}
Esc & ,:: SendInput, +{Home}
Esc & .:: SendInput, +{End}
Esc & b:: SendInput, +{Left}
Esc & e:: SendInput, +{Right}
Esc & /:: SendInput, +{Down}
Esc & p:: SendInput, +{Up}
Esc & d:: SendInput, {PgDn}
Esc & f:: SendInput, {PgUp}
Esc & ':: SendInput, +{F10}
Esc & LAlt:: SendInput, #{Left}
Esc & RCtrl:: SendInput, #{Right}
Esc & Space:: SendInput, #{Up}
Esc & g:: SendInput, ^!{Tab}
Esc & q:: SendInput, !{F4}
Esc & 9:: SendInput, ^#{Left}
Esc & 0:: SendInput, ^#{Right}
Esc & c:: SendInput, ^#d
Esc & r:: SendInput, ^#{F4}
Esc & v:: SendInput, #+s
Esc & t:: SendInput, #{Tab}
Esc & Shift:: SendInput, {Del}
Esc & LButton::
SendInput, #{Left}
return
Esc & RButton::
SendInput, #{Right}
return
Esc & XButton2::
SendInput, #{Up}
return
#IfWinActive

#u::XButton1
#i::XButton2

#q::
WinGet, min_wnd_id, ID, A
wnd_stack.Push(min_wnd_id)
WinMinimize, A
return

#w::
min_wnd_id := wnd_stack.Pop()
WinActivate, ahk_id %min_wnd_id%
return

#+w::
wnd_stack := Array()
return

#j::
Gui +LastFound +OwnDialogs +AlwaysOnTop
InputBox, x, , , , 300, 100
if(x=="c") {
    WinActivateBottom, ahk_exe cmd.exe
} else {
    SetTitleMatchMode RegEx
    WinActivateBottom, ahk_exe i)%x%
}

#/::
id := WinExist("A")
WinGet, name, ProcessName, ahk_id %id%
WinActivateBottom, ahk_exe %name%
return

#9::
win_id := WinExist("A")
return

#+9::
WinActivate, ahk_id %win_id%
return

#0::
current := DllCall(GetCurrentDesktopNumberProc, UInt)
DllCall(MoveWindowToDesktopNumberProc, UInt, win_id, UInt, current)
WinActivate, ahk_id %win_id%
return

#\::
id := WinExist("A")
desktop_cnt := DllCall(GetDesktopCountProc, Int)
current := DllCall(GetCurrentDesktopNumberProc, UInt)
current := current + 1
WinGet, name, ProcessPath, ahk_id %id%
WinGet, pid, PID, ahk_id %id%
WinGetClass, Class, ahk_id %id%
pid_hex := dec2hex(pid)
msgbox, %name%`n`n PID: [ %pid% ] [ %pid_hex% ]`n AHK_CLASS: [ %Class% ]`n WHND: [ %id% ]`n CurDesktop: [ %current% ]`n DesktopCnt: [ %desktop_cnt% ]
clipboard := name
return

#+\::
id := WinExist("A")
WinGet, pid, PID, ahk_id %id%
clipboard = %pid%
return

#h::
CoordMode, Mouse, Screen
MouseMove, (A_ScreenWidth // 4), (A_ScreenHeight // 2)
SendInput, {LButton}
return

#k::
CoordMode, Mouse, Screen
MouseMove, (A_ScreenWidth//2 + A_ScreenWidth // 4), (A_ScreenHeight // 2)
SendInput, {LButton}
return

<!Esc::SendInput, {Click}
<#Esc::SendInput, {Click 2}
<+Esc::SendInput, {Enter}
MButton::RCtrl

#+,::
win_id0 := WinExist("A")
return

#,::
WinActivate, ahk_id %win_id0%
return

#+.::
win_id1 := WinExist("A")
return

#.::
WinActivate, ahk_id %win_id1%
return

#+'::
win_id2 := WinExist("A")
return

#'::
WinActivate, ahk_id %win_id2%
return

#+RCtrl::
win_id3 := WinExist("A")
return

#RCtrl::
WinActivate, ahk_id %win_id3%
return

+Space::
Loop {
	Input, first, L1, {space}
	
	if(first=="q") {
		return
	} else if(first=="a") {
		SendInput, {Home}
		Continue
	} else if(first==";") {
		SendInput, {End}
		Continue
	} else if(first=="d") {
		SendInput, {PgDn}
		Continue
	} else if(first=="f") {
		SendInput, {PgUp}
		Continue
	} else if(first==",") {
		SendInput, +{Home}
		Continue
	} else if(first==".") {
		SendInput, +{End}
		Continue
	} else if(first=="j") {
		SendInput, {Down}
		Continue
	} else if (first=="k") {
		SendInput, {Up}
		Continue
	} else if (first=="h") {
		SendInput, {Left}
		Continue
	} else if (first=="l") {
		SendInput, {Right}
		Continue
	} else if (first=="u") {
		SendInput, ^{Left}
		Continue
	} else if (first=="i") {
		SendInput, ^{Right}
		Continue
	} else if (first=="y") {
		SendInput, {BS}
		Continue
	} else if (first=="o") {
		SendInput, ^{BS}
		Continue
	} else if (first=="n") {
		SendInput, ^+{Left}
		Continue
	} else if (first=="m") {
		SendInput, ^+{Right}
		Continue
	} else if (first=="b") {
		SendInput, +{Left}
		Continue
	} else if (first=="e") {
		SendInput, +{Right}
		Continue
	} else if (first=="/") {
		SendInput, +{Down}
		Continue
	} else if (first=="p") {
		SendInput, +{Up}
		Continue
	} else if (first=="c") {
		SendInput, ^c
		Continue
	} else if (first=="v") {
		SendInput, ^v
		Continue
	} else if (first=="z") {
		SendInput, ^z
		Continue
	} else if (first=="x") {
		SendInput, ^x
		Continue
	} else if (first=="s") {
		SendInput, {Enter}
		Continue
	} else if (first=="g") {
		SendInput, ^a
		Continue
	} else if (first=="r") {
		SendInput, x{End}+{Home 2}{BS}{Del}
		Continue
	} else if (first=="t") {
		SendInput, {Del}
		Continue
	} else if (first=="w") {
		SendInput, ^y
		Continue
	} else if (first=="'") {
		SendInput, ^{Del}
		Continue
	} else if (RegExMatch(first, "^[\d]$")!=0) {
		RepeatSendKey(first)
		Continue
	} else {
		Continue
	}
}
#IfWinActive ahk_exe KeyPatch64.exe
`;::SendInput, {Enter}
#IfWinActive