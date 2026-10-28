param([Parameter(Mandatory=$true)][string]$Label,[Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
Add-Type @'
using System;using System.Text;using System.Runtime.InteropServices;using System.Collections.Generic;
public static class MultiInventory {
 [StructLayout(LayoutKind.Sequential)] public struct RECT{public int Left,Top,Right,Bottom;}
 [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc p,IntPtr a);
 delegate bool EnumProc(IntPtr h,IntPtr a);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr h,StringBuilder b,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h,StringBuilder b,int n);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);
 [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] static extern bool IsIconic(IntPtr h);
 [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h,out RECT r);
 public class WindowState{public string hwnd,title,class_name; public uint owner_pid;public bool visible,iconic;public int x,y,width,height;}
 public static WindowState[] Read(){var items=new List<WindowState>();EnumWindows((h,a)=>{
  var title=new StringBuilder(512);var cls=new StringBuilder(128);GetWindowText(h,title,512);GetClassName(h,cls,128);
  if(title.ToString()=="Makepad (Ubuntu)" && cls.ToString()=="RAIL_WINDOW"){
   uint pid;RECT r;GetWindowThreadProcessId(h,out pid);GetWindowRect(h,out r);
   items.Add(new WindowState{hwnd="0x"+h.ToInt64().ToString("X"),title=title.ToString(),class_name=cls.ToString(),owner_pid=pid,visible=IsWindowVisible(h),iconic=IsIconic(h),x=r.Left,y=r.Top,width=r.Right-r.Left,height=r.Bottom-r.Top});}
  return true;},IntPtr.Zero);return items.ToArray();}
}
'@
$r=[ordered]@{utc=[DateTime]::UtcNow.ToString('o');label=$Label;windows=@([MultiInventory]::Read());method='read-only EnumWindows; includes hidden; exact title/class filter'}
$json=$r|ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $OutputDirectory ($Label+'.json')),$json,[Text.UTF8Encoding]::new($false));$json
