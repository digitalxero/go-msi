// Drive the actual Windows Installer dialogs. No external-UI callback replaces
// the authored UI: clicks go to its native controls on the runner's desktop.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class NativeMsiUI {
    public delegate bool EnumProc(IntPtr window, IntPtr param);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr param);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr window, EnumProc callback, IntPtr param);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr window, StringBuilder text, int count);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr window, StringBuilder text, int count);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr window);
    [DllImport("user32.dll")] static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr window, IntPtr dc, uint flags);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] static extern bool AttachThreadInput(uint from, uint to, bool attach);
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")] static extern IntPtr SetActiveWindow(IntPtr window);
    public struct Rect { public int Left, Top, Right, Bottom; }
    public static string Text(IntPtr w) { var s = new StringBuilder(8192); GetWindowText(w,s,s.Capacity); return s.ToString(); }
    public static string Class(IntPtr w) { var s = new StringBuilder(256); GetClassName(w,s,s.Capacity); return s.ToString(); }
    public static IntPtr Find(string title) {
        IntPtr result = IntPtr.Zero;
        EnumWindows((w,p) => { if(IsWindowVisible(w) && Text(w) == title) { result=w; return false; } return true; }, IntPtr.Zero);
        return result;
    }
    public static IntPtr[] Children(IntPtr w) {
        var list = new List<IntPtr>();
        EnumChildWindows(w,(c,p) => { if(IsWindowVisible(c)) list.Add(c); return true; },IntPtr.Zero);
        return list.ToArray();
    }
    public static string Contents(IntPtr w) {
        var s = new StringBuilder(Text(w));
        foreach(var c in Children(w)) s.Append("\n" + Class(c) + ": " + Text(c));
        return s.ToString();
    }
    public static bool Click(IntPtr w, string caption) {
        foreach(var c in Children(w)) {
            if(Class(c) == "Button" && Text(c).Replace("&", "") == caption && IsWindowEnabled(c)) {
                // BM_CLICK can be ignored when a modeless dialog is inactive.
                // Attach only while activating this job's installer window.
                uint pid;
                uint target = GetWindowThreadProcessId(w, out pid), current = GetCurrentThreadId();
                bool attached = current != target && AttachThreadInput(current,target,true);
                try {
                    SetForegroundWindow(w);
                    SetActiveWindow(w);
                    return PostMessage(c,0x00F5,IntPtr.Zero,IntPtr.Zero);
                } finally { if(attached) AttachThreadInput(current,target,false); }
            }
        }
        return false;
    }
    public static Rect Bounds(IntPtr w) { Rect r; GetWindowRect(w,out r); return r; }
    public static bool Capture(IntPtr w, IntPtr dc) { return PrintWindow(w,dc,2); }
}
