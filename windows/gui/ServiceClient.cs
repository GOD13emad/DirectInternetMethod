using System.ComponentModel;
using System.Runtime.InteropServices;

namespace DirectInternetMethod;

internal static class ServiceClient
{
    const string ServiceName = "DirectInternetMethodSvc";
    const uint SC_MANAGER_CONNECT = 0x0001;
    const uint SERVICE_QUERY_STATUS = 0x0004;
    const uint SERVICE_USER_DEFINED_CONTROL = 0x0100;
    const uint CTRL_START = 128;
    const uint CTRL_STOP = 129;
    const uint CTRL_RECOVERY = 130;

    [StructLayout(LayoutKind.Sequential)]
    struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr OpenService(IntPtr scm, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ControlService(IntPtr service, uint control, ref SERVICE_STATUS status);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CloseServiceHandle(IntPtr handle);

    internal static void Send(string action)
    {
        uint code = action switch
        {
            "start" => CTRL_START,
            "stop" => CTRL_STOP,
            "recovery" => CTRL_RECOVERY,
            _ => throw new ArgumentOutOfRangeException(nameof(action))
        };

        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to connect to Service Control Manager.");
        try
        {
            IntPtr service = OpenService(scm, ServiceName, SERVICE_QUERY_STATUS | SERVICE_USER_DEFINED_CONTROL);
            if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Direct Internet Method service is not installed or access is denied.");
            try
            {
                var status = new SERVICE_STATUS();
                if (!ControlService(service, code, ref status))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to send {action} to Direct Internet Method service.");
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(scm); }
    }
}
