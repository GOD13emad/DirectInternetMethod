// R896: offline Windows Sandbox-only OS authorization *negative* fixture.
// CreateRestrictedToken + impersonation; NEVER change production DIM resources.
// Native token & ACL behavior is observed, not publisher provenance/approval.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;

internal static class RestrictedBoundaryProbe
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool CreateRestrictedToken(
        IntPtr existingToken, uint flags, uint disableSidCount,
        [In] SidAndAttributes[] disableSids, uint deletePrivilegeCount,
        IntPtr deletePrivileges, uint restrictSidCount,
        [In] SidAndAttributes[] restrictSids, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool IsTokenRestricted(IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool RevertToSelf();
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static IntPtr Sid(WellKnownSidType type)
    {
        var sid = new SecurityIdentifier(type, null);
        byte[] buffer = new byte[sid.BinaryLength];
        sid.GetBinaryForm(buffer, 0);
        IntPtr unmanaged = Marshal.AllocHGlobal(buffer.Length);
        Marshal.Copy(buffer, 0, unmanaged, buffer.Length);
        return unmanaged;
    }

    private static void Need(bool ok, string name)
    {
        if (!ok)
            throw new InvalidOperationException(name + ":WIN32_" + Marshal.GetLastWin32Error());
    }

    private static string Esc(string value)
    {
        return value.Replace(@"\", @"\\").Replace("\"", "\\\"");
    }

    public static int Main(string[] args)
    {
        if (args.Length != 3 ||
            args[0].IndexOf("DIM_R896_ProtectedACL", StringComparison.OrdinalIgnoreCase) < 0 ||
            args[1].IndexOf("DIM_R896_UserACL", StringComparison.OrdinalIgnoreCase) < 0)
        {
            Console.Error.WriteLine("FIXTURE_PATHS_REQUIRED");
            return 4;
        }
        var elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent());
        if (!elevated.IsInRole(WindowsBuiltInRole.Administrator))
        {
            Console.Error.WriteLine("GUEST_ADMIN_ONLY");
            return 5;
        }
        string protectedFile = Path.Combine(args[0], "fixture-owner-marker.txt");
        string protectedNew = Path.Combine(args[0], "unprivileged-injection.txt");
        string userFile = Path.Combine(args[1], "restricted-user-marker.txt");
        if (!File.Exists(protectedFile) || File.Exists(protectedNew) ||
            File.Exists(userFile) || !Directory.Exists(args[1]))
        {
            Console.Error.WriteLine("FIXTURE_PRECONDITIONS");
            return 6;
        }
        string before = File.ReadAllText(protectedFile);
        if (before != args[2])
        {
            Console.Error.WriteLine("MARKER_PIN_MISMATCH");
            return 7;
        }

        IntPtr admin = Sid(WellKnownSidType.BuiltinAdministratorsSid);
        IntPtr users = Sid(WellKnownSidType.BuiltinUsersSid);
        IntPtr source = IntPtr.Zero;
        IntPtr restricted = IntPtr.Zero;
        bool deniedProtected = false, allowedUser = false, isRestricted = false;
        bool impersonated = false;
        try
        {
            Need(OpenProcessToken(GetCurrentProcess(), 0x0002 | 0x0008 | 0x0001,
                                  out source), "OPEN_PROCESS_TOKEN");
            var disable = new[] { new SidAndAttributes{ Sid=admin, Attributes=0 }};
            var restrict = new[] { new SidAndAttributes{ Sid=users, Attributes=0 }};
            Need(CreateRestrictedToken(source, 0x0001, 1, disable, 0, IntPtr.Zero,
                                       1, restrict, out restricted),
                 "CREATE_RESTRICTED_TOKEN");
            isRestricted = IsTokenRestricted(restricted);
            Need(isRestricted, "TOKEN_NOT_RESTRICTED");
            Need(ImpersonateLoggedOnUser(restricted), "IMPERSONATE_RESTRICTED");
            impersonated = true;
            try
            {
                try
                {
                    File.WriteAllText(protectedNew, "MUST_NOT_CREATE");
                }
                catch (UnauthorizedAccessException) { deniedProtected = true; }
                catch (IOException) { deniedProtected = true; }

                try
                {
                    File.WriteAllText(userFile, "R896_USER_ONLY_WRITE_OK");
                    allowedUser = true;
                }
                catch (UnauthorizedAccessException) { allowedUser = false; }
                catch (IOException) { allowedUser = false; }
            }
            finally
            {
                Need(RevertToSelf(), "REVERT_TO_SELF");
                impersonated = false;
            }
            bool protectedUnchanged = File.ReadAllText(protectedFile) == before &&
                                      !File.Exists(protectedNew);
            bool userValid = File.Exists(userFile) &&
                             File.ReadAllText(userFile) == "R896_USER_ONLY_WRITE_OK";
            bool pass = deniedProtected && allowedUser && isRestricted &&
                        protectedUnchanged && userValid;
            Console.WriteLine("{\"schema\":1,\"status\":\"" +
                              (pass ? "PASS_R896_RESTRICTED_TOKEN_ACL" :
                                      "FAIL_R896_RESTRICTED_TOKEN_ACL") +
                              "\",\"restricted_token\":" + isRestricted.ToString().ToLower() +
                              ",\"protected_write_denied\":" + deniedProtected.ToString().ToLower() +
                              ",\"user_write_allowed\":" + allowedUser.ToString().ToLower() +
                              ",\"protected_marker_preserved\":" + protectedUnchanged.ToString().ToLower() +
                              ",\"native_product_installation_accepted\":false}");
            return pass ? 0 : 8;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e.GetType().Name + ":" + Esc(e.Message));
            return 9;
        }
        finally
        {
            if (impersonated) RevertToSelf();
            if (restricted != IntPtr.Zero) CloseHandle(restricted);
            if (source != IntPtr.Zero) CloseHandle(source);
            Marshal.FreeHGlobal(admin);
            Marshal.FreeHGlobal(users);
        }
    }
}
