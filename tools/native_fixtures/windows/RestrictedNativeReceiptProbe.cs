// R931: Offline guest-only synthetic receipt ACL attack using a REAL
// CreateRestrictedToken + impersonation (not a mock user-role boolean).
// No DIM service, Inno, credentials, network, publisher or protected host paths.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.InteropServices;

internal static class RestrictedNativeReceiptProbe
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        internal IntPtr Sid;
        internal uint Attributes;
    }
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool CreateRestrictedToken(
        IntPtr oldToken, uint flags, uint disableCount,
        [In] SidAndAttributes[] disable, uint deleteCount,
        IntPtr delete, uint restrictCount,
        [In] SidAndAttributes[] restrict, out IntPtr token);
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
        var data = new byte[sid.BinaryLength];
        sid.GetBinaryForm(data, 0);
        var p = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, p, data.Length);
        return p;
    }
    private static string Digest(string path)
    {
        using (var stream = File.OpenRead(path))
        using (var h = SHA256.Create())
        {
            return BitConverter.ToString(h.ComputeHash(stream))
                .Replace("-", "").ToLowerInvariant();
        }
    }
    private static bool Blocked(Action action)
    {
        try { action(); return false; }
        catch (UnauthorizedAccessException) { return true; }
        catch (IOException) { return true; }
    }
    private static void Need(bool pass, string message)
    {
        if (!pass) throw new InvalidOperationException(message);
    }
    public static int Main(string[] args)
    {
        if (args.Length != 3)
            return 4;
        var protectedRoot = Path.GetFullPath(args[0]).TrimEnd('\\');
        var userRoot = Path.GetFullPath(args[1]).TrimEnd('\\');
        var expected = args[2].ToLowerInvariant();
        var programData = Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        var p = Path.Combine(programData, "DIM_R931_SyntheticReceiptCustody");
        if (!string.Equals(protectedRoot, p, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(userRoot, @"C:\DIMR931\user", StringComparison.OrdinalIgnoreCase) ||
            expected.Length != 64)
        {
            Console.Error.WriteLine("R931_ONLY_EXACT_DISPOSABLE_ROOTS");
            return 5;
        }
        var receipt = Path.Combine(protectedRoot, "restored.receipt.json");
        var other = Path.Combine(protectedRoot, "untrusted-replacement.json");
        var moved = Path.Combine(protectedRoot, "old-receipt.json");
        var userFile = Path.Combine(userRoot, "untrusted-receipt.json");
        var admin = IntPtr.Zero;
        var users = IntPtr.Zero;
        var source = IntPtr.Zero;
        var restricted = IntPtr.Zero;
        var impersonating = false;
        try
        {
            Need(Directory.Exists(protectedRoot) && Directory.Exists(userRoot) &&
                 File.Exists(receipt) && !File.Exists(other) &&
                 !File.Exists(moved) && !File.Exists(userFile),
                 "R931_GUEST_FILE_PRECONDITION");
            Need(Digest(receipt) == expected, "R931_NATIVE_RECEIPT_SHA_DRIFT");
            admin = Sid(WellKnownSidType.BuiltinAdministratorsSid);
            users = Sid(WellKnownSidType.BuiltinUsersSid);
            Need(OpenProcessToken(GetCurrentProcess(), 0x0002|0x0008|0x0001,
                                  out source), "R931_OPEN_SOURCE_TOKEN");
            var disable = new[] { new SidAndAttributes { Sid = admin, Attributes = 0 } };
            var restrict = new[] { new SidAndAttributes { Sid = users, Attributes = 0 } };
            Need(CreateRestrictedToken(source, 0x0001, 1, disable,
                                       0, IntPtr.Zero, 1, restrict, out restricted),
                 "R931_CREATE_RESTRICTED_TOKEN");
            var actuallyRestricted = IsTokenRestricted(restricted);
            Need(actuallyRestricted, "R931_NOT_RESTRICTED");
            Need(ImpersonateLoggedOnUser(restricted), "R931_IMPERSONATE");
            impersonating = true;
            bool overwriteDenied, appendDenied, deleteDenied;
            bool renameDenied, injectionDenied, userWriteAllowed;
            try
            {
                overwriteDenied = Blocked(() => File.WriteAllText(receipt,
                    "{\"status\":\"restored\",\"intent_sha256\":\"spoofed\"}"));
                appendDenied = Blocked(() => File.AppendAllText(receipt, "spoof"));
                deleteDenied = Blocked(() => File.Delete(receipt));
                renameDenied = Blocked(() => File.Move(receipt, moved));
                injectionDenied = Blocked(() => File.WriteAllText(other, "spoof"));
                userWriteAllowed = !Blocked(() => File.WriteAllText(
                    userFile, "UNPRIVILEGED_FORGED_RECEIPT_ONLY"));
            }
            finally
            {
                Need(RevertToSelf(), "R931_REVERT_IMPERSONATION");
                impersonating = false;
            }
            bool protectedIdentical = File.Exists(receipt) &&
                Digest(receipt) == expected && !File.Exists(other) &&
                !File.Exists(moved);
            bool separateUserWritable = File.Exists(userFile) &&
                File.ReadAllText(userFile) == "UNPRIVILEGED_FORGED_RECEIPT_ONLY";
            bool pass = actuallyRestricted && overwriteDenied && appendDenied &&
                deleteDenied && renameDenied && injectionDenied &&
                userWriteAllowed && separateUserWritable && protectedIdentical;
            Console.WriteLine("{\"schema\":1,\"status\":\"" +
                (pass ? "PASS_R931_RESTRICTED_RECEIPT_CUSTODY" :
                        "FAIL_R931_RESTRICTED_RECEIPT_CUSTODY") +
                "\",\"restricted_token\":" + actuallyRestricted.ToString().ToLowerInvariant() +
                ",\"overwrite_denied\":" + overwriteDenied.ToString().ToLowerInvariant() +
                ",\"append_denied\":" + appendDenied.ToString().ToLowerInvariant() +
                ",\"delete_denied\":" + deleteDenied.ToString().ToLowerInvariant() +
                ",\"rename_denied\":" + renameDenied.ToString().ToLowerInvariant() +
                ",\"injection_denied\":" + injectionDenied.ToString().ToLowerInvariant() +
                ",\"user_scope_write_allowed\":" + userWriteAllowed.ToString().ToLowerInvariant() +
                ",\"protected_receipt_intact\":" + protectedIdentical.ToString().ToLowerInvariant() +
                ",\"trusted_broker_implemented\":false}");
            return pass ? 0 : 8;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("R931_EXCEPTION_" + e.GetType().Name +
                                    "_" + e.Message);
            return 9;
        }
        finally
        {
            if (impersonating) RevertToSelf();
            if (restricted != IntPtr.Zero) CloseHandle(restricted);
            if (source != IntPtr.Zero) CloseHandle(source);
            if (admin != IntPtr.Zero) Marshal.FreeHGlobal(admin);
            if (users != IntPtr.Zero) Marshal.FreeHGlobal(users);
        }
    }
}
