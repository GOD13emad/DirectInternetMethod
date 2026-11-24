using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DirectInternetMethod.Service;

/// <summary>
/// Read-only policy for choosing the future privileged update/receipt store.
/// This helper does NOT move the updater, grant permissions, or authenticate a
/// publisher. Do not use a user-creatable ProgramData/updates path as a
/// native transaction-completion authority.
/// </summary>
internal static class NativeProtectedUpdateAcl
{
    private const string SystemSid = "S-1-5-18";
    private const string AdministratorsSid = "S-1-5-32-544";
    private const string TrustedInstallerSid =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    private const FileSystemRights DangerousWriteRights =
        FileSystemRights.WriteData | FileSystemRights.AppendData |
        FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes |
        FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.Delete |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    private static bool TrustedWriterSid(string sid) =>
        sid is SystemSid or AdministratorsSid or TrustedInstallerSid;

    /// <summary>
    /// Rejects writable allow ACEs for any non-privileged SID, including
    /// inherited ACEs and unrecognized service/user identities.
    /// Restriction is intentionally stronger than an effective-access
    /// calculation; an explicit DENY does not rescue an unsafe ALLOW.
    /// </summary>
    internal static bool IsProtectedDescriptor(DirectorySecurity security)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !TrustedWriterSid(owner.Value)) return false;
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                (rule.FileSystemRights & DangerousWriteRights) == 0)
                continue;
            if (rule.IdentityReference is not SecurityIdentifier sid ||
                !TrustedWriterSid(sid.Value))
                return false;
        }
        return true;
    }

    internal static bool IsProtectedExistingDirectory(string path)
    {
        if (!OperatingSystem.IsWindows() || !Directory.Exists(path))
            return false;
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                return false;
            var descriptor = new DirectoryInfo(path).GetAccessControl(
                AccessControlSections.Owner | AccessControlSections.Access);
            return IsProtectedDescriptor(descriptor);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                   or ArgumentException or SystemException)
        {
            return false;
        }
    }

    /// <summary>
    /// Only consider the exact 64-bit Program Files product layout. An
    /// arbitrary redirected user folder cannot become an updater root.
    /// No filesystem changes are performed here.
    /// </summary>
    internal static bool TryGetTrustedProtectedParent(string serviceBaseDirectory,
                                                       out string privilegedRoot)
    {
        privilegedRoot = "";
        if (!OperatingSystem.IsWindows() ||
            string.IsNullOrWhiteSpace(serviceBaseDirectory))
            return false;
        try
        {
            var programFiles = Path.GetFullPath(Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFiles)).TrimEnd('\\');
            var product = Path.Combine(programFiles, "DirectInternetMethod");
            var required = Path.Combine(product, "Privileged");
            var app = Path.Combine(required, "app");
            var observed = Path.GetFullPath(serviceBaseDirectory).TrimEnd('\\');
            if (!string.Equals(observed, app, StringComparison.OrdinalIgnoreCase))
                return false;
            foreach (var candidate in new[] { programFiles, product, required, app })
                if (!IsProtectedExistingDirectory(candidate))
                    return false;
            privilegedRoot = required;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                   or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>
    /// Safe only when called by the trusted SYSTEM/native service. A
    /// verified protected parent denies ordinary Users the ability to
    /// pre-create the child. Rechecks the actual directory after creation.
    /// Callers still need bound open-file handles and trusted package pins.
    /// </summary>
    internal static string PrepareProtectedTransactionDirectory(string serviceBaseDirectory)
    {
        if (!TryGetTrustedProtectedParent(serviceBaseDirectory, out var root))
            throw new UnauthorizedAccessException(
                "Update transaction root does not have OS-protected provenance.");

        var transactions = Path.Combine(root, "UpdateTransactions");
        Directory.CreateDirectory(transactions);
        if (!IsProtectedExistingDirectory(transactions))
            throw new UnauthorizedAccessException(
                "Update transaction directory permits non-privileged modifications.");
        return transactions;
    }

    internal static bool SyntheticPolicySelfTest()
    {
        if (!OperatingSystem.IsWindows()) return false;
        var safe = new DirectorySecurity();
        safe.SetSecurityDescriptorSddlForm(
            "O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)");
        var userWritable = new DirectorySecurity();
        userWritable.SetSecurityDescriptorSddlForm(
            "O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FW;;;BU)");
        var userOwned = new DirectorySecurity();
        userOwned.SetSecurityDescriptorSddlForm(
            "O:BUG:BUD:(A;OICI;FR;;;BU)(A;OICI;FA;;;SY)");
        return IsProtectedDescriptor(safe) &&
               !IsProtectedDescriptor(userWritable) &&
               !IsProtectedDescriptor(userOwned);
    }
}
