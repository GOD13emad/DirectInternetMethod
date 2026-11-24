using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace DirectInternetMethod.Service;

/// <summary>
/// OS-local protected pending-update record writer. Only the service's
/// previously ACL-verified, fixed UpdateTransactions directory is accepted.
/// This improves crash/flush boundaries but does NOT prove powercut survival,
/// publisher authority, native rollback or full OS broker coordination.
/// </summary>
internal static class NativeProtectedUpdateJournal
{
    private const uint MOVEFILE_REPLACE_EXISTING = 0x00000001;
    private const uint MOVEFILE_WRITE_THROUGH = 0x00000008;
    private const int MaximumPendingBytes = 65536;

    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(
        string existingPath, string newPath, uint flags);

    internal static void WriteJsonAtomic(string path, object payload)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Windows native pending journal requires Win32.");
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path))
            throw new InvalidDataException("Native pending path must be absolute.");
        var target = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(target);
        if (!string.Equals(target, path, StringComparison.OrdinalIgnoreCase) ||
            parent is null ||
            !string.Equals(Path.GetFileName(target), "pending-update.json",
                           StringComparison.Ordinal) ||
            !string.Equals(Path.GetFileName(parent), "UpdateTransactions",
                           StringComparison.Ordinal) ||
            !Directory.Exists(parent) ||
            (File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Native pending target is not the fixed owned leaf.");
        // The calling service verifies NativeProtectedUpdateAcl for the full
        // protected ancestor chain under LocalSystem BEFORE this function.
        if (File.Exists(target) &&
            (File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Native pending target cannot be a reparse point.");

        var raw = JsonSerializer.SerializeToUtf8Bytes(payload);
        if (raw.Length is < 1 or > MaximumPendingBytes)
            throw new InvalidDataException("Native pending record size invalid.");
        var temp = target + ".tmp";
        // The fixed temp name is created EXCLUSIVELY. A prior crash's temp
        // cannot be overwritten or mistaken for a successful journal state.
        using (var output = new FileStream(
            temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            bufferSize: 4096, options: FileOptions.WriteThrough))
        {
            output.Write(raw);
            output.Flush(flushToDisk: true);
        }
        // Same-directory, same-volume Win32 rename; the WRITE_THROUGH flag
        // requests a stronger flush than the previous bare File.Move.
        // This remains NOT an independently power-cut-proven guarantee.
        if (!MoveFileExW(temp, target,
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            throw new IOException("Native pending journal MoveFileExW failed.",
                new Win32Exception(Marshal.GetLastWin32Error()));
    }
}