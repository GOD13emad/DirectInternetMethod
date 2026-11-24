using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace DirectInternetMethod.Service;

/// <summary>
/// A protected transaction-bound assertion from the actual Inno ssDone step.
/// The receipt is a *completion prerequisite*, not publisher authentication,
/// an install rollback, or proof that service/network behavior is healthy.
/// Its containing directory must pass NativeProtectedUpdateAcl independently.
/// </summary>
internal static class NativeInnoCompletionReceipt
{
    internal const string Prefix = "DIM-INNO-V1|";

    internal static bool Hex64(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    internal static string FileName(string transactionId)
    {
        if (!Hex64(transactionId))
            throw new InvalidDataException("Invalid completion transaction identifier.");
        return "completion-" + transactionId.ToUpperInvariant() + ".receipt";
    }

    internal static bool Matches(string? content, string? transactionId, string? sha256)
    {
        if (!Hex64(transactionId) || !Hex64(sha256) || content is null)
            return false;
        var expected = Prefix + transactionId!.ToUpperInvariant() +
                       "|" + sha256!.ToUpperInvariant();
        return string.Equals(content, expected, StringComparison.Ordinal);
    }

    // Win32 native receipt must be read FROM THE SAME HANDLE checked below.
    // The update directory ACL was checked separately by the SYSTEM service;
    // these OS checks close the leaf path/attribute/read TOCTOU window.
    // This validates existing Inno ssDone evidence, NEVER OS publisher trust.
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const int ExactReceiptBytes = 141;

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public uint Low;
        public uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileInfo
    {
        public uint Attributes;
        public NativeFileTime Created;
        public NativeFileTime Accessed;
        public NativeFileTime Modified;
        public uint VolumeSerial;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string name, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition,
        uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle, out NativeFileInfo info);

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle handle, StringBuilder name, uint capacity, uint flags);

    internal static string ReadHeldExact(string receiptPath, string transactionId)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows native receipt handle required.");
        if (receiptPath is null || !Path.IsPathFullyQualified(receiptPath) ||
            !Hex64(transactionId))
            throw new InvalidDataException("Native completion path or ID invalid.");
        // Only the literal per-transaction receipt leaf can be read.
        // Path must already come from trusted UpdateTransactions scope.
        var expectedPath = Path.GetFullPath(receiptPath);
        if (!string.Equals(receiptPath, expectedPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(receiptPath), FileName(transactionId),
                           StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Native completion receipt path drift.");
        using var held = OpenHeldExact(expectedPath, ExactReceiptBytes, writable: false);
        using var reader = new FileStream(held, FileAccess.Read);
        var bytes = new byte[ExactReceiptBytes];
        reader.ReadExactly(bytes);
        if (reader.ReadByte() != -1 || bytes.Any(x => x > 127))
            throw new InvalidDataException("Native receipt bytes are not exact ASCII.");
        return Encoding.ASCII.GetString(bytes);
    }

    // Same held-file metadata checks for the one protected journal temp.
    // No caller-controlled filename or permission grant.
    internal static void VerifyAndFlushJournalTemp(string path, byte[] expected)
    {
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(path) ||
            !string.Equals(path, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase) ||
            Path.GetFileName(path) != "pending-update.json.tmp" ||
            Path.GetFileName(Path.GetDirectoryName(path)) != "UpdateTransactions" ||
            expected.Length is < 1 or > 65536)
            throw new InvalidDataException("Protected cleanup temp identity invalid.");
        using var held = OpenHeldExact(path, expected.Length, writable: true);
        using var reader = new FileStream(held, FileAccess.ReadWrite);
        var actual = new byte[expected.Length];
        reader.ReadExactly(actual);
        if (reader.ReadByte() != -1 || !actual.AsSpan().SequenceEqual(expected))
            throw new InvalidDataException("Interrupted cleanup temp differs from exact authorized transition.");
        reader.Flush(flushToDisk: true);
    }

    // Reuse the same native handle validation for the fixed, protected
    // pending journal. The caller must still verify the store ACL/authority.
    internal static JsonDocument ReadHeldPendingJson(string path)
    {
        if (!OperatingSystem.IsWindows() ||
            string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            !string.Equals(path, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase) ||
            Path.GetFileName(path) != "pending-update.json" ||
            Path.GetFileName(Path.GetDirectoryName(path)) != "UpdateTransactions")
            throw new InvalidDataException("Protected pending record identity invalid.");
        using var held = OpenHeldExact(path, 65536, writable: false, bounded: true);
        using var reader = new FileStream(held, FileAccess.Read);
        // The size bound is enforced on the SAME non-reparse, single-link
        // handle. No secondary pathname open or unbounded read.
        return JsonDocument.Parse(reader);
    }

    // Caller already verified the protected directory ACL and release SHA.
    // Return the same verified, single-link read handle to keep the fixed
    // stage immutable through Process.Start. No authority to execute here.
    internal static FileStream HoldVerifiedStage(string path, string expectedSha)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path) ||
            !string.Equals(path, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase) ||
            Path.GetFileName(path) != "DirectInternetMethod-update-stage.exe" ||
            Path.GetFileName(Path.GetDirectoryName(path)) != "UpdateTransactions" ||
            !Hex64(expectedSha))
            throw new InvalidDataException("Protected installer stage identity invalid.");
        var held = OpenHeldExact(path, int.MaxValue, writable: false, bounded: true);
        FileStream? stream = null;
        try
        {
            stream = new FileStream(held, FileAccess.Read);
            var actual = Convert.ToHexString(SHA256.HashData(stream));
            if (!string.Equals(actual, expectedSha, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Protected installer stage SHA changed.");
            stream.Position = 0;
            return stream;
        }
        catch
        {
            if (stream is not null) stream.Dispose();
            else held.Dispose();
            throw;
        }
    }

    private static SafeFileHandle OpenHeldExact(string expectedPath, int exactBytes, bool writable,
                                                bool bounded = false)
    {
        // FILE_FLAG_OPEN_REPARSE_POINT opens the link itself, never follows it.
        // FILE_SHARE_READ blocks concurrent rename/deletion/new writes until
        // the byte read has completed; keep that handle open throughout.
        var held = CreateFileW(expectedPath, writable ? 0xC0000000u : 0x80000000u,
                               writable ? 0u : FILE_SHARE_READ,
                               IntPtr.Zero, 3,
                               FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        try
        {
            if (held.IsInvalid)
                throw new IOException("Cannot open protected native file.");
            if (!GetFileInformationByHandle(held, out var info) ||
                (info.Attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0 ||
                info.NumberOfLinks != 1 ||
                info.FileSizeHigh != 0 ||
                (!bounded && info.FileSizeLow != exactBytes) ||
                (bounded && (info.FileSizeLow < 1 || info.FileSizeLow > exactBytes)))
                throw new InvalidDataException("Native held-file metadata invalid.");
            var final = new StringBuilder(8192);
            var count = GetFinalPathNameByHandleW(held, final, (uint)final.Capacity, 0);
            var expectedFinal = @"\\?\" + expectedPath;
            if (count == 0 || count >= final.Capacity ||
                !string.Equals(final.ToString(), expectedFinal,
                               StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Native final handle path mismatch.");
            return held;
        }
        catch
        {
            held.Dispose();
            throw;
        }
    }

    internal static bool SelfTest()
    {
        const string txn = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        const string sha = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        const string other = "F123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        var good = Prefix + txn + "|" + sha;
        return Matches(good, txn, sha) &&
               Matches(good, txn.ToLowerInvariant(), sha.ToLowerInvariant()) &&
               FileName(txn.ToLowerInvariant()) == "completion-" + txn + ".receipt" &&
               !Matches(good, other, sha) &&
               !Matches(good, txn, other) &&
               !Matches(good + "\n", txn, sha) &&
               !Matches("DIM-INNO-V0|" + txn + "|" + sha, txn, sha) &&
               !Matches("", txn, sha) &&
               !Matches(null, txn, sha) &&
               !Matches(good, "nothex", sha) &&
               !Matches(good, txn, "nothex");
    }
}
