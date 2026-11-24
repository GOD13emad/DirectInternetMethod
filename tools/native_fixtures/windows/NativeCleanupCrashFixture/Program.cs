// Test-only disposable process-exit fixture. No service/registry/UAC operations.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DirectInternetMethod.Service;

internal static class Program
{
    private const string Marker = ".dim-r923-owned";
    private const string Sentinel = "preserved-owner-data-r923";
    private const string TransactionId =
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    private static string FileAt(string root, string name) => Path.Combine(root, name);

    private static void WriteAtomic(string path, string payload)
    {
        var temp = path + ".tmp";
        using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write,
                                           FileShare.None, 4096, FileOptions.WriteThrough))
        {
            var bytes = Encoding.UTF8.GetBytes(payload);
            output.Write(bytes);
            output.Flush(flushToDisk: true);
        }
        File.Move(temp, path, overwrite: true);
    }

    private static string FixtureSha(string stage) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(stage)));

    private static int Run(string command, string root)
    {
        var pending = FileAt(root, "pending-update.json");
        var receipt = FileAt(root, NativeInnoCompletionReceipt.FileName(TransactionId));
        var stage = FileAt(root, "stage-fixture.bin");
        var sentinel = FileAt(root, "owner-data.txt");

        if (command == "seed")
        {
            if (Directory.EnumerateFileSystemEntries(root).Count() != 1 ||
                File.Exists(pending) || File.Exists(stage))
                throw new InvalidDataException("Fixture root must contain only the ownership marker.");
            File.WriteAllText(stage, "synthetic-owned-stage-r923", Encoding.UTF8);
            File.WriteAllText(sentinel, Sentinel, Encoding.UTF8);
            var sha = FixtureSha(stage);
            File.WriteAllText(receipt,
                NativeInnoCompletionReceipt.Prefix + TransactionId + "|" + sha,
                Encoding.UTF8);
            WriteAtomic(pending, JsonSerializer.Serialize(new {
                schema = 2, transactionId = TransactionId, sha256 = sha
            }));
            return 0;
        }

        if (command == "verify")
        {
            if (File.Exists(pending) || File.Exists(stage) || File.Exists(receipt) ||
                File.ReadAllText(sentinel) != Sentinel)
                throw new InvalidDataException("Fixture cleanup or owner data verification failed.");
            return 0;
        }

        using var doc = JsonDocument.Parse(File.ReadAllText(pending));
        var data = doc.RootElement;
        if (data.GetProperty("schema").GetInt32() != 2 ||
            data.GetProperty("transactionId").GetString() != TransactionId)
            throw new InvalidDataException("Unexpected fixture transaction identity.");
        var sha256 = data.GetProperty("sha256").GetString();
        if (!NativeInnoCompletionReceipt.Hex64(sha256) ||
            File.ReadAllText(sentinel) != Sentinel)
            throw new InvalidDataException("Invalid digest or modified owner data.");
        var present = File.Exists(receipt);
        if (present && !NativeInnoCompletionReceipt.Matches(
                File.ReadAllText(receipt), TransactionId, sha256))
            throw new InvalidDataException("Native completion receipt mismatched.");
        var committed = NativeUpdateCleanupJournal.IsReceiptConsumed(data);
        NativeUpdateCleanupJournal.RequireSafeStageAfterCommit(committed, File.Exists(stage));

        if (command == "commit-exit")
        {
            if (committed || !present || !File.Exists(stage) ||
                !FixtureSha(stage).Equals(sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Fixture commit preconditions not met.");
            File.Delete(stage);
            WriteAtomic(pending,
                NativeUpdateCleanupJournal.MarkReceiptConsumed(data).ToJsonString());
            Environment.Exit(79); // Independent process terminates before receipt removal.
            return 79;
        }
        if (command == "receipt-exit")
        {
            if (!committed || !present || File.Exists(stage))
                throw new InvalidDataException("Fixture receipt-exit preconditions not met.");
            File.Delete(receipt);
            Environment.Exit(80); // Different interruption boundary: receipt gone, pending remains.
            return 80;
        }
        if (command == "resume")
        {
            if (!committed || File.Exists(stage))
                throw new InvalidDataException("Uncommitted or staged fixture cannot resume.");
            if (present)
                File.Delete(receipt);
            File.Delete(pending);
            return 0;
        }
        throw new InvalidDataException("Unknown test-only command.");
    }

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length != 2)
                return 2;
            var root = Path.GetFullPath(args[1]);
            var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(
                Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) ||
                !Directory.Exists(root) ||
                !File.Exists(FileAt(root, Marker)) ||
                Directory.Exists(FileAt(root, "pending-update.json")))
                throw new UnauthorizedAccessException("Only marked disposable OS temp fixture roots are permitted.");
            return Run(args[0], root);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FIXTURE_REJECTED:" + ex.GetType().Name);
            return 12;
        }
    }
}
