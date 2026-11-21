using System;
using System.IO;

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
