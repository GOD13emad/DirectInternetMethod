using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DirectInternetMethod.Service;

/// <summary>
/// Crash-restart recovery for the trusted, ACL-protected Inno ssDone transaction.
/// The only transition from prepared to receipt-consumed occurs AFTER the
/// matching native receipt is validated and the pinned installer is retired.
/// This is NOT a power-cut durability or automatic rollback guarantee.
/// </summary>
internal static class NativeUpdateCleanupJournal
{
    internal const string Consumed = "receipt-consumed";

    internal static bool IsReceiptConsumed(JsonElement pending)
    {
        if (!pending.TryGetProperty("cleanupPhase", out var phase))
            return false; // Original R918 pending schema v2.
        if (phase.ValueKind != JsonValueKind.String ||
            !string.Equals(phase.GetString(), Consumed, StringComparison.Ordinal))
            throw new InvalidDataException("Unknown protected update cleanup phase; evidence preserved.");
        return true;
    }

    internal static JsonObject MarkReceiptConsumed(JsonElement pending)
    {
        if (IsReceiptConsumed(pending))
            throw new InvalidDataException("Protected update cleanup phase already committed.");
        var record = JsonNode.Parse(pending.GetRawText()) as JsonObject
            ?? throw new InvalidDataException("Protected pending update must be a JSON object.");
        record["cleanupPhase"] = Consumed;
        return record;
    }

    // Shared by the actual Service finalizer and the process-exit fixture.
    // Never treat an existing staged installer as safe once cleanup was committed.
    internal static void RequireSafeStageAfterCommit(bool committed, bool stagedInstallerExists)
    {
        if (committed && stagedInstallerExists)
            throw new InvalidDataException(
                "Committed native completion journal cannot coexist with staged installer.");
    }

    internal static bool SelfTest()
    {
        const string baseline =
            "{\"schema\":2,\"transactionId\":\"TEST-NONCE\",\"sha256\":\"TEST-DIGEST\"}";
        using var original = JsonDocument.Parse(baseline);
        if (IsReceiptConsumed(original.RootElement))
            return false;
        var consumed = MarkReceiptConsumed(original.RootElement);
        using var committed = JsonDocument.Parse(consumed.ToJsonString());
        if (!IsReceiptConsumed(committed.RootElement) ||
            committed.RootElement.GetProperty("transactionId").GetString() != "TEST-NONCE" ||
            committed.RootElement.GetProperty("sha256").GetString() != "TEST-DIGEST" ||
            committed.RootElement.GetProperty("schema").GetInt32() != 2)
            return false;
        try
        {
            _ = MarkReceiptConsumed(committed.RootElement);
            return false;
        }
        catch (InvalidDataException) { }
        RequireSafeStageAfterCommit(true, false);
        RequireSafeStageAfterCommit(false, true);
        try
        {
            RequireSafeStageAfterCommit(true, true);
            return false;
        }
        catch (InvalidDataException) { }
        foreach (var invalid in new[]
        {
            "{\"cleanupPhase\":\"unverified\"}",
            "{\"cleanupPhase\":null}",
            "{\"cleanupPhase\":true}",
            "{\"cleanupPhase\":\"receipt-consumed \"}"
        })
        {
            using var doc = JsonDocument.Parse(invalid);
            try
            {
                _ = IsReceiptConsumed(doc.RootElement);
                return false;
            }
            catch (InvalidDataException) { }
        }
        return true;
    }
}
