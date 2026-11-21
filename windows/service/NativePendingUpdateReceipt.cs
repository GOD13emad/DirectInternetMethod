using System;
using System.IO;

namespace DirectInternetMethod.Service;

/// <summary>
/// Side-effect-free native Inno registration consistency prerequisite for
/// pending-update cleanup. Registry facts are NOT publisher authentication,
/// OS handle-bound file attestation, or native installation acceptance.
/// </summary>
internal static class NativePendingUpdateReceipt
{
    private const string ExactDisplayName = "Direct Internet Method";

    private static string? CanonicalLocalInstallDirectory(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 2048)
            return null;

        var trimmed = value.Trim();
        // Accept only ordinary absolute local drive paths. Never permit UNC,
        // device/extended names, relative paths, alternate streams or dot
        // components to select a different privileged installer destination.
        if (trimmed.Length < 4 ||
            !char.IsAsciiLetter(trimmed[0]) || trimmed[1] != ':' ||
            trimmed[2] != '\\' || trimmed.IndexOfAny(new[] { '/', '\0', '"' }) >= 0 ||
            trimmed.IndexOf(':', 2) >= 0 ||
            !Path.IsPathFullyQualified(trimmed))
            return null;

        if (Array.Exists(trimmed[3..].Split('\\'),
            part => part is "." or ".."))
            return null;
        try
        {
            return Path.GetFullPath(trimmed).TrimEnd('\\');
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException
                                   or PathTooLongException)
        {
            return null;
        }
    }

    public static bool IsConsistent(
        string? registeredDisplayName, string? registeredDisplayVersion,
        string? registeredInstallDirectory, string? pendingInstallDirectory,
        Version runningServiceVersion, Version pendingTargetVersion)
    {
        if (!string.Equals(registeredDisplayName, ExactDisplayName,
                           StringComparison.Ordinal) ||
            runningServiceVersion is null || pendingTargetVersion is null ||
            runningServiceVersion.Build < 0 || pendingTargetVersion.Build < 0 ||
            runningServiceVersion.Revision is not (-1 or 0) ||
            pendingTargetVersion.Revision is not (-1 or 0) ||
            runningServiceVersion.CompareTo(pendingTargetVersion) < 0 ||
            !Version.TryParse(registeredDisplayVersion, out var registered) ||
            registered.Build < 0 || registered.Revision is not (-1 or 0) ||
            registered.Major != runningServiceVersion.Major ||
            registered.Minor != runningServiceVersion.Minor ||
            registered.Build != runningServiceVersion.Build)
            return false;

        var nativeDirectory = CanonicalLocalInstallDirectory(registeredInstallDirectory);
        var expectedDirectory = CanonicalLocalInstallDirectory(pendingInstallDirectory);
        return nativeDirectory is not null && expectedDirectory is not null &&
               string.Equals(nativeDirectory, expectedDirectory,
                             StringComparison.OrdinalIgnoreCase);
    }
}
