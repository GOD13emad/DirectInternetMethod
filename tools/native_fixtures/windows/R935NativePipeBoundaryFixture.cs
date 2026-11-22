// R935 WINDOWS SANDBOX ONLY: OS named-pipe ACL/client-token preflight,
// NOT a privileged production broker, publisher trust or product installation.
// A native SYSTEM-held server accepts a pinned synthetic intent from a real
// restricted Win32 client; checks the OS token and rejects altered request.
using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

internal static class R935NativePipeBoundaryFixture
{
    const string SandboxPath = @"C:\Users\WDAGUtilityAccount";
    const string ProtectedRoot = @"C:\ProgramData\DIM_R935_NativeBrokerPipeSandbox";
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_IMPERSONATE = 0x0004;
    const uint DISABLE_MAX_PRIVILEGE = 0x1;
    const uint FILE_WRITE_DATA = 0x2;
    const uint SYNCHRONIZE = 0x00100000;
    const int OPEN_EXISTING = 3;
    const int ERROR_ACCESS_DENIED = 5;
    const int ERROR_PIPE_BUSY = 231;
    const int ERROR_FILE_NOT_FOUND = 2;
    static readonly IntPtr INVALID = new(-1);

    [StructLayout(LayoutKind.Sequential)]
    struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr h, uint desired, out IntPtr token);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool CreateRestrictedToken(IntPtr source, uint flags,
         uint disabledCount, [In] SidAndAttributes[] disabled,
         uint removedPrivs, IntPtr removed, uint restrictingCount,
         [In] SidAndAttributes[] restricting, out IntPtr result);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool IsTokenRestricted(IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool RevertToSelf();
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint rights,
          uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);

    static void Must(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    static IntPtr Sid(WellKnownSidType type)
    {
        var sid = new SecurityIdentifier(type, null);
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        var buffer = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, buffer, bytes.Length);
        return buffer;
    }

    static byte[] ReceiveBounded(NamedPipeServerStream server)
    {
        // Exact bounded length-prefixed JSON transport; no newline parsing or
        // transient unbounded StreamReader. Schema is R899, NOT invented here.
        var header=new byte[4];
        var offset=0;
        while(offset<header.Length)
        {
            var n=server.Read(header,offset,header.Length-offset);
            Must(n>0,"R935_CLIENT_HEADER_DISCONNECTED");
            offset+=n;
        }
        var count=System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(header);
        Must(count>0 && count<=65536,"R935_NATIVE_BROKER_REQUEST_LENGTH_DENIED");
        var data=new byte[count];
        offset=0;
        while(offset<count)
        {
            var n=server.Read(data,offset,count-offset);
            Must(n>0,"R935_NATIVE_BROKER_REQUEST_TRUNCATED");
            offset+=n;
        }
        return data;
    }

    static string Hex(byte[] content) =>
        Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

    static PipeSecurity ProtectedPipeAcl()
    {
        var acl = new PipeSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid,null);
        acl.SetOwner(system);
        acl.SetAccessRuleProtection(true, false);
        acl.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(admins, PipeAccessRights.FullControl, AccessControlType.Allow));
        // No FILE_CREATE_PIPE_INSTANCE granted to ordinary users.
        acl.AddAccessRule(new PipeAccessRule(users,
            PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes |
            PipeAccessRights.Synchronize, AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(network,
            PipeAccessRights.ReadWrite, AccessControlType.Deny));
        return acl;
    }

    static object OneRound(string pipeName, byte[] payload,
                           string expectedSha, bool shouldMatch)
    {
        using var server=NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte,
            PipeOptions.None, 4096, 4096, ProtectedPipeAcl());
        var receivedHash="";
        var accepted=false;
        var identifiedRestricted=false;
        var identityFound=false;
        var pipePid=0u;
        var serviceIdentityRestored=false;
        var serverTask=System.Threading.Tasks.Task.Run(() =>
        {
            server.WaitForConnection();
            var bytes=ReceiveBounded(server);
            receivedHash=Hex(bytes);
            Must(GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(),
                        out pipePid), "R935_OS_PIPE_CLIENT_PID_UNAVAILABLE");
            server.RunAsClient(() => {
                using var id=WindowsIdentity.GetCurrent(true);
                identityFound=id is not null && id.User is not null;
                identifiedRestricted=IsTokenRestricted(id!.AccessToken.DangerousGetHandle());
            });
            using var own=WindowsIdentity.GetCurrent();
            serviceIdentityRestored=own.User is not null &&
                         own.User.Value=="S-1-5-18";
            accepted=identityFound && identifiedRestricted &&
                     pipePid == (uint)Environment.ProcessId &&
                     serviceIdentityRestored &&
                     CryptographicOperations.FixedTimeEquals(
                         Convert.FromHexString(receivedHash),
                         Convert.FromHexString(expectedSha));
        });
        IntPtr admin=IntPtr.Zero, user=IntPtr.Zero;
        IntPtr original=IntPtr.Zero, restricted=IntPtr.Zero;
        bool impersonating=false, protectedWriteDenied=false;
        try
        {
            admin=Sid(WellKnownSidType.BuiltinAdministratorsSid);
            user=Sid(WellKnownSidType.BuiltinUsersSid);
            Must(OpenProcessToken(GetCurrentProcess(),
                     TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_IMPERSONATE,
                     out original), "R935_SOURCE_TOKEN_UNAVAILABLE");
            var disable=new[]{new SidAndAttributes{Sid=admin,Attributes=0}};
            var restrict=new[]{new SidAndAttributes{Sid=user,Attributes=0}};
            Must(CreateRestrictedToken(original,DISABLE_MAX_PRIVILEGE,
                 1,disable,0,IntPtr.Zero,1,restrict,out restricted),
                 "R935_OS_RESTRICTED_CLIENT_CREATION_FAILED");
            Must(IsTokenRestricted(restricted), "R935_CLIENT_NOT_OS_RESTRICTED");
            Must(ImpersonateLoggedOnUser(restricted),
                 "R935_RESTRICTED_CLIENT_IMPERSONATION_FAILED");
            impersonating=true;
            try
            {
                try
                {
                    File.WriteAllText(Path.Combine(ProtectedRoot,
                        "untrusted-write.json"),"FORGED");
                }
                catch(UnauthorizedAccessException) { protectedWriteDenied=true; }
                catch(IOException) { protectedWriteDenied=true; }
                Must(protectedWriteDenied, "R935_RESTRICTED_CLIENT_WROTE_PROTECTED_ROOT");

                using var client=CreateFileW(@"\\.\pipe\"+pipeName,
                   FILE_WRITE_DATA|SYNCHRONIZE, 0, IntPtr.Zero,
                   OPEN_EXISTING, 0, IntPtr.Zero);
                Must(!client.IsInvalid,"R935_OS_NATIVE_PIPE_CLIENT_OPEN_DENIED_"+
                     Marshal.GetLastWin32Error());
                using var stream=new FileStream(client,FileAccess.Write,4096,false);
                var header=new byte[4];
                System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(
                    header,payload.Length);
                stream.Write(header);
                stream.Write(payload);
                stream.Flush(); // Pipe transport never constitutes fsync.
            }
            finally
            {
                Must(RevertToSelf(),"R935_OS_REVERT_CLIENT_FAILED");
                impersonating=false;
            }
            Must(serverTask.Wait(7000),"R935_SERVER_RESPONSE_TIMEOUT");
            Must(serverTask.IsCompletedSuccessfully,"R935_SERVER_NATIVE_IDENTITY_FAILURE");
            Must(accepted == shouldMatch,
                 "R935_EXPECTED_PINNED_REQUEST_OUTCOME_MISMATCH");
            return new {
                actual_pinned_request_match=accepted,
                expected_pinned_request_match=shouldMatch,
                protected_writer_denied_to_restricted_client=protectedWriteDenied,
                server_real_client_token_restricted=identifiedRestricted,
                pipe_client_process_id_matches=(pipePid==(uint)Environment.ProcessId),
                server_reverted_to_system=serviceIdentityRestored,
                native_product_installation_accepted=false,
                trusted_completion_receipt_minted=false
            };
        }
        finally
        {
            if(impersonating) RevertToSelf();
            if(restricted!=IntPtr.Zero) CloseHandle(restricted);
            if(original!=IntPtr.Zero) CloseHandle(original);
            if(admin!=IntPtr.Zero) Marshal.FreeHGlobal(admin);
            if(user!=IntPtr.Zero) Marshal.FreeHGlobal(user);
        }
    }

    static int Main(string[] args)
    {
        if(args.Length!=1 || args[0]!="--offline-guest-preflight")
            return 4;
        try
        {
            using var current=WindowsIdentity.GetCurrent();
            Must(current.User?.Value=="S-1-5-18","R935_GUEST_SYSTEM_REQUIRED");
            Must(Directory.Exists(SandboxPath),"R935_WINDOWS_SANDBOX_REQUIRED");
            Must(Directory.Exists(ProtectedRoot),"R935_APPROVED_SANDBOX_ROOT_REQUIRED");
            // Host test harness independently verifies the pin from the fixture
            // input. This is a synthetic pin, NOT publisher authorization.
            // Test-only exact R899 canonical JSON policy/request generated by
            // existing Python fixtures; no new custom broker operation schema.
            // A host-controlled test pin is NOT trusted publisher provenance.
            var bytes=File.ReadAllBytes(@"C:\DIMR935\input\broker-request.json");
            var policy=File.ReadAllBytes(@"C:\DIMR935\input\broker-policy.json");
            Must(bytes.Length>0 && bytes.Length<=65536 &&
                 policy.Length>0 && policy.Length<=65536,
                 "R935_R899_INPUT_BYTES_OUTSIDE_LIMIT");
            using var doc=JsonDocument.Parse(policy);
            var policyHash=doc.RootElement.GetProperty(
                "request_sha256").GetString();
            Must(policyHash==Hex(bytes),
                 "R935_R899_POLICY_REQUEST_CANONICAL_SHA_DRIFT");
            using var requestDoc=JsonDocument.Parse(bytes);
            Must(requestDoc.RootElement.GetProperty("schema").GetInt32()==1 &&
                 requestDoc.RootElement.GetProperty("platform").GetString()
                 =="windows-x86_64" &&
                 requestDoc.RootElement.GetProperty("operation").GetString()
                 =="upgrade" &&
                 requestDoc.RootElement.GetProperty("scopes").GetArrayLength()
                 ==2,"R935_R899_SHARED_REQUEST_NOT_TWO_SCOPE");
            var expected=Hex(bytes);
            var modified=(byte[])bytes.Clone();
            modified[0]^=1;
            var good=OneRound("DIM_R935_Isolated_"+Guid.NewGuid().ToString("N"),
                              bytes,expected,true);
            var bad=OneRound("DIM_R935_Isolated_"+Guid.NewGuid().ToString("N"),
                             modified,expected,false);
            Must(!File.Exists(Path.Combine(ProtectedRoot,
                     "untrusted-write.json")),
                 "R935_RESTRICTED_CLIENT_CREATED_UNTRUSTED_FILE");
            Console.WriteLine(JsonSerializer.Serialize(new {
                status="PASS_R935_ISOLATED_NATIVE_WIN_PIPE_CLIENT_TOKEN_PREFLIGHT",
                native_pinned_request_sha256=expected,
                reused_shared_r899_broker_request_schema=true,
                shared_policy_pins_request_sha256=true,
                request_bytes_transported_length_prefixed=true,
                successful_token_and_pinned_request=good,
                rejected_tampered_request=bad,
                os_named_pipe_acl_used=true,
                native_restricted_client_token_observed=true,
                protected_system_store_unchanged=true,
                OS_authenticated_production_broker=false,
                publisher_authenticated=false,
                native_completed_receipt_minted=false,
                replay_protected_writer_implemented=false,
                native_product_installation_accepted=false
            }));
            return 0;
        }
        catch(Exception ex)
        {
            Console.Error.WriteLine("R935_FAIL_CLOSED_"+ex.GetType().Name+
                                    "_"+ex.Message);
            return 9;
        }
    }
}
