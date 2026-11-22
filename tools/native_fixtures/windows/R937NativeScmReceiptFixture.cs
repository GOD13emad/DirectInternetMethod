// R937. Disposable Windows Sandbox-only SCM-owned broker receipt experiment.
// Uses native Service Control Manager, Win32 peer identity, existing R899
// request/policy and R901 replay + R926 receipt *schemas*. This is NOT
// production DIM installer or publisher trust. No real DIM service is touched.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using Microsoft.Win32.SafeHandles;

internal static class R937NativeScmReceiptFixture
{
    private const string Name = "DIMR937BrokerFixtureSvc";
    private const string Root = @"C:\ProgramData\DIM_R937_ScmBrokerReceiptFixture";
    private const string Input = @"C:\DIMR937\input";
    private const string Pipe = "DIM_R937_ScmBrokerReceiptFixture_One";
    private const string Ledger = "broker-replay.json";
    private const string Receipt = "native-completed-receipt.json";
    private const int MaxBytes = 65536;
    private const uint Running = 4;
    private const uint Stopped = 1;
    private const uint Starting = 2;
    private const uint Stopping = 3;
    private const uint ServiceWin32OwnProcess = 0x10;
    private const uint AcceptStop = 1;
    private const uint AcceptShutdown = 4;
    private const uint ServiceControlStop = 1;
    private const uint ServiceControlShutdown = 5;
    private static readonly CancellationTokenSource Cancel = new();
    private static IntPtr _statusHandle = IntPtr.Zero;
    private static ServiceMainDelegate? _mainDelegate;
    private static HandlerDelegate? _handlerDelegate;

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct SERVICE_TABLE_ENTRY {
        [MarshalAs(UnmanagedType.LPWStr)] public string? serviceName;
        public ServiceMainDelegate? callback;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS {
        public uint serviceType, currentState, controlsAccepted,
            win32Exit, serviceExit, checkpoint, waitHint;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS {
        public uint serviceType, state, controls, exitCode,
            serviceExit, checkpoint, waitHint, pid, flags;
    }
    private delegate void ServiceMainDelegate(int argc, IntPtr argv);
    private delegate uint HandlerDelegate(uint control, uint eventType, IntPtr data, IntPtr context);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool StartServiceCtrlDispatcher([In] SERVICE_TABLE_ENTRY[] table);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(string name, HandlerDelegate fn, IntPtr context);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool SetServiceStatus(IntPtr statusHandle, ref SERVICE_STATUS status);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machine, string? db, uint access);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool QueryServiceStatusEx(IntPtr service, uint infoLevel,
        out SERVICE_STATUS_PROCESS status, uint length, out uint needed);
    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(string path,uint rights,
        uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES {
        public IntPtr sid;
        public uint attributes;
    }
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool OpenProcessToken(IntPtr process,uint rights,out IntPtr token);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll",SetLastError=true)]
    private static extern bool CreateRestrictedToken(IntPtr source,uint flags,
        uint disabledCount,[In] SID_AND_ATTRIBUTES[] disabled,
        uint deletedPrivilegeCount,IntPtr deletedPrivileges,uint restrictingCount,
        [In] SID_AND_ATTRIBUTES[] restricting,out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool IsTokenRestricted(IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool RevertToSelf();
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);
    private static IntPtr NativeSid(WellKnownSidType kind) {
        var sid=new SecurityIdentifier(kind,null);
        var bytes=new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes,0);
        var pointer=Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes,0,pointer,bytes.Length);
        return pointer;
    }

    private static void Require(bool ok, string reason) {
        if (!ok) throw new InvalidOperationException(reason);
    }

    private static string Hash(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static byte[] Bounded(string path) {
        var f = new FileInfo(path);
        Require(f.Exists && f.Length>0 && f.Length<=MaxBytes &&
                (f.Attributes & FileAttributes.ReparsePoint)==0,
                "R937_PINNED_FILE_INVALID");
        return File.ReadAllBytes(path);
    }
    private static JsonDocument Strict(byte[] bytes) {
        var doc = JsonDocument.Parse(bytes);
        Require(doc.RootElement.ValueKind==JsonValueKind.Object,
                "R937_JSON_ROOT_NOT_OBJECT");
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in doc.RootElement.EnumerateObject())
            Require(set.Add(p.Name),"R937_DUPLICATE_JSON_FIELD");
        return doc;
    }
    private static void ExactFields(JsonElement obj, params string[] keys) {
        var actual = new HashSet<string>(StringComparer.Ordinal);
        foreach(var p in obj.EnumerateObject())
            Require(actual.Add(p.Name),"R937_DUPLICATE_PROPERTY");
        Require(actual.SetEquals(keys),"R937_JSON_SCHEMA_KEYS_DRIFT");
    }
    private static byte[] Canonical(object content) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(content));

    private static Dictionary<string,string> Pins() {
        using var doc = Strict(Bounded(Path.Combine(Root,"pins.json")));
        var result=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(var name in new[]{"request_sha256","policy_sha256",
                      "native_intent_sha256","native_receipt_intent_sha256"}) {
            var s=doc.RootElement.GetProperty(name).GetString();
            Require(s is not null && s.Length==64 &&
                    s.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f'),
                    "R937_PIN_SHA_INVALID");
            result[name]=s!;
        }
        Require(doc.RootElement.GetProperty("scope").GetString()
                =="R937_SYNTHETIC_SCM_RECEIPT_ONLY","R937_PIN_SCOPE_INVALID");
        return result;
    }

    private static (string RequestId,string RequestHash,string PolicyHash,
        string Version,string Operation,string IntentHash) SharedContract(byte[] incoming) {
        var pins=Pins();
        var fromStore=Bounded(Path.Combine(Root,"broker-request.json"));
        var policy=Bounded(Path.Combine(Root,"broker-policy.json"));
        var native=Bounded(Path.Combine(Root,"native-intent.json"));
        Require(Hash(fromStore)==pins["request_sha256"] &&
                Hash(policy)==pins["policy_sha256"] &&
                Hash(native)==pins["native_intent_sha256"],
                "R937_OS_PROTECTED_INPUT_SHA_DRIFT");
        Require(CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(incoming),SHA256.HashData(fromStore)),
                "R937_REQUEST_SHA_MISMATCH");
        using var p=Strict(policy);
        using var r=Strict(fromStore);
        using var n=Strict(native);
        var req=r.RootElement;
        var pol=p.RootElement;
        var nat=n.RootElement;
        ExactFields(req,"schema","product","platform","version","operation","request_id","scopes");
        ExactFields(pol,"schema","product","platform","version","operation","request_sha256","scopes");
        ExactFields(nat,"schema","request_id","platform","operation","old","new","preimage_sha256","scope_pins");
        Require(req.GetProperty("schema").GetInt32()==1 &&
                pol.GetProperty("schema").GetInt32()==1 &&
                nat.GetProperty("schema").GetInt32()==1,
                "R937_SHARED_SCHEMAS_INVALID");
        string id=req.GetProperty("request_id").GetString()??"";
        string ver=req.GetProperty("version").GetString()??"";
        string act=req.GetProperty("operation").GetString()??"";
        Require(id.Length==32 && id.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f') &&
                ver=="1.5.7" && act=="upgrade" &&
                req.GetProperty("platform").GetString()=="windows-x86_64" &&
                pol.GetProperty("platform").GetString()=="windows-x86_64" &&
                nat.GetProperty("platform").GetString()=="windows-x86_64" &&
                pol.GetProperty("operation").GetString()==act &&
                nat.GetProperty("operation").GetString()==act &&
                pol.GetProperty("version").GetString()==ver &&
                nat.GetProperty("new").GetString()==ver &&
                nat.GetProperty("old").GetString()=="1.5.6" &&
                nat.GetProperty("request_id").GetString()==id &&
                pol.GetProperty("product").GetString()==req.GetProperty("product").GetString() &&
                pol.GetProperty("request_sha256").GetString()==Hash(fromStore),
                "R937_SHARED_IDENTITY_DRIFT");
        var scopes=req.GetProperty("scopes").EnumerateArray().ToArray();
        var policies=pol.GetProperty("scopes").EnumerateArray().ToArray();
        var nativeScopes=nat.GetProperty("scope_pins").EnumerateArray().ToArray();
        Require(scopes.Length==2 && policies.Length==2 && nativeScopes.Length==2,
                "R937_EXACT_TWO_MANAGED_SCOPES_REQUIRED");
        for (int i=0;i<2;i++) {
            var code=scopes[i].GetProperty("name").GetString();
            var digest=scopes[i].GetProperty("manifest_sha256").GetString();
            Require(code == (i==0?"code":"user") &&
                    policies[i].GetProperty("name").GetString()==code &&
                    nativeScopes[i].GetProperty("name").GetString()==code &&
                    policies[i].GetProperty("manifest_sha256").GetString()==digest &&
                    nativeScopes[i].GetProperty("manifest_sha256").GetString()==digest,
                    "R937_SHARED_TWO_SCOPE_PIN_DRIFT");
        }
        Require(Hash(native)==pins["native_intent_sha256"],
                "R937_R926_NATIVE_INTENT_SOURCE_CHANGED");
        // R926 canonical intent SHA is generated by the existing native_receipt
        // Python kernel from independently staged canonical fixture bytes.
        Require(pins["native_receipt_intent_sha256"].Length==64,
                "R937_R926_NATIVE_RECEIPT_INTENT_PIN_MISSING");
        return (id,Hash(fromStore),Hash(policy),ver,act,
                pins["native_receipt_intent_sha256"]);
    }

    private static void SetState(uint state, uint accepted=0) {
        var item=new SERVICE_STATUS {
            serviceType=ServiceWin32OwnProcess,
            currentState=state,
            controlsAccepted=accepted,
            win32Exit=0,
            serviceExit=0,
            checkpoint=0,
            waitHint=(state is Starting or Stopping)?4000u:0u
        };
        Require(SetServiceStatus(_statusHandle,ref item),
                "R937_SCM_SET_STATUS_FAILED");
    }

    private static void HealthCheckScm() {
        IntPtr manager=OpenSCManager(null,null,0x0001);
        Require(manager!=IntPtr.Zero,"R937_OPEN_SCM_FAILED");
        try {
            IntPtr svc=OpenService(manager,Name,0x0004);
            Require(svc!=IntPtr.Zero,"R937_OPEN_SCM_SERVICE_FAILED");
            try {
                Require(QueryServiceStatusEx(svc,0,out var status,
                    (uint)Marshal.SizeOf<SERVICE_STATUS_PROCESS>(),out _),
                    "R937_NATIVE_SCM_QUERY_FAILED");
                Require(status.state==Running &&
                        status.serviceType==ServiceWin32OwnProcess &&
                        status.pid==(uint)Environment.ProcessId,
                        "R937_NATIVE_SCM_PID_OR_RUNNING_STATE_INVALID");
            } finally { CloseServiceHandle(svc); }
        } finally { CloseServiceHandle(manager); }
    }

    private static PipeSecurity PipeDacl() {
        var acl=new PipeSecurity();
        var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
        var admin=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
        var users=new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid,null);
        var network=new SecurityIdentifier(WellKnownSidType.NetworkSid,null);
        acl.SetOwner(system);
        acl.SetAccessRuleProtection(true,false);
        acl.AddAccessRule(new PipeAccessRule(system,PipeAccessRights.FullControl,AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(admin,PipeAccessRights.FullControl,AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(users,
             PipeAccessRights.ReadData | PipeAccessRights.WriteData |
             PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize,
             AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(network,PipeAccessRights.ReadWrite,AccessControlType.Deny));
        return acl;
    }

    private static byte[] ReadFrame(Stream stream) {
        byte[] h=new byte[4];
        stream.ReadExactly(h);
        int size=BinaryPrimitives.ReadInt32LittleEndian(h);
        Require(size>0 && size<=MaxBytes,"R937_RPC_FRAME_SIZE_INVALID");
        byte[] data=new byte[size];
        stream.ReadExactly(data);
        return data;
    }
    private static void WriteFrame(Stream stream, byte[] content) {
        Require(content.Length>0 && content.Length<=4096,"R937_RESPONSE_FRAME_INVALID");
        byte[] h=new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(h,content.Length);
        stream.Write(h);
        stream.Write(content);
        stream.Flush();
    }

    private static byte[] ReadLedger() {
        var bytes=Bounded(Path.Combine(Root,Ledger));
        using var doc=Strict(bytes);
        var obj=doc.RootElement;
        ExactFields(obj,"schema","platform","used_request_ids","active");
        Require(obj.GetProperty("schema").GetInt32()==1 &&
                obj.GetProperty("platform").GetString()=="windows-x86_64",
                "R937_R901_LEDGER_SCHEMA_INVALID");
        return bytes;
    }

    private static (List<string> used, bool pending) LedgerState() {
        using var doc=Strict(ReadLedger());
        var obj=doc.RootElement;
        var ids=obj.GetProperty("used_request_ids").EnumerateArray()
            .Select(x=>x.GetString()??"").ToList();
        Require(ids.Count<=256 && ids.Distinct(StringComparer.Ordinal).Count()==ids.Count &&
                ids.All(x=>x.Length==32),
                "R937_R901_REPLAY_USED_IDS_INVALID");
        return (ids,obj.GetProperty("active").ValueKind!=JsonValueKind.Null);
    }

    private static void AtomicLedger(object payload) {
        byte[] content=Canonical(payload);
        var ledger=Path.Combine(Root,Ledger);
        var temp=Path.Combine(Root,".r937-"+Guid.NewGuid().ToString("N")+".tmp");
        try {
            using(var fs=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,
                       FileShare.None,4096,FileOptions.WriteThrough)) {
                fs.Write(content);
                fs.Flush(true);
            }
            File.Replace(temp,ledger,null,true);
        } finally {
            if(File.Exists(temp)) File.Delete(temp);
        }
    }
    private static object Replay(List<string> ids, object? active) =>
       new {schema=1,platform="windows-x86_64",used_request_ids=ids,active};

    private static string Respond(byte[] bytes, bool clientAuthenticated) {
        Require(clientAuthenticated,"R937_NATIVE_OS_CLIENT_IDENTITY_REJECTED");
        var contract=SharedContract(bytes);
        var (ids,pending)=LedgerState();
        Require(!pending,"R937_PENDING_NATIVE_REQUEST_REQUIRES_RECOVERY");
        Require(!ids.Contains(contract.RequestId,StringComparer.Ordinal),
                "R937_REQUEST_REPLAY_DENIED");
        Require(ids.Count<256,"R937_LEDGER_CAPACITY_EXHAUSTED");
        // From this point only SYSTEM's own worker writes under a protected
        // filesystem owner. Any crash leaves active state and refuses replay.
        ids.Add(contract.RequestId);
        var identity=new {
           request_id=contract.RequestId,
           request_sha256=contract.RequestHash,
           policy_sha256=contract.PolicyHash,
           version=contract.Version,
           operation=contract.Operation,
           phase="reserved"
        };
        AtomicLedger(Replay(ids,identity));
        AtomicLedger(Replay(ids,new {
           identity.request_id,identity.request_sha256,identity.policy_sha256,
           identity.version,identity.operation,phase="applying"
        }));
        HealthCheckScm();
        var receipt=Canonical(new {
            schema=1,status="completed",
            intent_sha256=contract.IntentHash
        });
        var receiptPath=Path.Combine(Root,Receipt);
        Require(!File.Exists(receiptPath),
                "R937_NATIVE_RECEIPT_ALREADY_PRESENT");
        using(var fs=new FileStream(receiptPath,FileMode.CreateNew,FileAccess.Write,
            FileShare.None,4096,FileOptions.WriteThrough)) {
            fs.Write(receipt);
            fs.Flush(true);
        }
        AtomicLedger(Replay(ids,null));
        return "COMPLETED_SYNTHETIC_SCM_POSTFLIGHT";
    }

    private static void Worker() {
        using var own=WindowsIdentity.GetCurrent();
        Require(own.User?.Value=="S-1-5-18","R937_NOT_SCM_SYSTEM_IDENTITY");
        Require(Directory.Exists(@"C:\Users\WDAGUtilityAccount"),
                "R937_NOT_IN_SANDBOX");
        Require(Directory.Exists(Root) && Directory.Exists(Input),
                "R937_FIXTURE_ROOT_NOT_PREPROVISIONED");
        HealthCheckScm();
        bool first=true;
        while (!Cancel.IsCancellationRequested) {
            using var server=NamedPipeServerStreamAcl.Create(Pipe,
                PipeDirection.InOut,1,PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,8192,8192,PipeDacl());
            if (first) {
                File.WriteAllText(Path.Combine(Root,"ready.txt"),
                    Environment.ProcessId.ToString());
                first=false;
            }
            try { server.WaitForConnectionAsync(Cancel.Token).GetAwaiter().GetResult(); }
            catch(OperationCanceledException) { break; }
            bool trusted=false;
            uint peerPid=0;
            try {
                byte[] message=ReadFrame(server);
                Require(GetNamedPipeClientProcessId(
                    server.SafePipeHandle.DangerousGetHandle(),out peerPid),
                    "R937_NATIVE_CLIENT_PID_QUERY_FAILED");
                server.RunAsClient(() => {
                    using var id=WindowsIdentity.GetCurrent(true);
                    // Native restricted thread token, not a client JSON
                    // field or bare PID. The fixture launcher starts as SYSTEM
                    // but drops access via Windows CreateRestrictedToken before
                    // opening a pipe in its own independent client process.
                    trusted=id.User is not null &&
                            IsTokenRestricted(id.AccessToken.DangerousGetHandle());
                });
                Require(peerPid!=0 && peerPid!=(uint)Environment.ProcessId,
                    "R937_CLIENT_NOT_INDEPENDENT_PROCESS");
                using var after=WindowsIdentity.GetCurrent();
                Require(after.User?.Value=="S-1-5-18",
                    "R937_SCM_IMPERSONATION_NOT_REVERTED");
                var response=Respond(message,trusted);
                WriteFrame(server,Canonical(new{result=response,synthetic_only=true}));
            }
            catch(Exception err) {
                var reason=err.Message;
                try { WriteFrame(server,Canonical(new{
                    result="DENIED",reason,synthetic_only=true
                })); } catch {}
            }
        }
    }

    private static void ServiceMain(int argc, IntPtr argv) {
        _statusHandle=RegisterServiceCtrlHandlerEx(Name,_handlerDelegate!,IntPtr.Zero);
        if(_statusHandle==IntPtr.Zero) return;
        try {
            SetState(Starting);
            SetState(Running,AcceptStop|AcceptShutdown);
            var work=System.Threading.Tasks.Task.Run(Worker);
            while(!Cancel.IsCancellationRequested && !work.IsCompleted)
                Thread.Sleep(100);
            if(work.IsFaulted) {
                try {
                    File.WriteAllText(Path.Combine(Root,"service-error.txt"),
                                      work.Exception?.ToString()??"FAULTED");
                } catch {}
            }
            SetState(Stopping);
            Cancel.Cancel();
            work.Wait(3000);
            SetState(Stopped);
        } catch(Exception err) {
            try { File.WriteAllText(Path.Combine(Root,"service-error.txt"),err.ToString()); } catch {}
            try {SetState(Stopped);}catch{}
        }
    }

    private static uint Handle(uint signal,uint eventType,IntPtr data,IntPtr context) {
        if(signal==ServiceControlStop || signal==ServiceControlShutdown)
            Cancel.Cancel();
        return 0;
    }

    private static int Client(string mode) {
        string stage="prepare";
        IntPtr original=IntPtr.Zero, restricted=IntPtr.Zero;
        IntPtr admins=IntPtr.Zero, users=IntPtr.Zero;
        bool impersonating=false;
        try {
            using var system=WindowsIdentity.GetCurrent();
            Require(system.User?.Value=="S-1-5-18" &&
                    Directory.Exists(@"C:\Users\WDAGUtilityAccount"),
                    "R937_ISOLATED_SYSTEM_TEST_LAUNCHER_REQUIRED");
            Require(mode is "good" or "tampered" or "replay",
                    "R937_CLIENT_MODE_INVALID");
            // Synthetic, OS-read-only input payload is prepared BEFORE
            // restricting this test process; no protected write follows.
            stage="synthetic-request-source";
            byte[] payload=Bounded(Path.Combine(Input,"broker-request.json"));
            if(mode=="tampered") payload[0]^=1;
            stage="native-restricted-process-token";
            Require(OpenProcessToken(GetCurrentProcess(),0x0008|0x0002|0x0004,
                                     out original),
                    "R937_OS_CLIENT_SOURCE_TOKEN_MISSING");
            admins=NativeSid(WellKnownSidType.BuiltinAdministratorsSid);
            users=NativeSid(WellKnownSidType.BuiltinUsersSid);
            var disable=new [] {new SID_AND_ATTRIBUTES{sid=admins,attributes=0}};
            var restrict=new [] {new SID_AND_ATTRIBUTES{sid=users,attributes=0}};
            Require(CreateRestrictedToken(original,1,1,disable,0,IntPtr.Zero,
                                          1,restrict,out restricted),
                    "R937_CREATE_RESTRICTED_OS_TOKEN_FAILED");
            Require(IsTokenRestricted(restricted),
                    "R937_NATIVE_RESTRICTED_TOKEN_REQUIRED");
            Require(ImpersonateLoggedOnUser(restricted),
                    "R937_THREAD_IMPERSONATE_RESTRICTED_TOKEN_FAILED");
            impersonating=true;
            bool protectedWriteDenied=false;
            string result,reason;
            try {
                stage="native-client-thread-and-file-acl";
                using var current=WindowsIdentity.GetCurrent(true);
                Require(current.User is not null &&
                        IsTokenRestricted(current.AccessToken.DangerousGetHandle()),
                        "R937_EFFECTIVE_THREAD_RESTRICTION_NOT_VERIFIED");
                try {
                    File.WriteAllText(Path.Combine(Root,"untrusted-forged-receipt.json"),
                        "CLIENT_FORGED");
                } catch(UnauthorizedAccessException) {protectedWriteDenied=true;}
                  catch(IOException) {protectedWriteDenied=true;}
                Require(protectedWriteDenied,
                        "R937_RESTRICTED_CLIENT_CAN_FORGE_PROTECTED_RECEIPT");
                // Microsoft's CreateFileW named-pipe client pattern requests
                // only FILE_READ_DATA|FILE_WRITE_DATA|SYNCHRONIZE, never
                // GENERIC_WRITE (which includes CREATE_PIPE_INSTANCE).
                stage="native-restricted-client-pipe-createfile";
                using var handle=CreateFileW(@"\\.\pipe\"+Pipe,
                    0x00000001|0x00000002|0x00100000,
                    0,IntPtr.Zero,3,0,IntPtr.Zero);
                Require(!handle.IsInvalid,"R937_OS_PIPE_CLIENT_CREATEFILE_DENIED_"+
                        Marshal.GetLastWin32Error());
                using var client=new FileStream(handle,FileAccess.ReadWrite,4096,false);
                stage="native-restricted-bounded-pipe-rpc";
                WriteFrame(client,payload);
                using var response=Strict(ReadFrame(client));
                result=response.RootElement.GetProperty("result").GetString()??"";
                reason=response.RootElement.TryGetProperty("reason",out var value)
                        ? value.GetString()??"" : "";
            } finally {
                Require(RevertToSelf(),
                        "R937_RESTRICTED_CLIENT_THREAD_REVERSION_FAILED");
                impersonating=false;
            }
            using var restored=WindowsIdentity.GetCurrent();
            Require(restored.User?.Value=="S-1-5-18",
                    "R937_CLIENT_LAUNCHER_OS_THREAD_TOKEN_NOT_RESTORED");
            bool accepted=result=="COMPLETED_SYNTHETIC_SCM_POSTFLIGHT";
            if(mode=="good")
                Require(accepted,"R937_CLIENT_SYNTHETIC_SCM_RECEIPT_NOT_RETURNED_"+reason);
            else if(mode=="tampered")
                Require(result=="DENIED" &&
                        reason=="R937_REQUEST_SHA_MISMATCH",
                        "R937_CLIENT_TAMPER_NOT_REJECTED_"+reason);
            else Require(result=="DENIED" &&
                         reason=="R937_REQUEST_REPLAY_DENIED",
                         "R937_CLIENT_REPLAY_NOT_REJECTED_"+reason);
            Console.WriteLine(JsonSerializer.Serialize(new {
                schema=1,status="PASS_R937_DIFFERENT_PROCESS_NATIVE_RESTRICTED_CLIENT",
                mode,
                token_owner_sid=system.User!.Value,
                independent_client_process_id=Environment.ProcessId,
                OS_restricted_client_token_verified=true,
                separate_real_non_system_login_verified=false,
                protected_receipt_forgery_denied=protectedWriteDenied,
                native_scm_owned_broker_result=result,
                rejection_reason=reason,
                native_product_installation_accepted=false,
                independent_publisher_authenticated=false
            }));
            return 0;
        } catch(Exception ex) {
            Console.Error.WriteLine("R937_CLIENT_FAIL_CLOSED_"+stage+"_"+ex.Message);
            return 31;
        } finally {
            if(impersonating) RevertToSelf();
            if(restricted!=IntPtr.Zero) CloseHandle(restricted);
            if(original!=IntPtr.Zero) CloseHandle(original);
            if(admins!=IntPtr.Zero) Marshal.FreeHGlobal(admins);
            if(users!=IntPtr.Zero) Marshal.FreeHGlobal(users);
        }
    }

    private static int Main(string[] args) {
        if(args.Length==2 && args[0]=="--client")
            return Client(args[1]);
        if(args.Length==1 && args[0]=="--version") {
            Console.WriteLine("R937-SYNTHETIC-SCM-BROKER-NO-PRODUCT");
            return 0;
        }
        if(args.Length!=0) return 30;
        _mainDelegate=ServiceMain;
        _handlerDelegate=Handle;
        var entries=new[] {
            new SERVICE_TABLE_ENTRY{serviceName=Name,callback=_mainDelegate},
            new SERVICE_TABLE_ENTRY{serviceName=null,callback=null}
        };
        if(!StartServiceCtrlDispatcher(entries)) return Marshal.GetLastWin32Error();
        return 0;
    }
}
