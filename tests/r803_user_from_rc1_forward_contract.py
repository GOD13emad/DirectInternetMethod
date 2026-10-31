#!/usr/bin/env python3
"""R803: real user transaction from accepted private 1.5.5-rc1 to 1.5.7.

Strictly user-owned temporary HOME; no physical install, pkexec, network,
systemd, DNS, Tailscale, external browser, or release publication.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib,json,os,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
TX=ROOT/"linux/app/user_update_transaction.py"
PACKAGE_SOURCE=ROOT/"linux"
KNOWN=("direct_internet_method.py","socket_fallback.py","router_gateway.py",
       "router_gateway_core.py","direct-internet-method.svg","uninstall.sh",
       "user_uninstall_preserve.py","user_update_transaction.py")
MUTABLE=("settings.json","strategy.txt","scope.txt","custom-hosts.txt",
         "adult-enabled.txt","adult-hosts.txt","adult-hosts.meta.json",
         "encrypted-dns-optin.txt","selective-dns-optin.txt")
H=lambda b:hashlib.sha256(b).hexdigest()
def need(x,why):
 if not x:raise AssertionError(why)
def invoke(home,cmd,expected=True):
 env=dict(os.environ,HOME=str(home),PYTHONDONTWRITEBYTECODE="1")
 args=[sys.executable,"-B",str(TX),cmd]
 if cmd in ("--stage","--apply"):args+=["--source",str(PACKAGE_SOURCE)]
 p=subprocess.run(args,env=env,capture_output=True,text=True,timeout=12)
 need((p.returncode==0)==expected,cmd+" "+p.stderr[-350:])
 return p
def initialize(home,manage_provider):
 app=home/".local/share/DirectInternetMethod";app.mkdir(parents=True)
 (app/"router_gateway").mkdir()
 managed={}
 for i,name in enumerate(KNOWN):
  raw=("EXISTING_RC1_CODE_"+str(i)+"\n").encode()
  (app/name).write_bytes(raw);managed[name]=H(raw)
 provider=app/"router_gateway/providers.json"
 provider.write_bytes(b'{"previousProvider":"keep"}\n')
 md5=H(provider.read_bytes()) if manage_provider else None
 preserved={}
 for i,name in enumerate(MUTABLE):
  raw=("PRIVATE_SETTINGS_"+str(i)+"\n").encode()
  if i%3: (app/name).write_bytes(raw);preserved[name]=H(raw)
  else:preserved[name]=None
 metadata={"schema":2,"product":"Direct Internet Method",
           "version":"1.5.5-rc1","managedProviderSha256":md5,
           "managedCodeSha256":managed,"managedLaunchersSha256":{}}
 (app/"INSTALL.json").write_text(json.dumps(metadata,sort_keys=True)+"\n")
 return app,metadata,preserved,H(provider.read_bytes())
def finalize_metadata(app,source_manifest):
 installed={
    "schema":2,"version":"1.5.7",
    "managedProviderSha256":source_manifest["providerSha"],
    "managedCodeSha256":{name:row["sha"] for name,row in source_manifest["managed"].items()
                         if name!="router_gateway/providers.json"},
    "managedLaunchersSha256":{}
 }
 (app/"INSTALL.json").write_text(json.dumps(installed,sort_keys=True)+"\n")
def verify_settings(app,preserved):
 for key,expected in preserved.items():
  p=app/key
  got=H(p.read_bytes()) if p.exists() else None
  need(got==expected,"MUTABLE_DRIFT_"+key)
def case(label,manage_provider,commit):
 with TemporaryDirectory(prefix="DIM_R803_USER_RC1_FAKE_HOME_") as td:
  home=Path(td)/"home";home.mkdir()
  app,prior,preserved,provider_sha=initialize(home,manage_provider)
  original={n:(app/n).read_bytes() for n in KNOWN}
  original_provider=(app/"router_gateway/providers.json").read_bytes()
  original_meta=(app/"INSTALL.json").read_bytes()
  invoke(home,"--stage")
  pending=home/".local/state/DirectInternetMethod/update-pending"
  manifest=json.loads((pending/"manifest.json").read_text())
  need(manifest["version"]=="1.5.7" and manifest["previousVersion"]=="1.5.5-rc1","INCORRECT_RC1_PREDECESSOR")
  need(manifest["providerManaged"] is manage_provider,"PROVIDER_MANAGED_POLICY")
  need(len(manifest["managed"])==(9 if manage_provider else 8),"MANAGED_CARDINALITY")
  invoke(home,"--apply")
  verify_settings(app,preserved)
  if commit:
   finalize_metadata(app,manifest)
   invoke(home,"--commit")
   need(json.loads((app/"INSTALL.json").read_text())["version"]=="1.5.7","RC1_FORWARD_VERSION")
   for name,row in manifest["managed"].items():
    need(H((app/name).read_bytes())==row["sha"],"NEW_MANAGED_SHA_"+name)
   if not manage_provider:
    need((app/"router_gateway/providers.json").read_bytes()==original_provider,"CUSTOM_PROVIDER_LOST")
  else:
   invoke(home,"--rollback")
   for name,raw in original.items():
    need((app/name).read_bytes()==raw,"OLD_RC1_SOURCE_NOT_RESTORED_"+name)
   need((app/"INSTALL.json").read_bytes()==original_meta,"OLD_RC1_METADATA_NOT_RESTORED")
   need((app/"router_gateway/providers.json").read_bytes()==original_provider,"OLD_PROVIDER_NOT_RESTORED")
  need(not pending.exists(),"PENDING_STAGING_REMAINS")
  verify_settings(app,preserved)
  print("PASS_R803_USER_FROM_RC1",label,"settings",len(preserved),"managed",len(manifest["managed"]))
for m in (False,True):
 for c in (False,True):
  case("managedProvider="+str(m)+"/commit="+str(c),m,c)
print("R803_RC1_USER_FORWARD_AND_ROLLBACK",4,"PASS")
