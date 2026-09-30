import subprocess,time,json,os
out=os.path.join(os.environ.get("TEMP","."),"dim-fast-netmon.jsonl")
try: os.remove(out)
except FileNotFoundError: pass
end=time.time()+8
seen=set()
while time.time()<end:
    ts=time.time()
    try:
        ps=subprocess.run(["tasklist","/fo","csv","/nh"],capture_output=True,text=True,timeout=1).stdout
        ctrld=[]
        for line in ps.splitlines():
            if line.lower().startswith('"ctrld.exe"'):
                ctrld.append(line)
        ns=subprocess.run(["netstat","-ano"],capture_output=True,text=True,timeout=1).stdout
        lines=[x.strip() for x in ns.splitlines() if ":53" in x]
        ip=subprocess.run(["powershell.exe","-NoProfile","-Command","(Get-NetIPAddress -InterfaceIndex 1 -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object IPAddress -eq 'fd53:4444:48::53').IPAddress"],capture_output=True,text=True,timeout=1).stdout.strip()
        key=(tuple(ctrld),tuple(lines),ip)
        if key not in seen:
            seen.add(key)
            with open(out,"a",encoding="utf-8") as f:
                f.write(json.dumps({"t":ts,"ctrld":ctrld,"netstat":lines,"ula":ip})+"\n")
    except Exception as e:
        pass
    time.sleep(.08)
print(out)
