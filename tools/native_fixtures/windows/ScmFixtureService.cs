// Isolated SCM test service only. Never register against the installed DIM service.
// Compile twice with VERSION_157 / default VERSION_156 using .NET Framework csc.exe.
using System;
using System.IO;
using System.ServiceProcess;

internal static class NativeFixture
{
    internal const string ServiceName = "DIMR887IsolatedFixtureSvc";
#if VERSION_157
    internal const string Version = "1.5.7";
#else
    internal const string Version = "1.5.6";
#endif

    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--version")
        {
            Console.WriteLine(Version);
            return 0;
        }

        ServiceBase.Run(new FixtureService());
        return 0;
    }

    private sealed class FixtureService : ServiceBase
    {
        private static readonly string MarkerRoot = @"C:\ProgramData\DIM_R887_SCMSandboxFixture";
        public FixtureService()
        {
            ServiceName = NativeFixture.ServiceName;
            CanStop = true;
            AutoLog = false;
        }

        protected override void OnStart(string[] args)
        {
            Directory.CreateDirectory(MarkerRoot);
            File.WriteAllText(Path.Combine(MarkerRoot, "active-version.txt"),
                              NativeFixture.Version);
        }

        protected override void OnStop()
        {
            Directory.CreateDirectory(MarkerRoot);
            File.WriteAllText(Path.Combine(MarkerRoot, "last-stop.txt"),
                              NativeFixture.Version);
        }
    }
}
