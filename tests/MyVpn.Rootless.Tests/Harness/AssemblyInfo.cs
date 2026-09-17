using System.Runtime.CompilerServices;

// The test project starts this assembly as a process in its own namespaces and reads the report it
// writes; sharing the fixture constants (the tunnel name, the target address) keeps the assertions
// and the rig from drifting apart.
[assembly: InternalsVisibleTo("MyVpn.Rootless.Tests")]
