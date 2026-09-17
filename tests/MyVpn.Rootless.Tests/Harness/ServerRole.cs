using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace MyVpn.Rootless.Harness;

/// <summary>
/// The far side of the tunnel: the core's server, and the traffic target behind it.
/// </summary>
/// <remarks>
/// <para>
/// This runs in its own network namespace, created by the client helper as a child
/// <c>unshare -n</c> and joined to the client's by a veth pair. That is what makes the topology
/// honest: the target is <i>not</i> a local address of the client's namespace (where the kernel
/// would short-circuit it into the loopback table and never let it near the tunnel), and the
/// client's only route to it is the tunnel itself.
/// </para>
/// <para>
/// <b>Address choice.</b> The target is bound to a globally routable address rather than one from
/// RFC 1918 or a documentation range, because both gates that stand between a client and a real
/// destination are range-based: the client core's LAN-bypass rule matches <c>geoip:private</c>
/// (which covers the documentation ranges), and the server core's freedom outbound blocks private
/// and reserved destinations by default. A test address outside those lists is what makes the
/// request take the same path a real one would. Nothing can leave the machine: the address is
/// assigned to a dummy interface in this namespace, so the kernel delivers to the local listener,
/// and this namespace has no default route at all.
/// </para>
/// </remarks>
internal static class ServerRole
{
    /// <summary>Address of this side of the uplink, and the client's gateway.</summary>
    public const string UplinkAddress = "10.0.0.1";

    /// <summary>Name of the veth end the client moves into this namespace.</summary>
    public const string UplinkInterface = "srv0";

    /// <summary>The traffic target's address, in the globally routable range (see the type remarks).</summary>
    public const string TargetAddress = "93.184.216.34";

    /// <summary>Port the target listens on.</summary>
    public const int TargetPort = 8080;

    public static async Task<int> RunAsync(HarnessArgs arguments, CancellationToken cancellationToken)
    {
        var work = arguments.Work;
        var readyPath = Path.Combine(work, "server-ready");
        var errorPath = Path.Combine(work, "server-error");
        var stopPath = Path.Combine(work, "server-stop");

        TargetServer? target = null;
        System.Diagnostics.Process? core = null;

        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(work, "server-started"), DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                cancellationToken).ConfigureAwait(false);

            if (!await WaitForInterfaceAsync(UplinkInterface, TimeSpan.FromSeconds(30), cancellationToken).ConfigureAwait(false))
            {
                await File.WriteAllTextAsync(
                    errorPath,
                    $"the client never moved '{UplinkInterface}' into this namespace",
                    cancellationToken).ConfigureAwait(false);

                return 2;
            }

            foreach (var command in new[]
            {
                new[] { "link", "set", "lo", "up" },
                new[] { "addr", "add", $"{UplinkAddress}/24", "dev", UplinkInterface },
                new[] { "link", "set", UplinkInterface, "up" },
                new[] { "link", "add", "target0", "type", "dummy" },
                new[] { "addr", "add", $"{TargetAddress}/32", "dev", "target0" },
                new[] { "link", "set", "target0", "up" },
            })
            {
                var result = await CommandRunner
                    .RunAsync(CommandRunner.IpBinary, command, TimeSpan.FromSeconds(10), cancellationToken)
                    .ConfigureAwait(false);

                if (!result.Succeeded)
                {
                    await File.WriteAllTextAsync(
                        errorPath,
                        $"{CommandRunner.Describe(CommandRunner.IpBinary, command)} failed: {result}",
                        cancellationToken).ConfigureAwait(false);

                    return 3;
                }
            }

            target = new TargetServer(TargetAddress, TargetPort, Path.Combine(work, "target-requests.log"));
            target.Start();

            // Evidence the client cannot collect for itself: the far side is a different network
            // namespace, so its interfaces are invisible from the client. Written to the run
            // directory instead, where the client reads it into the report.
            var addresses = await CommandRunner
                .OutputAsync(CommandRunner.IpBinary, "-brief", "address", "show")
                .ConfigureAwait(false);
            await File.WriteAllTextAsync(Path.Combine(work, "server-addresses.txt"), addresses, cancellationToken)
                .ConfigureAwait(false);

            var configPath = Path.Combine(work, "server-config.json");
            await File.WriteAllTextAsync(configPath, BuildServerConfig(arguments.UserId, arguments.ServerPort), cancellationToken)
                .ConfigureAwait(false);

            core = StartCore(arguments, configPath, Path.Combine(work, "server-core.log"));

            if (!await WaitForPortAsync(arguments.ServerPort, TimeSpan.FromSeconds(20), cancellationToken).ConfigureAwait(false))
            {
                await File.WriteAllTextAsync(
                    errorPath,
                    "the far-side core never started listening on the VLESS port",
                    cancellationToken).ConfigureAwait(false);

                return 4;
            }

            await File.WriteAllTextAsync(
                readyPath,
                string.Create(CultureInfo.InvariantCulture, $"{UplinkAddress} {TargetAddress}:{TargetPort}"),
                cancellationToken).ConfigureAwait(false);

            // Wait for the client to say it is finished. The client also kills this whole tree in
            // its own finally, so this is the graceful path rather than the only one.
            while (!cancellationToken.IsCancellationRequested && !File.Exists(stopPath))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
            }

            return 0;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (Exception ex)
        {
            try
            {
                await File.WriteAllTextAsync(errorPath, ex.ToString(), CancellationToken.None).ConfigureAwait(false);
            }
            catch (IOException)
            {
                // Reporting the failure is best effort; the exit code still says something went wrong.
            }

            return 5;
        }
        finally
        {
            if (core is not null)
            {
                CommandRunner.TryKill(core);
                core.Dispose();
            }

            if (target is not null)
            {
                await target.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>The far-side core config: one VLESS inbound, one freedom outbound.</summary>
    /// <remarks>
    /// Deliberately minimal and deliberately <i>unmodified</i>: no allow rules are added to the
    /// freedom outbound, so the request succeeds only because the target address is a normal
    /// globally routable one — which is what a real deployment looks like.
    /// </remarks>
    internal static string BuildServerConfig(string userId, int port)
    {
        var config = new Dictionary<string, object>
        {
            ["log"] = new Dictionary<string, object> { ["loglevel"] = "warning" },
            ["inbounds"] = new object[]
            {
                new Dictionary<string, object>
                {
                    ["tag"] = "in",
                    ["listen"] = UplinkAddress,
                    ["port"] = port,
                    ["protocol"] = "vless",
                    ["settings"] = new Dictionary<string, object>
                    {
                        ["clients"] = new object[] { new Dictionary<string, object> { ["id"] = userId } },
                        ["decryption"] = "none",
                    },
                },
            },
            ["outbounds"] = new object[]
            {
                new Dictionary<string, object> { ["tag"] = "direct", ["protocol"] = "freedom" },
            },
        };

        return JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
    }

    private static System.Diagnostics.Process StartCore(HarnessArgs arguments, string configPath, string logPath)
    {
        var info = new System.Diagnostics.ProcessStartInfo
        {
            FileName = arguments.Xray,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = arguments.Work,
        };

        info.ArgumentList.Add("run");
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add(configPath);

        var process = System.Diagnostics.Process.Start(info)
            ?? throw new InvalidOperationException($"could not start '{arguments.Xray}'");

        var writer = new StreamWriter(logPath, append: false) { AutoFlush = true };
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) { writer.WriteLine(e.Data); } };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) { writer.WriteLine(e.Data); } };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        return process;
    }

    private static async Task<bool> WaitForInterfaceAsync(
        string name,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
        {
            var result = await CommandRunner
                .RunAsync(CommandRunner.IpBinary, new[] { "link", "show", "dev", name }, TimeSpan.FromSeconds(5), cancellationToken)
                .ConfigureAwait(false);

            if (result.Succeeded)
            {
                return true;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
        }

        return false;
    }

    private static async Task<bool> WaitForPortAsync(int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var probe = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(2));
                await probe.ConnectAsync(IPAddress.Parse(UplinkAddress), port, cts.Token).ConfigureAwait(false);
                return true;
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(150), cancellationToken).ConfigureAwait(false);
            }
        }

        return false;
    }
}
