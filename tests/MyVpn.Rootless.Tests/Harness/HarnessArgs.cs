namespace MyVpn.Rootless.Harness;

/// <summary>
/// The harness command line.
/// </summary>
/// <remarks>
/// Parsed by hand from an argv vector. The client helper re-launches this same assembly inside a
/// child namespace, so every value it forwards is an argv element — there is no shell to quote
/// for and therefore no quoting bug to have.
/// </remarks>
internal sealed record HarnessArgs
{
    public const string ClientRole = "client";
    public const string ServerRoleName = "server";

    /// <summary><c>client</c> (the namespace that connects) or <c>server</c> (the far side).</summary>
    public required string Role { get; init; }

    /// <summary>Throwaway directory for the run's files.</summary>
    public required string Work { get; init; }

    /// <summary>Path of the real core binary.</summary>
    public required string Xray { get; init; }

    /// <summary>VLESS credential shared by both sides.</summary>
    public required string UserId { get; init; }

    /// <summary>Port of the far side's VLESS inbound.</summary>
    public required int ServerPort { get; init; }

    /// <summary><c>off</c> or <c>on-demand</c>.</summary>
    public required string KillSwitch { get; init; }

    /// <summary>Path of the <c>dotnet</c> host, used to re-launch this assembly in the child namespace.</summary>
    public string Dotnet { get; init; } = string.Empty;

    /// <summary>Path of this assembly, used to re-launch it in the child namespace.</summary>
    public string HarnessPath { get; init; } = string.Empty;

    public static bool TryParse(string[] args, out HarnessArgs parsed, out string error)
    {
        parsed = new HarnessArgs
        {
            Role = string.Empty,
            Work = string.Empty,
            Xray = string.Empty,
            UserId = string.Empty,
            ServerPort = 8443,
            KillSwitch = "off",
        };

        error = string.Empty;
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        string? role = null;

        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];

            if (!argument.StartsWith("--", StringComparison.Ordinal))
            {
                // The first bare word is the role; anything else is a typo worth reporting.
                if (role is null && index == 0)
                {
                    role = argument;
                    continue;
                }

                error = $"unexpected argument '{argument}'";
                return false;
            }

            if (index + 1 >= args.Length)
            {
                error = $"'{argument}' needs a value";
                return false;
            }

            values[argument] = args[++index];
        }

        if (role is not ClientRole and not ServerRoleName)
        {
            error = $"the first argument must be '{ClientRole}' or '{ServerRoleName}'";
            return false;
        }

        if (!values.TryGetValue("--work", out var work) || string.IsNullOrWhiteSpace(work))
        {
            error = "--work <directory> is required";
            return false;
        }

        if (!values.TryGetValue("--xray", out var xray) || !File.Exists(xray))
        {
            error = "--xray <path> must name an existing binary";
            return false;
        }

        if (!values.TryGetValue("--user-id", out var userId) || string.IsNullOrWhiteSpace(userId))
        {
            error = "--user-id <uuid> is required";
            return false;
        }

        var port = 8443;
        if (values.TryGetValue("--server-port", out var portText)
            && !int.TryParse(portText, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out port))
        {
            error = "--server-port must be a number";
            return false;
        }

        var killSwitch = values.TryGetValue("--kill-switch", out var mode) ? mode : "off";
        if (killSwitch is not ("off" or "on-demand"))
        {
            error = "--kill-switch must be 'off' or 'on-demand'";
            return false;
        }

        parsed = new HarnessArgs
        {
            Role = role,
            Work = work,
            Xray = xray,
            UserId = userId,
            ServerPort = port,
            KillSwitch = killSwitch,
            Dotnet = values.TryGetValue("--dotnet", out var dotnet) ? dotnet : string.Empty,
            HarnessPath = values.TryGetValue("--harness", out var harness) ? harness : string.Empty,
        };

        return true;
    }
}
