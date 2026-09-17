using Microsoft.Extensions.Logging;

namespace MyVpn.Rootless.Harness;

/// <summary>
/// Keeps every log line MyVpn emits, so the test can quote what the application itself said.
/// </summary>
/// <remarks>
/// No provider is registered: the point is not to render logs but to retain them. A test that only
/// looks at exit codes cannot tell "the kill switch was armed" from "the kill switch was skipped
/// because the process was not privileged", and that distinction is exactly what the report has to
/// survive.
/// </remarks>
internal sealed class RecordingLoggerFactory : ILoggerFactory
{
    private readonly List<string> _lines = new();
    private readonly object _gate = new();

    public IReadOnlyList<string> Lines
    {
        get
        {
            lock (_gate)
            {
                return _lines.ToArray();
            }
        }
    }

    public ILogger CreateLogger(string categoryName) => new RecordingLogger(categoryName, Add);

    public void AddProvider(ILoggerProvider provider)
    {
        // Not used: records are kept in memory.
    }

    public void Dispose()
    {
        // Nothing to release.
    }

    private void Add(string line)
    {
        lock (_gate)
        {
            _lines.Add(line);
        }
    }

    private sealed class RecordingLogger : ILogger
    {
        private readonly string _category;
        private readonly Action<string> _sink;

        public RecordingLogger(string category, Action<string> sink)
        {
            _category = category;
            _sink = sink;
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);

            var message = formatter(state, exception);
            _sink(exception is null
                ? $"[{logLevel}] {_category}: {message}"
                : $"[{logLevel}] {_category}: {message} ({exception.GetType().Name}: {exception.Message})");
        }
    }
}
