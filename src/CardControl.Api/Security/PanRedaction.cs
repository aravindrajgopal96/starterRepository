using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;

namespace CardControl.Api.Security;

/// <summary>
/// Replaces anything that looks like a card number (12-19 digits, optionally separated, passing Luhn).
/// This is a safety net: nothing is meant to log a PAN in the first place.
/// It errs towards redacting too much.
/// </summary>
public static partial class PanRedactor
{
    public const string Placeholder = "[REDACTED PAN]";

    [GeneratedRegex(@"(?<![0-9])[0-9](?:[ -]?[0-9]){11,18}(?![0-9])")]
    private static partial Regex Candidate();

    public static string Redact(string text) => Candidate().Replace(text, match =>
    {
        var digits = match.Value.Where(char.IsAsciiDigit).Select(c => (byte)c).ToArray();
        return Luhn.IsPan(digits) ? Placeholder : match.Value;
    });
}

/// <summary>Wraps the JSON console formatter so every line, including exceptions and scopes, is redacted.</summary>
public sealed class RedactingJsonConsoleFormatter : ConsoleFormatter, IDisposable
{
    public const string FormatterName = "redacting-json";

    private readonly ConsoleFormatter _inner;

    public RedactingJsonConsoleFormatter(IOptionsMonitor<JsonConsoleFormatterOptions> options) : base(FormatterName)
    {
        // JsonConsoleFormatter is internal to the framework, so it is obtained through its own registration.
        var provider = new ServiceCollection()
            .AddLogging(b => b.AddJsonConsole())
            .AddSingleton(options)
            .BuildServiceProvider();
        _inner = provider.GetServices<ConsoleFormatter>().First(f => f.Name == ConsoleFormatterNames.Json);
        _provider = provider;
    }

    private readonly ServiceProvider _provider;

    public override void Write<TState>(in LogEntry<TState> logEntry, IExternalScopeProvider? scopeProvider, TextWriter textWriter)
    {
        using var buffer = new StringWriter(new StringBuilder(256));
        _inner.Write(in logEntry, scopeProvider, buffer);
        textWriter.Write(PanRedactor.Redact(buffer.ToString()));
    }

    public void Dispose() => _provider.Dispose();
}
