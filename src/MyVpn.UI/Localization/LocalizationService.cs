using System.Globalization;
using System.Reflection;
using System.Text.Json;

namespace MyVpn.UI.Localization;

/// <summary>Plural category, following the CLDR naming used by .NET and ICU.</summary>
public enum PluralCategory
{
    One,
    Few,
    Many,
    Other,
}

/// <summary>
/// Selects the plural form for a language.
/// </summary>
/// <remarks>
/// This is not a nicety. Russian needs three distinct forms and the choice depends on the
/// number in a way that English speakers routinely get wrong: 1 форма, 2 формы, 5 форм — and
/// crucially 11, 12, 13, 14 take the "many" form despite ending in 1–4. Hard-coding
/// "singular for 1, plural otherwise" produces visibly broken Russian, which is why the rule
/// is implemented and unit-testable rather than being left to string concatenation.
/// </remarks>
public static class Pluralizer
{
    /// <summary>Categories required by each supported language.</summary>
    public static IReadOnlyList<PluralCategory> CategoriesFor(string languageCode) =>
        Normalize(languageCode) switch
        {
            "ru" or "uk" or "be" => new[] { PluralCategory.One, PluralCategory.Few, PluralCategory.Many, PluralCategory.Other },
            "zh" => new[] { PluralCategory.Other },
            _ => new[] { PluralCategory.One, PluralCategory.Other },
        };

    public static PluralCategory CategoryFor(string languageCode, long count)
    {
        var language = Normalize(languageCode);
        var n = Math.Abs(count);

        return language switch
        {
            "ru" or "uk" or "be" => RussianCategory(n),
            "zh" => PluralCategory.Other,
            _ => n == 1 ? PluralCategory.One : PluralCategory.Other,
        };
    }

    private static PluralCategory RussianCategory(long n)
    {
        var mod10 = n % 10;
        var mod100 = n % 100;

        if (mod10 == 1 && mod100 != 11)
        {
            return PluralCategory.One;
        }

        if (mod10 is >= 2 and <= 4 && mod100 is < 12 or > 14)
        {
            return PluralCategory.Few;
        }

        // 0 and everything ending in 5-9 or 11-14.
        return PluralCategory.Many;
    }

    /// <summary>Maps an <see cref="AppLanguage"/>-style code onto the resource file name.</summary>
    public static string Normalize(string? languageCode)
    {
        if (string.IsNullOrWhiteSpace(languageCode))
        {
            return "en";
        }

        var value = languageCode.Replace('_', '-').ToLowerInvariant();

        // Treat Simplified Chinese and any zh-* variant as "zh".
        if (value.StartsWith("zh", StringComparison.Ordinal))
        {
            return "zh";
        }

        var dash = value.IndexOf('-');
        return dash > 0 ? value[..dash] : value;
    }
}

/// <summary>
/// Runtime-switchable localization backed by embedded JSON dictionaries.
/// </summary>
/// <remarks>
/// <para>
/// JSON rather than <c>.resx</c> because the requirement is to switch language without
/// restarting. <c>.resx</c> is consumed through generated strongly-typed accessors bound via
/// <c>x:Static</c>, which is resolved once when the view tree is built; making it re-read on
/// change means either rebuilding the UI or hand-writing a binding layer. A dictionary behind
/// an observable service avoids the whole problem.
/// </para>
/// <para>
/// Fallback is explicit: a missing key in the active language falls back to English, and a
/// key missing everywhere returns the key itself rather than an empty string. An empty label
/// is invisible; a visible key name is a bug report.
/// </para>
/// </remarks>
public sealed class LocalizationService
{
    private const string FallbackLanguage = "en";
    private const string ResourceSuffix = ".json";

    private readonly Dictionary<string, Dictionary<string, string>> _catalogs =
        new(StringComparer.OrdinalIgnoreCase);

    public LocalizationService()
    {
        LoadEmbeddedCatalogs();
        Language = DetectSystemLanguage();
    }

    /// <summary>Raised when the active language changes, so bindings can refresh.</summary>
    public event EventHandler? LanguageChanged;

    /// <summary>Active two-letter language code (en, ru, zh).</summary>
    public string Language { get; private set; }

    /// <summary>Languages with a loaded catalog.</summary>
    public IReadOnlyList<string> AvailableLanguages =>
        _catalogs.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray();

    /// <summary>Switches language at runtime. Unknown codes fall back to English.</summary>
    public void SetLanguage(string? languageCode)
    {
        var normalized = Pluralizer.Normalize(languageCode);
        if (!_catalogs.ContainsKey(normalized))
        {
            normalized = FallbackLanguage;
        }

        if (string.Equals(normalized, Language, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        Language = normalized;
        CultureInfo.CurrentUICulture = normalized switch
        {
            "ru" => new CultureInfo("ru-RU"),
            "zh" => new CultureInfo("zh-Hans"),
            _ => new CultureInfo("en-US"),
        };

        LanguageChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Looks up a key in the active language, then English, then the key itself.</summary>
    public string this[string key] => Get(key);

    public string Get(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            return string.Empty;
        }

        if (_catalogs.TryGetValue(Language, out var active) && active.TryGetValue(key, out var value))
        {
            return value;
        }

        if (_catalogs.TryGetValue(FallbackLanguage, out var fallback) && fallback.TryGetValue(key, out var english))
        {
            return english;
        }

        return key;
    }

    /// <summary>
    /// Looks up a key and formats it with a count, selecting the correct plural form.
    /// </summary>
    /// <remarks>
    /// The catalog may define <c>key.one</c> / <c>key.few</c> / <c>key.many</c> / <c>key.other</c>.
    /// If none exist, the base key is used and <c>{count}</c> is substituted.
    /// </remarks>
    public string Get(string key, long count)
    {
        var category = Pluralizer.CategoryFor(Language, count);

        // Try the exact category, then "other", then the base key.
        foreach (var candidate in new[] { $"{key}.{category.ToString().ToLowerInvariant()}", $"{key}.other", key })
        {
            if (TryGetRaw(candidate, out var template))
            {
                return Format(template, count);
            }
        }

        return key;
    }

    /// <summary>Formats a template, substituting named placeholders from the error arguments.</summary>
    public string Format(string template, params (string Name, string Value)[] arguments)
    {
        var result = template;
        foreach (var (name, value) in arguments)
        {
            result = result.Replace("{" + name + "}", value, StringComparison.Ordinal);
        }

        return result;
    }

    /// <summary>
    /// Renders a structured error. This is how the "no raw technical strings in the UI"
    /// requirement is satisfied: the message key is resolved here, and the technical detail
    /// stays in the log.
    /// </summary>
    public string Describe(MyVpn.Core.Results.MyVpnError error)
    {
        ArgumentNullException.ThrowIfNull(error);

        var message = Get(error.MessageKey);
        return error.Arguments.Count == 0
            ? message
            : Format(message, error.Arguments.Select(a => (a.Key, a.Value)).ToArray());
    }

    private bool TryGetRaw(string key, out string value)
    {
        value = string.Empty;

        if (_catalogs.TryGetValue(Language, out var active) && active.TryGetValue(key, out var activeValue))
        {
            value = activeValue;
            return true;
        }

        if (_catalogs.TryGetValue(FallbackLanguage, out var fallback) && fallback.TryGetValue(key, out var fallbackValue))
        {
            value = fallbackValue;
            return true;
        }

        return false;
    }

    private static string Format(string template, long count) =>
        template.Replace("{count}", count.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);

    private void LoadEmbeddedCatalogs()
    {
        var assembly = Assembly.GetExecutingAssembly();

        foreach (var resourceName in assembly.GetManifestResourceNames())
        {
            if (!resourceName.EndsWith(ResourceSuffix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Resource names look like MyVpn.UI.Localization.locales.ru.json, so take the
            // token immediately before the extension as the language code.
            var parts = resourceName.Split('.');
            if (parts.Length < 2)
            {
                continue;
            }

            var code = Pluralizer.Normalize(parts[^2]);

            try
            {
                using var stream = assembly.GetManifestResourceStream(resourceName);
                if (stream is null)
                {
                    continue;
                }

                var catalog = JsonSerializer.Deserialize<Dictionary<string, string>>(stream);
                if (catalog is not null)
                {
                    _catalogs[code] = new Dictionary<string, string>(catalog, StringComparer.Ordinal);
                }
            }
            catch (JsonException)
            {
                // A malformed catalog must not prevent the app from starting; English remains.
            }
        }

        if (!_catalogs.ContainsKey(FallbackLanguage))
        {
            _catalogs[FallbackLanguage] = new Dictionary<string, string>(StringComparer.Ordinal);
        }
    }

    private static string DetectSystemLanguage()
    {
        var twoLetter = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        return Pluralizer.Normalize(twoLetter);
    }
}
