using System.Globalization;
using System.Text;

namespace MyVpn.Core.Parsing;

/// <summary>
/// Infers an ISO-3166 alpha-2 country code from a server display name.
/// </summary>
/// <remarks>
/// <para>
/// Subscription remarks almost always carry a country hint, and the main screen has to
/// show the current server's country. Rather than shipping a geo-IP lookup for UI
/// decoration, this derives the code from what the provider already wrote in the name.
/// </para>
/// <para>
/// Detection order, most reliable first:
/// <list type="number">
/// <item><description>A flag emoji, i.e. two regional indicator symbols. This is
/// unambiguous and is what most panels emit.</description></item>
/// <item><description>An explicit bracketed or prefixed code such as <c>[DE]</c>,
/// <c>(JP)</c> or <c>US -</c>.</description></item>
/// <item><description>A country name in English, Russian or Chinese.</description></item>
/// </list>
/// When nothing matches, the method returns <c>null</c> rather than guessing: a wrong
/// flag is worse than no flag.
/// </para>
/// </remarks>
public static class CountryInference
{
    private const int RegionalIndicatorA = 0x1F1E6;

    /// <summary>Returns an uppercase ISO-3166 alpha-2 code, or <c>null</c>.</summary>
    public static string? FromDisplayName(string? displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName))
        {
            return null;
        }

        var name = displayName.Trim();

        return FromFlagEmoji(name)
               ?? FromExplicitCode(name)
               ?? FromCountryName(name);
    }

    /// <summary>
    /// Decodes a flag emoji into its country code. A flag is a pair of regional
    /// indicator symbols, each offset from 'A'.
    /// </summary>
    private static string? FromFlagEmoji(string name)
    {
        // A flag occupies four UTF-16 units (two surrogate pairs), so stop while a
        // second indicator still fits.
        for (var i = 0; i + 3 < name.Length; i++)
        {
            if (!TryReadRegionalIndicator(name, i, out var first))
            {
                continue;
            }

            if (!TryReadRegionalIndicator(name, i + 2, out var second))
            {
                continue;
            }

            return string.Concat(first, second);
        }

        return null;
    }

    /// <summary>
    /// Reads one regional indicator symbol (U+1F1E6..U+1F1FF) starting at
    /// <paramref name="index"/> and maps it to 'A'..'Z'.
    /// </summary>
    private static bool TryReadRegionalIndicator(string value, int index, out char letter)
    {
        letter = 'A';

        if (index + 1 >= value.Length)
        {
            return false;
        }

        // Every regional indicator shares the high surrogate U+D83C.
        if (value[index] != '\uD83C')
        {
            return false;
        }

        var low = value[index + 1];
        if (low is < '\uDDE6' or > '\uDDFF')
        {
            return false;
        }

        letter = (char)('A' + (low - '\uDDE6'));
        return true;
    }

    /// <summary>Matches <c>[DE]</c>, <c>(JP)</c>, <c>DE-</c>, <c>us |</c> and similar prefixes.</summary>
    private static string? FromExplicitCode(string name)
    {
        for (var i = 0; i < name.Length && i < 24; i++)
        {
            var c = name[i];
            if (c is not ('[' or '(' or '<'))
            {
                continue;
            }

            var close = name.IndexOfAny(new[] { ']', ')', '>' }, i + 1);
            if (close < 0)
            {
                continue;
            }

            var inner = name[(i + 1)..close].Trim();
            if (IsIsoCode(inner))
            {
                return inner.ToUpperInvariant();
            }
        }

        // A leading two-letter code followed by a separator, e.g. "DE - Frankfurt".
        var head = name.Length >= 3 ? name[..2] : string.Empty;
        if (head.Length == 2
            && IsIsoCode(head)
            && (name.Length == 2 || !char.IsLetter(name[2])))
        {
            return head.ToUpperInvariant();
        }

        return null;
    }

    private static string? FromCountryName(string name)
    {
        // Longest names first so "United States" is not shadowed by "United".
        foreach (var (alias, code) in AliasesByLength)
        {
            if (name.Contains(alias, StringComparison.OrdinalIgnoreCase))
            {
                return code;
            }
        }

        return null;
    }

    private static bool IsIsoCode(string value) =>
        value.Length == 2 && value.All(char.IsAsciiLetter);

    /// <summary>
    /// Country-name aliases in English, Russian and Chinese for the countries that
    /// appear most often in commercial subscription lists.
    /// </summary>
    private static readonly (string Alias, string Code)[] Aliases =
    {
        ("united states", "US"), ("united kingdom", "GB"), ("south korea", "KR"),
        ("north macedonia", "MK"), ("czech republic", "CZ"), ("new zealand", "NZ"),
        ("saudi arabia", "SA"), ("south africa", "ZA"), ("hong kong", "HK"),
        ("netherlands", "NL"), ("switzerland", "CH"), ("luxembourg", "LU"),
        ("singapore", "SG"), ("australia", "AU"), ("indonesia", "ID"),
        ("argentina", "AR"), ("lithuania", "LT"), ("moldova", "MD"),
        ("соединённые штаты", "US"), ("соединенные штаты", "US"),
        ("великобритания", "GB"), ("нидерланды", "NL"), ("швейцария", "CH"),
        ("германия", "DE"), ("франция", "FR"), ("финляндия", "FI"),
        ("швеция", "SE"), ("норвегия", "NO"), ("дания", "DK"),
        ("польша", "PL"), ("чехия", "CZ"), ("австрия", "AT"),
        ("испания", "ES"), ("италия", "IT"), ("португалия", "PT"),
        ("румыния", "RO"), ("болгария", "BG"), ("венгрия", "HU"),
        ("греция", "GR"), ("турция", "TR"), ("украина", "UA"),
        ("казахстан", "KZ"), ("россия", "RU"), ("латвия", "LV"),
        ("эстония", "EE"), ("литва", "LT"), ("ирландия", "IE"),
        ("исландия", "IS"), ("сербия", "RS"), ("хорватия", "HR"),
        ("словакия", "SK"), ("словения", "SI"), ("молдова", "MD"),
        ("армения", "AM"), ("грузия", "GE"), ("израиль", "IL"),
        ("индия", "IN"), ("китай", "CN"), ("япония", "JP"),
        ("корея", "KR"), ("сингапур", "SG"), ("тайвань", "TW"),
        ("вьетнам", "VN"), ("таиланд", "TH"), ("малайзия", "MY"),
        ("филиппины", "PH"), ("австралия", "AU"), ("канада", "CA"),
        ("бразилия", "BR"), ("мексика", "MX"), ("аргентина", "AR"),
        ("чили", "CL"), ("колумбия", "CO"), ("египет", "EG"),
        ("оаэ", "AE"), ("саудовская аравия", "SA"), ("юар", "ZA"),
        ("нигерия", "NG"), ("кения", "KE"), ("美国", "US"), ("英國", "GB"),
        ("英国", "GB"), ("德国", "DE"), ("德國", "DE"), ("法国", "FR"),
        ("法國", "FR"), ("荷兰", "NL"), ("荷蘭", "NL"), ("瑞士", "CH"),
        ("瑞典", "SE"), ("挪威", "NO"), ("芬兰", "FI"), ("丹麥", "DK"),
        ("丹麦", "DK"), ("波兰", "PL"), ("波蘭", "PL"), ("奥地利", "AT"),
        ("奧地利", "AT"), ("西班牙", "ES"), ("意大利", "IT"), ("葡萄牙", "PT"),
        ("希腊", "GR"), ("希臘", "GR"), ("土耳其", "TR"), ("乌克兰", "UA"),
        ("烏克蘭", "UA"), ("俄罗斯", "RU"), ("俄羅斯", "RU"), ("白俄罗斯", "BY"),
        ("哈萨克斯坦", "KZ"), ("以色列", "IL"), ("印度", "IN"), ("中国", "CN"),
        ("中國", "CN"), ("日本", "JP"), ("韩国", "KR"), ("韓國", "KR"),
        ("新加坡", "SG"), ("台湾", "TW"), ("台灣", "TW"), ("香港", "HK"),
        ("越南", "VN"), ("泰国", "TH"), ("泰國", "TH"), ("马来西亚", "MY"),
        ("菲律賓", "PH"), ("菲律宾", "PH"), ("澳大利亚", "AU"), ("澳洲", "AU"),
        ("新西兰", "NZ"), ("紐西蘭", "NZ"), ("加拿大", "CA"), ("巴西", "BR"),
        ("墨西哥", "MX"), ("阿根廷", "AR"), ("智利", "CL"), ("埃及", "EG"),
        ("阿联酋", "AE"), ("南非", "ZA"), ("爱尔兰", "IE"), ("爱尔兰", "IE"),
        ("愛爾蘭", "IE"), ("冰岛", "IS"), ("冰島", "IS"), ("塞尔维亚", "RS"),
        ("塞爾維亞", "RS"), ("罗马尼亚", "RO"), ("羅馬尼亞", "RO"), ("保加利亚", "BG"),
        ("匈牙利", "HU"), ("捷克", "CZ"), ("立陶宛", "LT"), ("拉脱维亚", "LV"),
        ("爱沙尼亚", "EE"), ("愛沙尼亞", "EE"), ("摩尔多瓦", "MD"), ("格鲁吉亚", "GE"),
        ("亚美尼亚", "AM"), ("德国", "DE"), ("gb", "GB"), ("uk", "GB"),
    };

    /// <summary>Aliases sorted by descending length, computed once.</summary>
    private static readonly (string Alias, string Code)[] AliasesByLength =
        Aliases
            .OrderByDescending(a => a.Alias.Length)
            .ToArray();

    /// <summary>
    /// Converts an ISO-3166 alpha-2 code into its flag emoji, for display next to a
    /// server name when the provider did not include one.
    /// </summary>
    public static string? ToFlagEmoji(string? isoCode)
    {
        if (string.IsNullOrWhiteSpace(isoCode) || !IsIsoCode(isoCode))
        {
            return null;
        }

        var builder = new StringBuilder(4);
        foreach (var c in isoCode.ToUpperInvariant())
        {
            builder.Append(char.ConvertFromUtf32(RegionalIndicatorA + (c - 'A')));
        }

        return builder.ToString();
    }
}
