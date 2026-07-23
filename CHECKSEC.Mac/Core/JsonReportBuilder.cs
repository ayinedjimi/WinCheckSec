using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Checksec.Mac.Core;

/// <summary>
/// Produit le rapport JSON forensique, dans le meme esprit que ReportJsonBuilder cote Windows :
/// contexte hote, scores, modules horodates, puis empreinte SHA-256 du contenu (non-repudiation).
/// </summary>
public static class JsonReportBuilder
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string Build(ScanResult scan)
    {
        var body = new
        {
            SchemaVersion = "1.0-mac",
            Product = "MacSecCheck",
            GeneratedAtUtc = scan.FinishedAt,
            Host = new
            {
                scan.HostName,
                scan.OsVersion,
                scan.Elevated,
                Platform = "macOS"
            },
            Execution = new
            {
                scan.StartedAt,
                scan.FinishedAt,
                DurationMs = (scan.FinishedAt - scan.StartedAt).TotalMilliseconds,
                CollectorCount = scan.Reports.Count
            },
            Summary = new
            {
                scan.GlobalScore,
                Grade = Grade(scan.GlobalScore),
                Counts = CountBySeverity(scan)
            },
            scan.CategoryScores,
            Modules = scan.Reports.Select(r => new
            {
                r.Collector,
                r.Category,
                r.CollectedAt,
                r.DurationMs,
                r.Error,
                Findings = r.Findings
            })
        };

        // 1er passage : serialiser le corps.
        var json = JsonSerializer.Serialize(body, Options);

        // 2e passage : ajouter le bloc Integrity (hash du corps) — comme cote Windows.
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();
        using var doc = JsonDocument.Parse(json);
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();
            foreach (var prop in doc.RootElement.EnumerateObject())
                prop.WriteTo(w);
            w.WriteStartObject("Integrity");
            w.WriteString("Algorithm", "SHA-256");
            w.WriteString("Hash", hash);
            w.WriteEndObject();
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static Dictionary<string, int> CountBySeverity(ScanResult scan) =>
        scan.Reports.SelectMany(r => r.Findings)
            .GroupBy(f => f.Severity.ToString())
            .ToDictionary(g => g.Key, g => g.Count());

    private static string Grade(int score) => score switch
    {
        >= 90 => "A",
        >= 75 => "B",
        >= 60 => "C",
        >= 40 => "D",
        _ => "F"
    };
}
