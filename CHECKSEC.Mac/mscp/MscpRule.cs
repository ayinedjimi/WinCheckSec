using YamlDotNet.RepresentationModel;

namespace Checksec.Mac.Mscp;

/// <summary>Type et valeur attendus pour la conformite d'une regle mSCP.</summary>
public readonly record struct MscpExpected(string Kind, string Value)
{
    /// <summary>Vrai si la sortie observee (deja trimmee) satisfait la valeur attendue.</summary>
    public bool Matches(string observed)
    {
        observed = observed.Trim();
        return Kind switch
        {
            "integer" => long.TryParse(observed, out var o) && long.TryParse(Value, out var e) && o == e,
            "boolean" => string.Equals(observed, Value, StringComparison.OrdinalIgnoreCase),
            "float" => double.TryParse(observed, out var o) && double.TryParse(Value, out var e) && Math.Abs(o - e) < 1e-9,
            _ => string.Equals(observed, Value, StringComparison.Ordinal) // string
        };
    }

    public override string ToString() => $"{Kind}={Value}";
}

/// <summary>
/// Une regle mSCP resolue pour une version macOS donnee : identifiant, commande de
/// verification, valeur attendue, remediation et references (CIS/DISA).
/// </summary>
public sealed class MscpRule
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public string? Discussion { get; init; }
    public string? CheckShell { get; init; }
    public MscpExpected? Expected { get; init; }
    public string? FixShell { get; init; }
    public string? CisBenchmark { get; init; }
    public IReadOnlyList<string> Nist80053 { get; init; } = Array.Empty<string>();
    public string? DisaSeverity { get; init; }

    /// <summary>Vrai si la regle possede une verification automatisable.</summary>
    public bool HasAutomatedCheck => !string.IsNullOrWhiteSpace(CheckShell) && Expected is not null;

    // ─── Parsing ────────────────────────────────────────────────────────────────

    /// <summary>Analyse un fichier YAML de regle mSCP pour la version macOS majeure ciblee (ex. "26").</summary>
    public static MscpRule? Parse(string yaml, string macMajor)
    {
        var stream = new YamlStream();
        stream.Load(new StringReader(yaml));
        if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
            return null;

        var id = Scalar(Get(root, "id"));
        var title = Scalar(Get(root, "title"));
        if (id is null || title is null) return null;

        var macos = Map(Get(Map(Get(root, "platforms")), "macOS"));

        // Resolution de enforcement_info, par priorite :
        //   1) bloc specifique a la version ciblee (ex. '26.0')
        //   2) bloc canonique de niveau macOS (s'applique a la version courante)
        //   3) repli : premier bloc d'une version disponible
        var verKey = $"{macMajor}.0";
        var verMap = Map(Get(macos, verKey));
        var ei = Map(Get(verMap, "enforcement_info"))
              ?? Map(Get(macos, "enforcement_info"));
        if (ei is null && macos is not null)
        {
            foreach (var child in macos.Children)
                if (child.Value is YamlMappingNode vm && Map(GetNode(vm, "enforcement_info")) is { } e)
                { ei = e; verMap ??= vm; break; }
        }

        var check = Map(Get(ei, "check"));
        var checkShell = Scalar(Get(check, "shell"));
        var expected = ParseExpected(Map(Get(check, "result")));
        var fixShell = Scalar(Get(Map(Get(ei, "fix")), "shell"));

        // References CIS/DISA/NIST.
        var refs = Map(Get(root, "references"));
        var cisBench = FirstScalar(Get(Map(Get(Map(Get(refs, "cis")), "benchmark")), $"macos_{macMajor}"));
        var nist = Sequence(Get(Map(Get(refs, "nist")), "800-53r5"));
        var disaSeverity = ResolveDisaSeverity(verMap ?? Map(Get(macos, verKey)));

        return new MscpRule
        {
            Id = id,
            Title = title,
            Discussion = Scalar(Get(root, "discussion"))?.Trim(),
            CheckShell = checkShell,
            Expected = expected,
            FixShell = fixShell,
            CisBenchmark = cisBench,
            Nist80053 = nist,
            DisaSeverity = disaSeverity,
        };
    }

    private static MscpExpected? ParseExpected(YamlMappingNode? result)
    {
        if (result is null) return null;
        foreach (var kind in new[] { "integer", "string", "boolean", "float" })
        {
            var v = Scalar(Get(result, kind));
            if (v is not null) return new MscpExpected(kind, v);
        }
        return null;
    }

    private static string? ResolveDisaSeverity(YamlMappingNode? verMap)
    {
        if (Get(verMap, "benchmarks") is not YamlSequenceNode seq) return null;
        foreach (var item in seq)
            if (item is YamlMappingNode m && Scalar(GetNode(m, "name")) == "disa_stig")
                return Scalar(GetNode(m, "severity"));
        return null;
    }

    // ─── Helpers de navigation YAML ──────────────────────────────────────────────

    private static YamlMappingNode? Map(YamlNode? n) => n as YamlMappingNode;

    private static YamlNode? Get(YamlMappingNode? m, string key)
    {
        if (m is null) return null;
        foreach (var kv in m.Children)
            if (kv.Key is YamlScalarNode s && s.Value == key) return kv.Value;
        return null;
    }

    private static YamlNode? GetNode(YamlNode? n, string key) => Get(n as YamlMappingNode, key);

    private static string? Scalar(YamlNode? n) => (n as YamlScalarNode)?.Value;

    private static string? FirstScalar(YamlNode? n) =>
        n is YamlSequenceNode { Children.Count: > 0 } seq ? Scalar(seq.Children[0]) : Scalar(n);

    private static IReadOnlyList<string> Sequence(YamlNode? n) =>
        n is YamlSequenceNode seq
            ? seq.Children.OfType<YamlScalarNode>().Select(s => s.Value ?? "").Where(v => v.Length > 0).ToList()
            : Array.Empty<string>();
}
