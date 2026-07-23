using System.Reflection;
using YamlDotNet.RepresentationModel;

namespace Checksec.Mac.Mscp;

/// <summary>Une section de baseline resolue : nom + regles associees.</summary>
public sealed record MscpSection(string Name, IReadOnlyList<MscpRule> Rules);

/// <summary>
/// Charge les donnees mSCP (regles + baselines) soit depuis les ressources embarquees,
/// soit depuis un checkout externe du depot usnistgov/macos_security (--mscp).
/// </summary>
public sealed class MscpDataLoader
{
    private readonly string _macMajor;
    private readonly Dictionary<string, string> _ruleYaml = new(StringComparer.OrdinalIgnoreCase); // id -> yaml
    private readonly Dictionary<string, string> _baselineYaml = new(StringComparer.OrdinalIgnoreCase); // nom -> yaml

    private MscpDataLoader(string macMajor) => _macMajor = macMajor;

    public int RuleCount => _ruleYaml.Count;
    public IEnumerable<string> BaselineNames => _baselineYaml.Keys;

    /// <summary>Charge depuis les ressources embarquees dans l'assembly.</summary>
    public static MscpDataLoader FromEmbedded(string macMajor)
    {
        var loader = new MscpDataLoader(macMajor);
        var asm = Assembly.GetExecutingAssembly();
        foreach (var name in asm.GetManifestResourceNames())
        {
            if (!name.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)) continue;
            using var s = asm.GetManifestResourceStream(name)!;
            using var r = new StreamReader(s);
            var text = r.ReadToEnd();
            if (name.Contains(".mscp.rules.", StringComparison.OrdinalIgnoreCase))
                loader.IndexRule(text);
            else if (name.Contains(".mscp.baselines.", StringComparison.OrdinalIgnoreCase))
                loader.IndexBaseline(BaselineKeyFromResource(name), text);
        }
        return loader;
    }

    /// <summary>Charge depuis un dossier (checkout mSCP : <dir>/rules, <dir>/baselines/macos).</summary>
    public static MscpDataLoader FromDirectory(string dir, string macMajor)
    {
        var loader = new MscpDataLoader(macMajor);
        var rulesDir = FirstExisting(Path.Combine(dir, "rules"), Path.Combine(dir, "src", "mscp", "data", "rules"));
        var blDir = FirstExisting(Path.Combine(dir, "baselines", "macos"),
                                  Path.Combine(dir, "src", "mscp", "data", "baselines", "macos"),
                                  Path.Combine(dir, "baselines"));
        if (rulesDir != null)
            foreach (var f in Directory.EnumerateFiles(rulesDir, "*.yaml", SearchOption.AllDirectories))
                loader.IndexRule(File.ReadAllText(f));
        if (blDir != null)
            foreach (var f in Directory.EnumerateFiles(blDir, "*.yaml"))
                loader.IndexBaseline(BaselineKeyFromFile(Path.GetFileName(f)), File.ReadAllText(f));
        return loader;
    }

    /// <summary>
    /// Resout une baseline (ex. "cis_lvl1") en sections ordonnees de regles automatisables.
    /// Renvoie une liste vide si la baseline est inconnue.
    /// </summary>
    public IReadOnlyList<MscpSection> ResolveBaseline(string baselineName)
    {
        if (!_baselineYaml.TryGetValue(baselineName, out var yaml)) return Array.Empty<MscpSection>();

        var stream = new YamlStream();
        stream.Load(new StringReader(yaml));
        if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
            return Array.Empty<MscpSection>();

        var profile = Get(root, "profile") as YamlSequenceNode;
        if (profile is null) return Array.Empty<MscpSection>();

        var sections = new List<MscpSection>();
        foreach (var node in profile)
        {
            if (node is not YamlMappingNode secMap) continue;
            var section = Scalar(Get(secMap, "section")) ?? "Divers";
            var rules = new List<MscpRule>();
            if (Get(secMap, "rules") is YamlSequenceNode ruleSeq)
            {
                foreach (var idNode in ruleSeq.OfType<YamlScalarNode>())
                {
                    var id = idNode.Value;
                    if (id is null || !_ruleYaml.TryGetValue(id, out var ruleText)) continue;
                    var rule = MscpRule.Parse(ruleText, _macMajor);
                    if (rule is not null) rules.Add(rule);
                }
            }
            if (rules.Count > 0) sections.Add(new MscpSection(section, rules));
        }
        return sections;
    }

    // ─── Indexation ──────────────────────────────────────────────────────────────

    private void IndexRule(string yaml)
    {
        var id = QuickScalar(yaml, "id");
        if (id != null) _ruleYaml[id] = yaml;
    }

    private void IndexBaseline(string key, string yaml) => _baselineYaml[key] = yaml;

    /// <summary>Lit rapidement une cle scalaire de 1er niveau sans parser tout le document.</summary>
    private static string? QuickScalar(string yaml, string key)
    {
        foreach (var line in yaml.Split('\n'))
        {
            var t = line.TrimEnd('\r');
            if (t.StartsWith(key + ":", StringComparison.Ordinal))
                return t[(key.Length + 1)..].Trim().Trim('\'', '"');
        }
        return null;
    }

    // "Checksec.Mac.mscp.baselines.cis_lvl1_macos_26.0.yaml" -> "cis_lvl1"
    private static string BaselineKeyFromResource(string resourceName)
    {
        var idx = resourceName.LastIndexOf(".baselines.", StringComparison.OrdinalIgnoreCase);
        var file = idx >= 0 ? resourceName[(idx + ".baselines.".Length)..] : resourceName;
        return BaselineKeyFromFile(file);
    }

    // "cis_lvl1_macos_26.0.yaml" -> "cis_lvl1"
    private static string BaselineKeyFromFile(string file)
    {
        var i = file.IndexOf("_macos", StringComparison.OrdinalIgnoreCase);
        return i > 0 ? file[..i] : Path.GetFileNameWithoutExtension(file);
    }

    private static string? FirstExisting(params string[] paths) => paths.FirstOrDefault(Directory.Exists);

    private static YamlNode? Get(YamlMappingNode m, string key)
    {
        foreach (var kv in m.Children)
            if (kv.Key is YamlScalarNode s && s.Value == key) return kv.Value;
        return null;
    }

    private static string? Scalar(YamlNode? n) => (n as YamlScalarNode)?.Value;
}
