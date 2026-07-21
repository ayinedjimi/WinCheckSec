using System.Reflection;
using CommunityToolkit.Mvvm.ComponentModel;
using WinRT;

namespace CHECKSEC.ViewModels;

public partial class AboutViewModel : ObservableObject
{
	public string AppName => "CHECKSEC";

	public string Version => Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "6.0.0";

	public string Author => "AYI NEDJIMI CONSULTANTS";

	public string Description => "Audit de sécurité et conformité Windows 11\nBaseline MSCT v25H2 — 25 collecteurs — CIS Benchmark\nAnalyse automatisée avec scoring et recommandations";

	public string Disclaimer => "Cet outil est fourni à titre informatif. Les résultats doivent être interprétés par un professionnel de la cybersécurité. L'éditeur décline toute responsabilité en cas de mauvaise utilisation.";
}
