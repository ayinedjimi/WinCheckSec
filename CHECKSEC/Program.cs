using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using WinRT;

namespace CHECKSEC;

// Point d'entrée personnalisé (DISABLE_XAML_GENERATED_MAIN dans le .csproj).
// Permet de vérifier l'élévation et les prérequis runtime AVANT tout appel natif WindowsAppSDK/WinUI.
public static class Program
{
	[STAThread]
	private static void Main(string[] args)
	{
		// 1) Élévation garantie AVANT toute analyse. Le manifeste (requireAdministrator) est la
		//    protection principale ; ce contrôle est un filet de sécurité qui fonctionne même si
		//    le manifeste est ignoré (copie/altération) : il relance l'app élevée avec invite UAC.
		if (!ElevationHelper.EnsureElevated(args))
		{
			return; // Instance non élevée : relance élevée déclenchée (ou refusée) → on quitte.
		}

		// 2) Le VC++ Redistributable : les DLL natives WinUI (Microsoft.ui.xaml.dll…) en dépendent.
		//    Vérifié avant Application.Start qui les charge.
		if (!RuntimePrerequisites.EnsureVisualCppRuntime())
		{
			return; // Composant manquant : message + proposition de téléchargement déjà affichés.
		}

		ComWrappersSupport.InitializeComWrappers();
		Application.Start(delegate
		{
			DispatcherQueueSynchronizationContext context = new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread());
			SynchronizationContext.SetSynchronizationContext(context);
			_ = new App();
		});
	}
}

// Garantit que le processus tourne en administrateur. N'utilise que des API .NET/OS.
internal static class ElevationHelper
{
	private const string AlreadyRelaunchedFlag = "--elevation-relaunched";

	[DllImport("user32", CharSet = CharSet.Unicode)]
	private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

	public static bool IsElevated()
	{
		try
		{
			using WindowsIdentity identity = WindowsIdentity.GetCurrent();
			return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
		}
		catch
		{
			return false;
		}
	}

	public static bool EnsureElevated(string[] args)
	{
		if (IsElevated())
		{
			return true;
		}

		// Évite toute boucle : si on a déjà tenté la relance et qu'on n'est toujours pas élevé,
		// on informe et on arrête (droits admin indisponibles).
		if (args != null && args.Contains(AlreadyRelaunchedFlag))
		{
			MessageBoxW(IntPtr.Zero,
				"WinCheckSec nécessite des privilèges administrateur pour analyser la configuration de sécurité du système.\n\n" +
				"L'élévation n'a pas pu être obtenue. Relancez l'application avec un compte administrateur.",
				"WinCheckSec — Privilèges administrateur requis", 0x10u /* MB_ICONERROR */ | 0x1000u /* MB_SYSTEMMODAL */);
			return false;
		}

		try
		{
			string? exePath = Environment.ProcessPath;
			if (string.IsNullOrEmpty(exePath))
			{
				return false;
			}
			string passThrough = (args != null && args.Length > 0) ? string.Join(" ", args) + " " : string.Empty;
			ProcessStartInfo psi = new ProcessStartInfo
			{
				FileName = exePath,
				UseShellExecute = true,
				Verb = "runas", // déclenche l'invite UAC
				Arguments = passThrough + AlreadyRelaunchedFlag
			};
			Process.Start(psi);
			return false; // l'instance élevée prend le relais ; celle-ci se termine.
		}
		catch (Win32Exception)
		{
			// L'utilisateur a refusé l'invite UAC : l'analyse ne peut pas se faire sans droits admin.
			return false;
		}
		catch
		{
			return false;
		}
	}
}

// Vérification des prérequis runtime portables (n'utilise QUE des API de l'OS : kernel32/user32/shell,
// jamais le VC++ runtime lui-même, pour rester fonctionnel même quand celui-ci manque).
internal static class RuntimePrerequisites
{
	private const string VcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe";

	[DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern IntPtr LoadLibraryW(string lpFileName);

	[DllImport("kernel32", SetLastError = true)]
	private static extern bool FreeLibrary(IntPtr hModule);

	[DllImport("user32", CharSet = CharSet.Unicode)]
	private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

	private const uint MB_YESNO = 0x4u;
	private const uint MB_ICONERROR = 0x10u;
	private const uint MB_SYSTEMMODAL = 0x1000u;
	private const int IDYES = 6;

	// .NET et WindowsAppSDK sont embarqués (self-contained) : seul le VC++ Redistributable x64
	// reste une dépendance système. On la contrôle explicitement.
	public static bool EnsureVisualCppRuntime()
	{
		string[] required = { "vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll" };
		foreach (string dll in required)
		{
			IntPtr handle = LoadLibraryW(dll);
			if (handle == IntPtr.Zero)
			{
				PromptDownload(dll);
				return false;
			}
			FreeLibrary(handle);
		}
		return true;
	}

	private static void PromptDownload(string missingDll)
	{
		string message =
			"WinCheckSec nécessite le composant Microsoft Visual C++ Redistributable (x64), introuvable sur ce système " +
			"(bibliothèque manquante : " + missingDll + ").\n\n" +
			"Sans ce composant, l'application ne peut pas démarrer.\n\n" +
			"Ouvrir la page de téléchargement officielle Microsoft maintenant ?";
		int result = MessageBoxW(IntPtr.Zero, message, "WinCheckSec — Composant requis manquant",
			MB_YESNO | MB_ICONERROR | MB_SYSTEMMODAL);
		if (result == IDYES)
		{
			try
			{
				System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
				{
					FileName = VcRedistUrl,
					UseShellExecute = true
				});
			}
			catch
			{
				// Le poste peut ne pas avoir de navigateur/associations ; l'URL est affichée dans le message.
			}
		}
	}
}
