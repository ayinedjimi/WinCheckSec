using System;
using System.Linq;
using CHECKSEC.Pages;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media.Animation;
using WinRT;
using WinRT.Interop;
using Windows.Graphics;
using Windows.System;

namespace CHECKSEC;

public sealed partial class MainWindow : Window
{
	private MicaController? _micaController;

	private SystemBackdropConfiguration? _backdropConfig;

	// Palette de couleurs du badge : la couleur change à chaque build (indexée par BuildNumber).
	private static readonly string[] BadgePalette =
	{
		"#0078D4", "#107C10", "#D83B01", "#5C2D91", "#008272",
		"#C30052", "#B146C2", "#E3008C", "#00B7C3", "#498205",
		"#8764B8", "#CA5010", "#0B6A0B", "#C239B3", "#005B70"
	};

	public MainWindow()
	{
		InitializeComponent();
		ConfigureWindow();
		SetupMicaBackdrop();
		ApplyVersionBadge();
		NavView.SelectedItem = NavView.MenuItems[0];
		ContentFrame.Navigate(typeof(DashboardPage), null, new SuppressNavigationTransitionInfo());
		SetupKeyboardAccelerators();
	}

	// Renseigne le badge de version, indique l'état administrateur, et choisit une couleur qui change à chaque build.
	private void ApplyVersionBadge()
	{
		try
		{
			bool isAdmin = IsRunningElevated();
			VersionBadgeText.Text = isAdmin ? $"{BuildInfo.Version}  ·  Admin" : $"{BuildInfo.Version}  ·  NON-ADMIN";

			// Si l'app n'est pas élevée, le badge devient rouge (anomalie) ; sinon couleur par build.
			string hex = isAdmin
				? BadgePalette[((BuildInfo.BuildNumber % BadgePalette.Length) + BadgePalette.Length) % BadgePalette.Length]
				: "#C50F1F";
			VersionBadge.Background = new Microsoft.UI.Xaml.Media.SolidColorBrush(HexToColor(hex));
			ToolTipService.SetToolTip(VersionBadge,
				$"CHECKSEC {BuildInfo.Version} — build {BuildInfo.BuildNumber} ({BuildInfo.BuildTimeUtc} UTC)\n" +
				(isAdmin ? "Exécution en tant qu'administrateur ✓" : "⚠ NON élevé — l'analyse sera incomplète"));
		}
		catch
		{
			// Le badge ne doit jamais empêcher le démarrage de la fenêtre.
		}
	}

	private static bool IsRunningElevated()
	{
		try
		{
			using System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
			return new System.Security.Principal.WindowsPrincipal(identity)
				.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
		}
		catch
		{
			return false;
		}
	}

	private static Windows.UI.Color HexToColor(string hex)
	{
		hex = hex.TrimStart('#');
		byte r = System.Convert.ToByte(hex.Substring(0, 2), 16);
		byte g = System.Convert.ToByte(hex.Substring(2, 2), 16);
		byte b = System.Convert.ToByte(hex.Substring(4, 2), 16);
		return Windows.UI.Color.FromArgb(255, r, g, b);
	}

	private void ConfigureWindow()
	{
		WindowId windowIdFromWindow = Win32Interop.GetWindowIdFromWindow(WindowNative.GetWindowHandle(this));
		AppWindow appWindow = AppWindow.GetFromWindowId(windowIdFromWindow);
		appWindow.Resize(new SizeInt32(1400, 900));
		appWindow.Changed += delegate(AppWindow s, AppWindowChangedEventArgs e)
		{
			if (e.DidSizeChange)
			{
				SizeInt32 size = appWindow.Size;
				if (size.Width < 800 || size.Height < 600)
				{
					appWindow.Resize(new SizeInt32(Math.Max(size.Width, 800), Math.Max(size.Height, 600)));
				}
			}
		};
		AppWindowTitleBar titleBar = appWindow.TitleBar;
		if ((object)titleBar != null)
		{
			titleBar.ExtendsContentIntoTitleBar = true;
			titleBar.ButtonBackgroundColor = Colors.Transparent;
			titleBar.ButtonInactiveBackgroundColor = Colors.Transparent;
		}
		base.Title = "CHECKSEC — Audit de Sécurité Windows 11";
	}

	private void SetupMicaBackdrop()
	{
		if (!MicaController.IsSupported())
		{
			return;
		}
		_micaController = new MicaController();
		_backdropConfig = new SystemBackdropConfiguration();
		base.Activated += delegate(object _, WindowActivatedEventArgs args)
		{
			if (_backdropConfig != null)
			{
				_backdropConfig.IsInputActive = args.WindowActivationState != WindowActivationState.Deactivated;
			}
		};
		base.Closed += delegate
		{
			_micaController?.Dispose();
			_micaController = null;
		};
		_micaController.AddSystemBackdropTarget(CastExtensions.As<ICompositionSupportsSystemBackdrop>(this));
		_micaController.SetSystemBackdropConfiguration(_backdropConfig);
	}

	private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
	{
		if (args.SelectedItemContainer is NavigationViewItem { Tag: var tag })
		{
			Type type = tag?.ToString() switch
			{
				"Dashboard" => typeof(DashboardPage),
				"SecureCore" => typeof(SecureCorePage),
				"Results" => typeof(ResultsPage),
				"Gaps" => typeof(GapsPage),
				"Cis" => typeof(CisPage),
				"Remediation" => typeof(RemediationPage),
				"EventLog" => typeof(EventLogPage),
				"History" => typeof(HistoryPage),
				"SystemInfo" => typeof(SystemInfoPage),
				"Settings" => typeof(SettingsPage),
				"About" => typeof(AboutPage),
				_ => null,
			};
			if (type != null && ContentFrame.CurrentSourcePageType != type)
			{
				ContentFrame.Navigate(type, null, new SlideNavigationTransitionInfo
				{
					Effect = SlideNavigationTransitionEffect.FromRight
				});
			}
		}
	}

	private void SetupKeyboardAccelerators()
	{
		KeyboardAccelerator keyboardAccelerator = new KeyboardAccelerator
		{
			Modifiers = VirtualKeyModifiers.Control,
			Key = VirtualKey.L
		};
		keyboardAccelerator.Invoked += delegate(KeyboardAccelerator s, KeyboardAcceleratorInvokedEventArgs e)
		{
			NavigateToTag("Dashboard");
			e.Handled = true;
		};
		base.Content.KeyboardAccelerators.Add(keyboardAccelerator);
		KeyboardAccelerator keyboardAccelerator2 = new KeyboardAccelerator
		{
			Modifiers = VirtualKeyModifiers.Control,
			Key = VirtualKey.E
		};
		keyboardAccelerator2.Invoked += delegate(KeyboardAccelerator s, KeyboardAcceleratorInvokedEventArgs e)
		{
			NavigateToTag("Dashboard");
			e.Handled = true;
		};
		base.Content.KeyboardAccelerators.Add(keyboardAccelerator2);
		KeyboardAccelerator keyboardAccelerator3 = new KeyboardAccelerator
		{
			Modifiers = VirtualKeyModifiers.Control,
			Key = VirtualKey.F
		};
		keyboardAccelerator3.Invoked += delegate(KeyboardAccelerator s, KeyboardAcceleratorInvokedEventArgs e)
		{
			NavigateToTag("Results");
			e.Handled = true;
		};
		base.Content.KeyboardAccelerators.Add(keyboardAccelerator3);
		KeyboardAccelerator keyboardAccelerator4 = new KeyboardAccelerator
		{
			Key = VirtualKey.F5
		};
		keyboardAccelerator4.Invoked += delegate(KeyboardAccelerator s, KeyboardAcceleratorInvokedEventArgs e)
		{
			NavigateToTag("Dashboard");
			e.Handled = true;
		};
		base.Content.KeyboardAccelerators.Add(keyboardAccelerator4);
		string[] array = new string[8] { "Dashboard", "SecureCore", "Results", "Gaps", "Cis", "Remediation", "EventLog", "SystemInfo" };
		for (int i = 0; i < array.Length; i++)
		{
			string tag = array[i];
			VirtualKey key = (VirtualKey)(49 + i);
			KeyboardAccelerator keyboardAccelerator5 = new KeyboardAccelerator
			{
				Modifiers = VirtualKeyModifiers.Control,
				Key = key
			};
			keyboardAccelerator5.Invoked += delegate(KeyboardAccelerator s, KeyboardAcceleratorInvokedEventArgs e)
			{
				NavigateToTag(tag);
				e.Handled = true;
			};
			base.Content.KeyboardAccelerators.Add(keyboardAccelerator5);
		}
	}

	private void NavigateToTag(string tag)
	{
		foreach (NavigationViewItem item in NavView.MenuItems.OfType<NavigationViewItem>())
		{
			if (item.Tag?.ToString() == tag)
			{
				NavView.SelectedItem = item;
				break;
			}
		}
		foreach (NavigationViewItem item2 in NavView.FooterMenuItems.OfType<NavigationViewItem>())
		{
			if (item2.Tag?.ToString() == tag)
			{
				NavView.SelectedItem = item2;
				break;
			}
		}
	}
}
