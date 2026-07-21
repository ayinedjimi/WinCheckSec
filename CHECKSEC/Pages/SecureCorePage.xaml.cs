using System;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using CHECKSEC.Core.Models;
using CHECKSEC.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using WinRT;
using Windows.Foundation;
using Windows.UI;

namespace CHECKSEC.Pages;

public sealed partial class SecureCorePage : Page
{

	public SecureCoreViewModel ViewModel { get; }

	public SecureCorePage()
	{
		ViewModel = App.Services.GetRequiredService<SecureCoreViewModel>();
		InitializeComponent();
	}

	private void OnLoaded(object sender, RoutedEventArgs e)
	{
		ViewModel.LoadIfNeeded();
	}

	private async void OnSecureCoreTapped(object sender, TappedRoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: SecureCoreItem dataContext })
		{
			StackPanel dialogPanel = new StackPanel
			{
				Spacing = 16.0
			};
			StackPanel statusPanel = new StackPanel
			{
				Orientation = Orientation.Horizontal,
				Spacing = 12.0
			};
			Color color = ParseHexColor(dataContext.StatusColorHex);
			statusPanel.Children.Add(new Ellipse
			{
				Width = 14.0,
				Height = 14.0,
				Fill = new SolidColorBrush(color),
				VerticalAlignment = VerticalAlignment.Center
			});
			statusPanel.Children.Add(new TextBlock
			{
				Text = dataContext.StatusLabel + " — " + dataContext.Value,
				FontSize = 15.0,
				FontWeight = FontWeights.SemiBold,
				VerticalAlignment = VerticalAlignment.Center,
				TextWrapping = TextWrapping.Wrap
			});
			dialogPanel.Children.Add(statusPanel);
			if (!string.IsNullOrEmpty(dataContext.TechnicalDescription))
			{
				dialogPanel.Children.Add(CreateSection("  Description technique", dataContext.TechnicalDescription, null));
			}
			if (!string.IsNullOrEmpty(dataContext.Impact))
			{
				dialogPanel.Children.Add(CreateSection("  Impact si désactivé", dataContext.Impact, Color.FromArgb(25, 244, 67, 54)));
			}
			if (!string.IsNullOrEmpty(dataContext.Remediation))
			{
				dialogPanel.Children.Add(CreateSection("  Remédiation", dataContext.Remediation, Color.FromArgb(25, 76, 175, 80)));
			}
			if (!string.IsNullOrEmpty(dataContext.Reference))
			{
				StackPanel referencePanel = new StackPanel
				{
					Spacing = 4.0,
					Margin = new Thickness(0.0, 4.0, 0.0, 0.0)
				};
				referencePanel.Children.Add(new TextBlock
				{
					Text = "  Référence Microsoft Learn",
					FontSize = 13.0,
					FontWeight = FontWeights.SemiBold,
					Opacity = 0.8
				});
				referencePanel.Children.Add(new HyperlinkButton
				{
					Content = dataContext.Reference,
					NavigateUri = new Uri(dataContext.Reference),
					FontSize = 12.0
				});
				dialogPanel.Children.Add(referencePanel);
			}
			ScrollViewer content = new ScrollViewer
			{
				Content = dialogPanel,
				MaxHeight = 520.0,
				HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
			};
			await new ContentDialog
			{
				Title = "  " + dataContext.Name,
				Content = content,
				CloseButtonText = "Fermer",
				XamlRoot = base.XamlRoot,
				DefaultButton = ContentDialogButton.Close
			}.ShowAsync();
		}
	}

	private static Border CreateSection(string header, string content, Color? bgColor = null)
	{
		StackPanel stackPanel = new StackPanel
		{
			Spacing = 6.0
		};
		stackPanel.Children.Add(new TextBlock
		{
			Text = header,
			FontSize = 13.0,
			FontWeight = FontWeights.SemiBold,
			Opacity = 0.8
		});
		stackPanel.Children.Add(new TextBlock
		{
			Text = content,
			FontSize = 12.0,
			TextWrapping = TextWrapping.Wrap,
			Opacity = 0.7,
			LineHeight = 20.0
		});
		return new Border
		{
			Background = new SolidColorBrush(bgColor ?? Color.FromArgb(15, 128, 128, 128)),
			CornerRadius = new CornerRadius(8.0),
			Padding = new Thickness(14.0, 10.0, 14.0, 10.0),
			Child = stackPanel
		};
	}

	private void OnCardPointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Border border)
		{
			Border hoverBorder = border;
			if ((object)hoverBorder.RenderTransform == null)
			{
				Transform newTransform = (hoverBorder.RenderTransform = new ScaleTransform());
			}
			if (border.RenderTransform is ScaleTransform scaleTransform)
			{
				border.RenderTransformOrigin = new Point(0.5, 0.5);
				scaleTransform.ScaleX = 1.02;
				scaleTransform.ScaleY = 1.02;
			}
		}
	}

	private void OnCardPointerExited(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Border { RenderTransform: ScaleTransform renderTransform })
		{
			renderTransform.ScaleX = 1.0;
			renderTransform.ScaleY = 1.0;
		}
	}

	private static Color ParseHexColor(string hex)
	{
		byte red = 120;
		byte green = 144;
		byte blue = 156;
		if (hex.Length == 7)
		{
			red = Convert.ToByte(hex.Substring(1, 2), 16);
			green = Convert.ToByte(hex.Substring(3, 2), 16);
			blue = Convert.ToByte(hex.Substring(5, 2), 16);
		}
		return Color.FromArgb(byte.MaxValue, red, green, blue);
	}
}
