using System;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using CHECKSEC.Services;
using CHECKSEC.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
using WinRT;
using Windows.Foundation;

namespace CHECKSEC.Pages;

public sealed partial class HistoryPage : Page
{












	public HistoryViewModel ViewModel { get; }

	public HistoryPage()
	{
		ViewModel = App.Services.GetRequiredService<HistoryViewModel>();
		InitializeComponent();
	}

	private void OnLoaded(object sender, RoutedEventArgs e)
	{
		ViewModel.LoadIfNeeded();
	}

	private void OnDeleteSnapshot(object sender, RoutedEventArgs e)
	{
		if (sender is Button { Tag: AnalysisSnapshot tag })
		{
			ViewModel.DeleteCommand.Execute(tag);
		}
	}

	private void OnCompareClick(object sender, RoutedEventArgs e)
	{
		ViewModel.CompareCommand.Execute(null);
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
				scaleTransform.ScaleX = 1.01;
				scaleTransform.ScaleY = 1.01;
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



}
