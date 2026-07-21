using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Input;
using CHECKSEC.ViewModels;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Markup;
using WinRT;

namespace CHECKSEC.Pages;

public sealed partial class SettingsPage : Page
{







	public SettingsViewModel ViewModel { get; }

	public SettingsPage()
	{
		ViewModel = App.Services.GetRequiredService<SettingsViewModel>();
		InitializeComponent();
	}

	private void OnCsvSepChanged(object sender, SelectionChangedEventArgs e)
	{
		if (CsvSepCombo?.SelectedItem is ComboBoxItem { Tag: string tag })
		{
			ViewModel.CsvSeparator = tag;
		}
	}



}
