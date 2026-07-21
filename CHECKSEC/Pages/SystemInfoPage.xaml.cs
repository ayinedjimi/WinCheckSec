using System;
using System.ComponentModel;
using System.Diagnostics;
using CHECKSEC.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Markup;
using WinRT;

namespace CHECKSEC.Pages;

public sealed partial class SystemInfoPage : Page
{

	public SystemInfoViewModel ViewModel { get; }

	public SystemInfoPage()
	{
		ViewModel = App.Services.GetRequiredService<SystemInfoViewModel>();
		InitializeComponent();
	}
}
