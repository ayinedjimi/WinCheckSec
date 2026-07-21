using System;
using CHECKSEC.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Markup;
using WinRT;

namespace CHECKSEC.Pages;

public sealed partial class AboutPage : Page
{
	public AboutViewModel ViewModel { get; }

	public AboutPage()
	{
		ViewModel = App.Services.GetRequiredService<AboutViewModel>();
		InitializeComponent();
	}
}
