using System;
using System.Diagnostics.CodeAnalysis;
using CommunityToolkit.Mvvm.ComponentModel;
using WinRT;

namespace CHECKSEC.ViewModels;

public partial class SystemInfoViewModel : ObservableObject
{
	[ObservableProperty]
	private string _machineName = Environment.MachineName;

	[ObservableProperty]
	private string _userName = Environment.UserName;

	[ObservableProperty]
	private string _osVersion = Environment.OSVersion.ToString();

	[ObservableProperty]
	private string _dotNetVersion = Environment.Version.ToString();

	[ObservableProperty]
	private bool _is64Bit = Environment.Is64BitProcess;

	[ObservableProperty]
	private int _processorCount = Environment.ProcessorCount;
}
