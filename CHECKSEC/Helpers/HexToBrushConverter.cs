using System;
using Microsoft.UI;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace CHECKSEC.Helpers;

public sealed class HexToBrushConverter : IValueConverter
{
	public object Convert(object value, Type targetType, object parameter, string language)
	{
		if (value is string hex && hex.StartsWith('#') && hex.Length == 7)
		{
			byte red = System.Convert.ToByte(hex.Substring(1, 2), 16);
			byte green = System.Convert.ToByte(hex.Substring(3, 2), 16);
			byte blue = System.Convert.ToByte(hex.Substring(5, 2), 16);
			return new SolidColorBrush(Color.FromArgb(byte.MaxValue, red, green, blue));
		}
		return new SolidColorBrush(Colors.Gray);
	}

	public object ConvertBack(object value, Type targetType, object parameter, string language)
	{
		throw new NotImplementedException();
	}
}
