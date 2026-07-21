using System;
using Microsoft.UI.Xaml.Data;

namespace CHECKSEC.Helpers;

public sealed class DateTimeConverter : IValueConverter
{
	public object Convert(object value, Type targetType, object parameter, string language)
	{
		if (!(value is DateTime dateTime))
		{
			return value?.ToString() ?? "";
		}
		return dateTime.ToString("dd/MM/yyyy HH:mm:ss");
	}

	public object ConvertBack(object value, Type targetType, object parameter, string language)
	{
		throw new NotImplementedException();
	}
}
