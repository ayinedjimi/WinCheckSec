using Microsoft.Windows.ApplicationModel.Resources;

namespace CHECKSEC.Helpers;

public static class LocalizationHelper
{
	private static readonly ResourceLoader _loader = new ResourceLoader();

	public static string Get(string key)
	{
		try
		{
			return _loader.GetString(key);
		}
		catch
		{
			return key;
		}
	}
}
