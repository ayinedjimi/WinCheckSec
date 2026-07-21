using System.Text.Json.Serialization;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Services;

public class SecureCoreSnapshot
{
	public string Name { get; set; } = string.Empty;

	[JsonConverter(typeof(JsonStringEnumConverter))]
	public SecurityStatus Status { get; set; }

	public string Value { get; set; } = string.Empty;
}
