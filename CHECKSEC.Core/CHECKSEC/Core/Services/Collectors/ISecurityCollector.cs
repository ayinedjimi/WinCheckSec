using System.Threading;
using System.Threading.Tasks;
using CHECKSEC.Core.Models;

namespace CHECKSEC.Core.Services.Collectors;

public interface ISecurityCollector
{
	string Name { get; }

	string Category { get; }

	Task<CollectorReport> CollectAsync(CancellationToken ct = default(CancellationToken));
}
