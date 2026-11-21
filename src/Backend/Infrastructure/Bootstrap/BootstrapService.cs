using Application.Bootstrap;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Bootstrap;

public sealed class BootstrapService(PamDbContext database) : IBootstrapService
{
    public async Task<BootstrapStateResponse> GetAsync(CancellationToken cancellationToken = default) =>
        await database.PamInstallations.AsNoTracking().Select(value => new BootstrapStateResponse(true,
            value.CompletedAt == null,
            value.BootstrapPrincipal == null ? null : value.BootstrapPrincipal.PublicId,
            value.InitializedAt, value.CompletedAt,
            value.CompletedByPrincipal == null ? null : value.CompletedByPrincipal.PublicId)
        { Version = value.Version }).SingleOrDefaultAsync(cancellationToken)
        ?? new BootstrapStateResponse(false, false, null, null, null, null);
}
