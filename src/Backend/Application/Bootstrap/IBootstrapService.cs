using Application.Authorization;

namespace Application.Bootstrap;

public interface IBootstrapService
{
    Task<BootstrapStateResponse> GetAsync(CancellationToken cancellationToken = default);
    Task<BootstrapWriteResult> CompleteAsync(CompleteBootstrapRequest request, AdministrativeActor actor,
        uint expectedVersion, string correlationId, CancellationToken cancellationToken = default);
}
