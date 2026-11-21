namespace Application.Bootstrap;

public interface IBootstrapService
{
    Task<BootstrapStateResponse> GetAsync(CancellationToken cancellationToken = default);
}
