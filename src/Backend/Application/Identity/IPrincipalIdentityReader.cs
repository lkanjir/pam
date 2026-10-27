namespace Application.Identity;

public interface IPrincipalIdentityReader
{
    Task<PrincipalIdentity?> FindAsync(string issuer, string subject, CancellationToken cancellationToken = default);
}
