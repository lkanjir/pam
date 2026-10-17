using Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class AuthenticationSessionLedgerConfiguration : IEntityTypeConfiguration<AuthenticationSessionLedger>
{
    public void Configure(EntityTypeBuilder<AuthenticationSessionLedger> builder)
    {
        builder.ToTable("authentication_session_ledger");
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).UseIdentityByDefaultColumn();
        builder.Property(e => e.PublicId).HasDefaultValueSql("gen_random_uuid()");
        builder.Property(e => e.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(e => e.UserAgent).HasMaxLength(2048);

        builder.HasIndex(e => e.PublicId).IsUnique();
        builder.HasIndex(e => e.SessionIdHash).IsUnique();

        builder.HasOne<Principal>()
               .WithMany()
               .HasForeignKey(e => e.PrincipalId)
               .OnDelete(DeleteBehavior.Restrict);
    }
}
