using Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class PolicyEvaluationConfiguration : IEntityTypeConfiguration<PolicyEvaluation>
{
    public void Configure(EntityTypeBuilder<PolicyEvaluation> builder)
    {
        builder.ToTable("policy_evaluations");
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).UseIdentityByDefaultColumn();
        builder.Property(e => e.PublicId).HasDefaultValueSql("uuidv7()");
        builder.Property(e => e.PolicyCode).IsRequired();
        builder.Property(e => e.Decision).IsRequired();
        builder.Property(e => e.EvaluatedAt).HasDefaultValueSql("now()");
        builder.Property(e => e.InputSnapshot).HasColumnType("jsonb");

        builder.HasIndex(e => e.PublicId).IsUnique();
        builder.HasIndex(e => e.RequestId).IsUnique();

        builder.HasOne<AccessRequest>()
               .WithMany()
               .HasForeignKey(e => e.RequestId)
               .OnDelete(DeleteBehavior.Restrict);
    }
}
