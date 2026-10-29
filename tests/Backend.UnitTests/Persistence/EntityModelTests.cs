using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Backend.UnitTests.Persistence;

public sealed class EntityModelTests
{
    [Fact]
    public void Model_WithNavigations_DoesNotRequireSchemaChanges()
    {
        // Arrange
        using var context = new PamDbContextFactory().CreateDbContext([]);

        // Act
        bool hasSchemaChanges = context.Database.HasPendingModelChanges();

        // Assert
        Assert.False(hasSchemaChanges);
    }
}
