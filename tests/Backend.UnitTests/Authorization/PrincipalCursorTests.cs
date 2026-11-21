using Application.Common.Pagination;
using Application.Principals;

namespace Backend.UnitTests.Authorization;

public sealed class PrincipalCursorTests
{
    [Fact]
    public void Parse_ValidCursor_PreservesExactContinuation()
    {
        // Arrange
        var expected = new PrincipalCursor(Guid.Parse("d5077489-f48b-43ef-90c3-57b6e12679de"));
        string encoded = CursorCodec.Encode(expected);

        // Act
        bool parsed = PrincipalCursor.TryParse(encoded, out var actual);

        // Assert
        Assert.True(parsed);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("e30")]
    [InlineData("eyJsYXN0UHVibGljSWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAifQ")]
    public void Parse_InvalidOrEmptyPosition_RejectsContinuation(string encoded)
    {
        // Act
        bool parsed = PrincipalCursor.TryParse(encoded, out var actual);

        // Assert
        Assert.False(parsed);
        Assert.Null(actual);
    }
}
