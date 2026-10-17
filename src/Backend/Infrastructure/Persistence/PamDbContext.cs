using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistence;

public class PamDbContext :  DbContext
{
    public PamDbContext(DbContextOptions<PamDbContext> options) : base(options){}
}