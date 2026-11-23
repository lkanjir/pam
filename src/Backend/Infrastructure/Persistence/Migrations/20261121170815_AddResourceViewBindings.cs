using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddResourceViewBindings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "resource_principal_bindings",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    public_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "uuidv7()"),
                    principal_id = table.Column<long>(type: "bigint", nullable: false),
                    resource_id = table.Column<long>(type: "bigint", nullable: false),
                    kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    assigned_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    assigned_by_principal_id = table.Column<long>(type: "bigint", nullable: false),
                    modified_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    modified_by_principal_id = table.Column<long>(type: "bigint", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_resource_principal_bindings", x => x.id);
                    table.CheckConstraint("ck_resource_principal_bindings_kind", "kind IN ('ViewResource')");
                    table.ForeignKey(
                        name: "fk_resource_principal_bindings_managed_resources_resource_id",
                        column: x => x.resource_id,
                        principalTable: "managed_resources",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_resource_principal_bindings_principals_assigned_by_principa",
                        column: x => x.assigned_by_principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_resource_principal_bindings_principals_modified_by_principa",
                        column: x => x.modified_by_principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_resource_principal_bindings_principals_principal_id",
                        column: x => x.principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_resource_principal_bindings_assigned_by_principal_id",
                table: "resource_principal_bindings",
                column: "assigned_by_principal_id");

            migrationBuilder.CreateIndex(
                name: "ix_resource_principal_bindings_modified_by_principal_id",
                table: "resource_principal_bindings",
                column: "modified_by_principal_id");

            migrationBuilder.CreateIndex(
                name: "ix_resource_principal_bindings_principal_id_kind_resource_id",
                table: "resource_principal_bindings",
                columns: new[] { "principal_id", "kind", "resource_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_resource_principal_bindings_public_id",
                table: "resource_principal_bindings",
                column: "public_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_resource_principal_bindings_resource_id_kind_principal_id",
                table: "resource_principal_bindings",
                columns: new[] { "resource_id", "kind", "principal_id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "resource_principal_bindings");
        }
    }
}
