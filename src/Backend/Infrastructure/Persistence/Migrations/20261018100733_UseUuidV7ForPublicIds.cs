using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class UseUuidV7ForPublicIds : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "principals",
                type: "uuid",
                nullable: false,
                defaultValueSql: "uuidv7()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "gen_random_uuid()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "policy_evaluations",
                type: "uuid",
                nullable: false,
                defaultValueSql: "uuidv7()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "gen_random_uuid()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "pam_role_assignments",
                type: "uuid",
                nullable: false,
                defaultValueSql: "uuidv7()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "gen_random_uuid()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "managed_resources",
                type: "uuid",
                nullable: false,
                defaultValueSql: "uuidv7()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "gen_random_uuid()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "entitlements",
                type: "uuid",
                nullable: false,
                defaultValueSql: "uuidv7()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "gen_random_uuid()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "eligibility_rules",
                type: "uuid",
                nullable: false,
                defaultValueSql: "uuidv7()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "gen_random_uuid()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "authentication_session_ledger",
                type: "uuid",
                nullable: false,
                defaultValueSql: "uuidv7()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "gen_random_uuid()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "audit_events",
                type: "uuid",
                nullable: false,
                defaultValueSql: "uuidv7()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "gen_random_uuid()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "access_requests",
                type: "uuid",
                nullable: false,
                defaultValueSql: "uuidv7()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "gen_random_uuid()");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "principals",
                type: "uuid",
                nullable: false,
                defaultValueSql: "gen_random_uuid()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "uuidv7()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "policy_evaluations",
                type: "uuid",
                nullable: false,
                defaultValueSql: "gen_random_uuid()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "uuidv7()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "pam_role_assignments",
                type: "uuid",
                nullable: false,
                defaultValueSql: "gen_random_uuid()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "uuidv7()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "managed_resources",
                type: "uuid",
                nullable: false,
                defaultValueSql: "gen_random_uuid()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "uuidv7()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "entitlements",
                type: "uuid",
                nullable: false,
                defaultValueSql: "gen_random_uuid()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "uuidv7()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "eligibility_rules",
                type: "uuid",
                nullable: false,
                defaultValueSql: "gen_random_uuid()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "uuidv7()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "authentication_session_ledger",
                type: "uuid",
                nullable: false,
                defaultValueSql: "gen_random_uuid()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "uuidv7()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "audit_events",
                type: "uuid",
                nullable: false,
                defaultValueSql: "gen_random_uuid()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "uuidv7()");

            migrationBuilder.AlterColumn<Guid>(
                name: "public_id",
                table: "access_requests",
                type: "uuid",
                nullable: false,
                defaultValueSql: "gen_random_uuid()",
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldDefaultValueSql: "uuidv7()");
        }
    }
}
