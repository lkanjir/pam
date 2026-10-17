using System;
using System.Net;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "principals",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    public_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    issuer = table.Column<string>(type: "text", nullable: false),
                    subject = table.Column<string>(type: "text", nullable: false),
                    display_name = table.Column<string>(type: "text", nullable: false),
                    is_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    modified_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_principals", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "authentication_session_ledger",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    public_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    principal_id = table.Column<long>(type: "bigint", nullable: false),
                    session_id_hash = table.Column<string>(type: "text", nullable: false),
                    idp_session_id = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    expected_expires_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ended_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    end_reason = table.Column<string>(type: "text", nullable: true),
                    client_ip_address = table.Column<IPAddress>(type: "inet", nullable: true),
                    user_agent = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true),
                    browser = table.Column<string>(type: "text", nullable: true),
                    operating_system = table.Column<string>(type: "text", nullable: true),
                    device_type = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_authentication_session_ledger", x => x.id);
                    table.ForeignKey(
                        name: "fk_authentication_session_ledger_principals_principal_id",
                        column: x => x.principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "managed_resources",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    public_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    name = table.Column<string>(type: "text", nullable: false),
                    description = table.Column<string>(type: "text", nullable: true),
                    resource_type = table.Column<string>(type: "text", nullable: false),
                    environment = table.Column<string>(type: "text", nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    created_by_principal_id = table.Column<long>(type: "bigint", nullable: false),
                    modified_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    modified_by_principal_id = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_managed_resources", x => x.id);
                    table.ForeignKey(
                        name: "fk_managed_resources_principals_created_by_principal_id",
                        column: x => x.created_by_principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_managed_resources_principals_modified_by_principal_id",
                        column: x => x.modified_by_principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "pam_roles",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    code = table.Column<string>(type: "text", nullable: false),
                    description = table.Column<string>(type: "text", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    created_by_principal_id = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_pam_roles", x => x.id);
                    table.ForeignKey(
                        name: "fk_pam_roles_principals_created_by_principal_id",
                        column: x => x.created_by_principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "entitlements",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    public_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    resource_id = table.Column<long>(type: "bigint", nullable: false),
                    code = table.Column<string>(type: "text", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    max_duration_minutes = table.Column<int>(type: "integer", nullable: false),
                    requires_approval = table.Column<bool>(type: "boolean", nullable: false),
                    requires_ticket = table.Column<bool>(type: "boolean", nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_entitlements", x => x.id);
                    table.CheckConstraint("ck_entitlements_max_duration_minutes", "max_duration_minutes > 0");
                    table.ForeignKey(
                        name: "fk_entitlements_managed_resources_resource_id",
                        column: x => x.resource_id,
                        principalTable: "managed_resources",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "pam_role_assignments",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    public_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    principal_id = table.Column<long>(type: "bigint", nullable: false),
                    role_id = table.Column<int>(type: "integer", nullable: false),
                    assigned_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    assigned_by_principal_id = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_pam_role_assignments", x => x.id);
                    table.ForeignKey(
                        name: "fk_pam_role_assignments_pam_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "pam_roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_pam_role_assignments_principals_assigned_by_principal_id",
                        column: x => x.assigned_by_principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_pam_role_assignments_principals_principal_id",
                        column: x => x.principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "access_requests",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    public_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    requester_principal_id = table.Column<long>(type: "bigint", nullable: false),
                    entitlement_id = table.Column<long>(type: "bigint", nullable: false),
                    requested_duration_minutes = table.Column<int>(type: "integer", nullable: false),
                    justification = table.Column<string>(type: "text", nullable: false),
                    ticket_reference = table.Column<string>(type: "text", nullable: true),
                    state = table.Column<string>(type: "text", nullable: false),
                    idempotency_key = table.Column<string>(type: "text", nullable: false),
                    payload_hash = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_access_requests", x => x.id);
                    table.CheckConstraint("ck_access_requests_requested_duration_minutes", "requested_duration_minutes > 0");
                    table.ForeignKey(
                        name: "fk_access_requests_entitlements_entitlement_id",
                        column: x => x.entitlement_id,
                        principalTable: "entitlements",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_access_requests_principals_requester_principal_id",
                        column: x => x.requester_principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "eligibility_rules",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    public_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    principal_id = table.Column<long>(type: "bigint", nullable: false),
                    entitlement_id = table.Column<long>(type: "bigint", nullable: false),
                    is_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_eligibility_rules", x => x.id);
                    table.ForeignKey(
                        name: "fk_eligibility_rules_entitlements_entitlement_id",
                        column: x => x.entitlement_id,
                        principalTable: "entitlements",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_eligibility_rules_principals_principal_id",
                        column: x => x.principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "audit_events",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    public_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    event_type = table.Column<string>(type: "text", nullable: false),
                    schema_version = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    occurred_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    actor_kind = table.Column<string>(type: "text", nullable: false),
                    actor_principal_id = table.Column<long>(type: "bigint", nullable: true),
                    subject_principal_id = table.Column<long>(type: "bigint", nullable: true),
                    resource_id = table.Column<long>(type: "bigint", nullable: true),
                    entitlement_id = table.Column<long>(type: "bigint", nullable: true),
                    request_id = table.Column<long>(type: "bigint", nullable: true),
                    actor_snapshot = table.Column<string>(type: "jsonb", nullable: true),
                    subject_snapshot = table.Column<string>(type: "jsonb", nullable: true),
                    resource_snapshot = table.Column<string>(type: "jsonb", nullable: true),
                    entitlement_snapshot = table.Column<string>(type: "jsonb", nullable: true),
                    session_id_hash = table.Column<string>(type: "text", nullable: true),
                    correlation_id = table.Column<string>(type: "text", nullable: false),
                    causation_id = table.Column<Guid>(type: "uuid", nullable: true),
                    source = table.Column<string>(type: "text", nullable: false),
                    outcome = table.Column<string>(type: "text", nullable: true),
                    reason_code = table.Column<string>(type: "text", nullable: true),
                    metadata = table.Column<string>(type: "jsonb", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_events", x => x.id);
                    table.ForeignKey(
                        name: "fk_audit_events_access_requests_request_id",
                        column: x => x.request_id,
                        principalTable: "access_requests",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_audit_events_entitlements_entitlement_id",
                        column: x => x.entitlement_id,
                        principalTable: "entitlements",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_audit_events_managed_resources_resource_id",
                        column: x => x.resource_id,
                        principalTable: "managed_resources",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_audit_events_principals_actor_principal_id",
                        column: x => x.actor_principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_audit_events_principals_subject_principal_id",
                        column: x => x.subject_principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "policy_evaluations",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    public_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    request_id = table.Column<long>(type: "bigint", nullable: false),
                    policy_code = table.Column<string>(type: "text", nullable: false),
                    policy_version = table.Column<int>(type: "integer", nullable: false),
                    decision = table.Column<string>(type: "text", nullable: false),
                    reason_code = table.Column<string>(type: "text", nullable: true),
                    explanation = table.Column<string>(type: "text", nullable: true),
                    input_snapshot = table.Column<string>(type: "jsonb", nullable: true),
                    evaluated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_policy_evaluations", x => x.id);
                    table.ForeignKey(
                        name: "fk_policy_evaluations_access_requests_request_id",
                        column: x => x.request_id,
                        principalTable: "access_requests",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_access_requests_entitlement_id",
                table: "access_requests",
                column: "entitlement_id");

            migrationBuilder.CreateIndex(
                name: "ix_access_requests_public_id",
                table: "access_requests",
                column: "public_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_access_requests_requester_principal_id_idempotency_key",
                table: "access_requests",
                columns: new[] { "requester_principal_id", "idempotency_key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_actor_principal_id",
                table: "audit_events",
                column: "actor_principal_id");

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_entitlement_id",
                table: "audit_events",
                column: "entitlement_id");

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_public_id",
                table: "audit_events",
                column: "public_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_request_id",
                table: "audit_events",
                column: "request_id");

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_resource_id",
                table: "audit_events",
                column: "resource_id");

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_subject_principal_id",
                table: "audit_events",
                column: "subject_principal_id");

            migrationBuilder.CreateIndex(
                name: "ix_authentication_session_ledger_principal_id",
                table: "authentication_session_ledger",
                column: "principal_id");

            migrationBuilder.CreateIndex(
                name: "ix_authentication_session_ledger_public_id",
                table: "authentication_session_ledger",
                column: "public_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_authentication_session_ledger_session_id_hash",
                table: "authentication_session_ledger",
                column: "session_id_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_eligibility_rules_entitlement_id",
                table: "eligibility_rules",
                column: "entitlement_id");

            migrationBuilder.CreateIndex(
                name: "ix_eligibility_rules_principal_id_entitlement_id",
                table: "eligibility_rules",
                columns: new[] { "principal_id", "entitlement_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_eligibility_rules_public_id",
                table: "eligibility_rules",
                column: "public_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_entitlements_public_id",
                table: "entitlements",
                column: "public_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_entitlements_resource_id_code",
                table: "entitlements",
                columns: new[] { "resource_id", "code" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_managed_resources_created_by_principal_id",
                table: "managed_resources",
                column: "created_by_principal_id");

            migrationBuilder.CreateIndex(
                name: "ix_managed_resources_modified_by_principal_id",
                table: "managed_resources",
                column: "modified_by_principal_id");

            migrationBuilder.CreateIndex(
                name: "ix_managed_resources_public_id",
                table: "managed_resources",
                column: "public_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_pam_role_assignments_assigned_by_principal_id",
                table: "pam_role_assignments",
                column: "assigned_by_principal_id");

            migrationBuilder.CreateIndex(
                name: "ix_pam_role_assignments_principal_id_role_id",
                table: "pam_role_assignments",
                columns: new[] { "principal_id", "role_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_pam_role_assignments_public_id",
                table: "pam_role_assignments",
                column: "public_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_pam_role_assignments_role_id",
                table: "pam_role_assignments",
                column: "role_id");

            migrationBuilder.CreateIndex(
                name: "ix_pam_roles_code",
                table: "pam_roles",
                column: "code",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_pam_roles_created_by_principal_id",
                table: "pam_roles",
                column: "created_by_principal_id");

            migrationBuilder.CreateIndex(
                name: "ix_policy_evaluations_public_id",
                table: "policy_evaluations",
                column: "public_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_policy_evaluations_request_id",
                table: "policy_evaluations",
                column: "request_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_principals_issuer_subject",
                table: "principals",
                columns: new[] { "issuer", "subject" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_principals_public_id",
                table: "principals",
                column: "public_id",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "audit_events");

            migrationBuilder.DropTable(
                name: "authentication_session_ledger");

            migrationBuilder.DropTable(
                name: "eligibility_rules");

            migrationBuilder.DropTable(
                name: "pam_role_assignments");

            migrationBuilder.DropTable(
                name: "policy_evaluations");

            migrationBuilder.DropTable(
                name: "pam_roles");

            migrationBuilder.DropTable(
                name: "access_requests");

            migrationBuilder.DropTable(
                name: "entitlements");

            migrationBuilder.DropTable(
                name: "managed_resources");

            migrationBuilder.DropTable(
                name: "principals");
        }
    }
}
