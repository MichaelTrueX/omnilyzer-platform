import os
import unittest
from uuid import UUID

from django.db import DatabaseError, connection, connections, transaction
from django.db.models import Count

from tenancy.context import workspace_scope
from tenancy.models import Project, Workspace


WORKSPACE_A = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
WORKSPACE_B = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
PROJECT_A1 = UUID("a1000000-0000-4000-8000-000000000001")
PROJECT_A2 = UUID("a2000000-0000-4000-8000-000000000002")
PROJECT_B1 = UUID("b1000000-0000-4000-8000-000000000001")
PROJECT_B2 = UUID("b2000000-0000-4000-8000-000000000002")


class RLSValidationTests(unittest.TestCase):
    def setUp(self):
        self._reset_workspace(
            WORKSPACE_A,
            "Workspace A",
            "personal",
            ((PROJECT_A1, "Shared Name"), (PROJECT_A2, "Project A2")),
        )
        self._reset_workspace(
            WORKSPACE_B,
            "Workspace B",
            "organization",
            ((PROJECT_B1, "Shared Name"), (PROJECT_B2, "Project B2")),
        )

    @staticmethod
    def _reset_workspace(workspace_id, name, workspace_type, projects):
        with workspace_scope(workspace_id):
            workspace, _ = Workspace.objects.update_or_create(
                id=workspace_id,
                defaults={"name": name, "workspace_type": workspace_type},
            )
            Project.objects.all().delete()
            Project.objects.bulk_create(
                [
                    Project(
                        id=project_id,
                        workspace=workspace,
                        name=project_name,
                        description=f"Synthetic fixture for {name}",
                    )
                    for project_id, project_name in projects
                ]
            )

    def test_01_missing_context_fails_closed_for_reads_and_writes(self):
        self.assertEqual(Workspace.objects.count(), 0)
        self.assertEqual(Project.objects.count(), 0)
        self.assertEqual(Project.objects.aggregate(total=Count("id"))["total"], 0)
        self.assertEqual(Project.objects.filter(id=PROJECT_A1).update(name="blocked"), 0)
        self.assertEqual(Project.objects.filter(id=PROJECT_A1).delete()[0], 0)
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM tenancy_project")
            self.assertEqual(cursor.fetchall(), [])
        with self.assertRaises(DatabaseError):
            Workspace.objects.create(id=UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc"), name="Blocked", workspace_type="personal")

    def test_02_normal_orm_isolation_is_symmetric_without_filters(self):
        with workspace_scope(WORKSPACE_A):
            self.assertEqual(list(Workspace.objects.values_list("id", flat=True)), [WORKSPACE_A])
            self.assertEqual(set(Project.objects.values_list("id", flat=True)), {PROJECT_A1, PROJECT_A2})
        with workspace_scope(WORKSPACE_B):
            self.assertEqual(list(Workspace.objects.values_list("id", flat=True)), [WORKSPACE_B])
            self.assertEqual(set(Project.objects.values_list("id", flat=True)), {PROJECT_B1, PROJECT_B2})

    def test_03_guessed_project_identifiers_cannot_read_update_or_delete_b(self):
        with workspace_scope(WORKSPACE_A):
            with self.assertRaises(Project.DoesNotExist):
                Project.objects.get(id=PROJECT_B1)
            self.assertEqual(Project.objects.filter(id=PROJECT_B1).update(name="compromised"), 0)
            self.assertEqual(Project.objects.filter(id=PROJECT_B1).delete()[0], 0)
        with workspace_scope(WORKSPACE_B):
            project = Project.objects.get(id=PROJECT_B1)
            self.assertEqual(project.name, "Shared Name")

    def test_04_raw_sql_broad_select_is_isolated(self):
        with workspace_scope(WORKSPACE_A):
            with connection.cursor() as cursor:
                cursor.execute("SELECT id, workspace_id FROM tenancy_project ORDER BY id")
                rows = cursor.fetchall()
        self.assertEqual({row[0] for row in rows}, {PROJECT_A1, PROJECT_A2})
        self.assertEqual({row[1] for row in rows}, {WORKSPACE_A})

    def test_05_join_and_aggregates_are_isolated(self):
        with workspace_scope(WORKSPACE_A):
            joined = list(
                Project.objects.select_related("workspace").values_list(
                    "id", "workspace__id", "workspace__name"
                )
            )
            aggregate = Project.objects.aggregate(total=Count("id"))
        self.assertEqual({row[0] for row in joined}, {PROJECT_A1, PROJECT_A2})
        self.assertEqual({row[1] for row in joined}, {WORKSPACE_A})
        self.assertEqual({row[2] for row in joined}, {"Workspace A"})
        self.assertEqual(aggregate, {"total": 2})

    def test_06_broad_orm_update_only_changes_active_workspace(self):
        with workspace_scope(WORKSPACE_A):
            self.assertEqual(Project.objects.update(status="archived"), 2)
        with workspace_scope(WORKSPACE_B):
            self.assertEqual(set(Project.objects.values_list("status", flat=True)), {"active"})

    def test_07_broad_orm_delete_only_deletes_active_workspace(self):
        with workspace_scope(WORKSPACE_A):
            self.assertEqual(Project.objects.all().delete()[0], 2)
        with workspace_scope(WORKSPACE_B):
            self.assertEqual(Project.objects.count(), 2)

    def test_08_cross_workspace_project_insert_and_move_are_rejected(self):
        with self.assertRaises(DatabaseError):
            with workspace_scope(WORKSPACE_A):
                Project.objects.create(
                    workspace_id=WORKSPACE_B,
                    name="Foreign insert",
                    description="must fail",
                )
        with self.assertRaises(DatabaseError):
            with workspace_scope(WORKSPACE_A):
                Project.objects.filter(id=PROJECT_A1).update(workspace_id=WORKSPACE_B)
        with workspace_scope(WORKSPACE_A):
            self.assertEqual(Project.objects.get(id=PROJECT_A1).workspace_id, WORKSPACE_A)
        with workspace_scope(WORKSPACE_B):
            self.assertFalse(Project.objects.filter(name="Foreign insert").exists())

    def test_09_workspace_table_blocks_cross_workspace_actions(self):
        foreign_id = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        with workspace_scope(WORKSPACE_A):
            self.assertFalse(Workspace.objects.filter(id=WORKSPACE_B).exists())
            self.assertEqual(Workspace.objects.filter(id=WORKSPACE_B).update(name="compromised"), 0)
            self.assertEqual(Workspace.objects.filter(id=WORKSPACE_B).delete()[0], 0)
        with self.assertRaises(DatabaseError):
            with workspace_scope(WORKSPACE_A):
                Workspace.objects.create(id=foreign_id, name="Foreign", workspace_type="personal")
        with workspace_scope(WORKSPACE_B):
            self.assertEqual(Workspace.objects.get().name, "Workspace B")

    def test_10_context_clears_on_same_connection_and_sequential_reuse(self):
        connection.ensure_connection()
        underlying_connection_id = id(connection.connection)
        with workspace_scope(WORKSPACE_A):
            self.assertEqual(set(Project.objects.values_list("workspace_id", flat=True)), {WORKSPACE_A})
        self.assertEqual(id(connection.connection), underlying_connection_id)
        self.assertEqual(Project.objects.count(), 0)
        with workspace_scope(WORKSPACE_B):
            self.assertEqual(set(Project.objects.values_list("workspace_id", flat=True)), {WORKSPACE_B})
        self.assertEqual(id(connection.connection), underlying_connection_id)
        self.assertEqual(Project.objects.count(), 0)

    def test_11_rollback_removes_data_and_context(self):
        rolled_back_id = UUID("a3000000-0000-4000-8000-000000000003")
        with self.assertRaisesRegex(RuntimeError, "deliberate rollback"):
            with workspace_scope(WORKSPACE_A):
                Project.objects.create(
                    id=rolled_back_id,
                    workspace_id=WORKSPACE_A,
                    name="Rolled back",
                )
                raise RuntimeError("deliberate rollback")
        self.assertEqual(Project.objects.count(), 0)
        with workspace_scope(WORKSPACE_A):
            self.assertFalse(Project.objects.filter(id=rolled_back_id).exists())

    def test_12_unsafe_nested_scope_is_rejected(self):
        with workspace_scope(WORKSPACE_A):
            with self.assertRaisesRegex(RuntimeError, "cannot be nested"):
                with workspace_scope(WORKSPACE_B):
                    pass
            self.assertEqual(set(Project.objects.values_list("workspace_id", flat=True)), {WORKSPACE_A})

    def test_13_roles_ownership_rls_and_privileges(self):
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT rolname, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication
                FROM pg_roles
                WHERE rolname IN ('omnilyzer_tenancy_runtime', 'omnilyzer_tenancy_owner')
                ORDER BY rolname
                """
            )
            roles = {row[0]: row[1:] for row in cursor.fetchall()}
            cursor.execute(
                """
                SELECT c.relname, r.rolname, c.relrowsecurity, c.relforcerowsecurity
                FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
                WHERE c.relname IN ('tenancy_workspace', 'tenancy_project')
                ORDER BY c.relname
                """
            )
            tables = cursor.fetchall()
            cursor.execute(
                """
                SELECT privilege_type FROM information_schema.role_table_grants
                WHERE grantee = 'omnilyzer_tenancy_runtime'
                  AND table_name = 'tenancy_project'
                """
            )
            privileges = {row[0] for row in cursor.fetchall()}
            cursor.execute(
                """
                SELECT
                    has_database_privilege('omnilyzer_tenancy_runtime', current_database(), 'CONNECT'),
                    has_database_privilege('omnilyzer_tenancy_runtime', current_database(), 'TEMPORARY'),
                    has_schema_privilege('omnilyzer_tenancy_runtime', 'public', 'USAGE'),
                    has_schema_privilege('omnilyzer_tenancy_runtime', 'public', 'CREATE'),
                    pg_get_userbyid(d.datdba), pg_get_userbyid(n.nspowner)
                FROM pg_database d, pg_namespace n
                WHERE d.datname = current_database() AND n.nspname = 'public'
                """
            )
            database_facts = cursor.fetchone()

        self.assertEqual(roles["omnilyzer_tenancy_runtime"], (False, False, False, False, False))
        self.assertEqual(roles["omnilyzer_tenancy_owner"], (False, False, False, False, False))
        self.assertEqual(len(tables), 2)
        for _, owner, rls_enabled, rls_forced in tables:
            self.assertEqual(owner, "omnilyzer_tenancy_owner")
            self.assertTrue(rls_enabled)
            self.assertTrue(rls_forced)
        self.assertEqual(privileges, {"SELECT", "INSERT", "UPDATE", "DELETE"})
        self.assertEqual(
            database_facts,
            (True, False, True, False, "omnilyzer_tenancy_owner", "omnilyzer_tenancy_owner"),
        )

    def test_14_runtime_cannot_alter_drop_or_disable_rls(self):
        statements = (
            "ALTER TABLE tenancy_project ADD COLUMN forbidden text",
            "DROP TABLE tenancy_project",
            "ALTER TABLE tenancy_project DISABLE ROW LEVEL SECURITY",
        )
        for statement in statements:
            with self.subTest(statement=statement):
                with self.assertRaises(DatabaseError):
                    with transaction.atomic(using="default"):
                        with connection.cursor() as cursor:
                            cursor.execute(statement)
        with connection.cursor() as cursor:
            cursor.execute("SELECT to_regclass('public.tenancy_project')")
            self.assertEqual(cursor.fetchone()[0], "tenancy_project")

    def test_15_forced_rls_prevents_unscoped_owner_reads(self):
        migration_connection = connections["migration"]
        with migration_connection.cursor() as cursor:
            cursor.execute("SELECT current_user")
            self.assertEqual(cursor.fetchone()[0], "omnilyzer_tenancy_owner")
            cursor.execute("SELECT count(*) FROM tenancy_workspace")
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute("SELECT count(*) FROM tenancy_project")
            self.assertEqual(cursor.fetchone()[0], 0)

    def test_16_cluster_has_no_tcp_and_private_unix_socket(self):
        with connection.cursor() as cursor:
            cursor.execute("SHOW listen_addresses")
            self.assertEqual(cursor.fetchone()[0], "")
            cursor.execute("SHOW unix_socket_permissions")
            self.assertEqual(cursor.fetchone()[0], "0700")
        socket_mode = os.stat("/tmp/omnilyzer-platform-tenancy-spike-socket").st_mode & 0o777
        self.assertEqual(socket_mode, 0o700)


if __name__ == "__main__":
    unittest.main()
