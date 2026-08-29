from django.db import migrations


RLS_SQL = """
ALTER TABLE tenancy_workspace ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy_workspace FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy_project ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy_project FORCE ROW LEVEL SECURITY;

CREATE POLICY workspace_isolation ON tenancy_workspace
    FOR ALL TO omnilyzer_tenancy_runtime
    USING (id = NULLIF(current_setting('omnilyzer.workspace_id', true), '')::uuid)
    WITH CHECK (id = NULLIF(current_setting('omnilyzer.workspace_id', true), '')::uuid);

CREATE POLICY project_isolation ON tenancy_project
    FOR ALL TO omnilyzer_tenancy_runtime
    USING (workspace_id = NULLIF(current_setting('omnilyzer.workspace_id', true), '')::uuid)
    WITH CHECK (workspace_id = NULLIF(current_setting('omnilyzer.workspace_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenancy_workspace TO omnilyzer_tenancy_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenancy_project TO omnilyzer_tenancy_runtime;
"""

REVERSE_SQL = """
REVOKE SELECT, INSERT, UPDATE, DELETE ON tenancy_project FROM omnilyzer_tenancy_runtime;
REVOKE SELECT, INSERT, UPDATE, DELETE ON tenancy_workspace FROM omnilyzer_tenancy_runtime;
DROP POLICY project_isolation ON tenancy_project;
DROP POLICY workspace_isolation ON tenancy_workspace;
ALTER TABLE tenancy_project DISABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy_workspace DISABLE ROW LEVEL SECURITY;
"""


class Migration(migrations.Migration):
    dependencies = [("tenancy", "0001_initial")]
    operations = [migrations.RunSQL(RLS_SQL, REVERSE_SQL)]
