import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(
            name="Workspace",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                ("workspace_type", models.CharField(choices=[("personal", "Personal"), ("organization", "Organization")], max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="Project",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                ("description", models.TextField(blank=True)),
                ("status", models.CharField(choices=[("active", "Active"), ("archived", "Archived")], default="active", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("workspace", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="tenancy.workspace")),
            ],
            options={
                "indexes": [models.Index(fields=["workspace", "status"], name="tenancy_project_ws_status_idx")],
                "constraints": [models.UniqueConstraint(fields=("workspace", "name"), name="tenancy_project_workspace_name_uniq")],
            },
        ),
    ]
