ALTER TABLE deployment_items ADD COLUMN description text NULL;
CREATE INDEX deployment_items_name_idx ON deployment_items (name);
