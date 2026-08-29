CREATE TABLE deployment_items (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL
);
INSERT INTO deployment_items (name) VALUES ('immutable deployment fixture');
