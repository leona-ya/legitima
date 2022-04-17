CREATE TABLE oauth_client
(
    client_id     VARCHAR NOT NULL PRIMARY KEY,
    login_allowed BOOLEAN NOT NULL
);

CREATE TABLE "group"
(
    id        SERIAL PRIMARY KEY,
    name      VARCHAR NOT NULL,
    ldap_dn VARCHAR NOT NULL
);

CREATE TABLE group_permission
(
    id        SERIAL PRIMARY KEY,
    client_id VARCHAR NOT NULL,
    CONSTRAINT fk_client_id
        FOREIGN KEY (client_id)
            REFERENCES oauth_client (client_id),
    group_id  INTEGER NOT NULL,
    CONSTRAINT fk_group_id
        FOREIGN KEY (group_id)
            REFERENCES "group" (id)
);
