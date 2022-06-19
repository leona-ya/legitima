CREATE TYPE user_credential_types AS ENUM ('webauthn_registration', 'webauthn_credential');

CREATE TABLE user_credential
(
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username varchar NOT NULL,
    label varchar,
    created_at timestamp DEFAULT now() NOT NULL,
    credential_type user_credential_types NOT NULL,
    credential_data jsonb NOT NULL
);
