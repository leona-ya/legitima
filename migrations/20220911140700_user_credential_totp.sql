ALTER TYPE user_credential_types ADD VALUE 'totp_credential';

ALTER TABLE user_credential
    ADD temporary boolean DEFAULT false NOT NULL;

UPDATE user_credential SET temporary = true WHERE credential_type = 'webauthn_registration' OR credential_type = 'webauthn_authentication'
