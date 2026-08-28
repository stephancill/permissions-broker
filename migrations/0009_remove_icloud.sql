-- Remove iCloud CalDAV provider support.
-- Cleans up any previously-linked iCloud accounts and pending connect states.

DELETE FROM linked_accounts WHERE provider = 'icloud';
DELETE FROM connect_states WHERE provider = 'icloud';
