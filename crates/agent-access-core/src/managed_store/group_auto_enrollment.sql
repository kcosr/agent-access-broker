-- Local enrollment is an administrator-owned group setting. Existing groups
-- remain opt-in, and disabling a group preserves its setting for future use.
ALTER TABLE groups
  ADD COLUMN auto_enroll_new_microsoft_users INTEGER NOT NULL DEFAULT 0
    CHECK(auto_enroll_new_microsoft_users IN (0, 1));
