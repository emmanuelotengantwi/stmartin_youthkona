<?php
// Legacy fallback config (kept for compatibility).
const ADMIN_PASSWORD = 'ChangeThisStrongPassword123!';

function adminPasswordFromEnv(): string
{
    return getenv('ADMIN_PASSWORD') ?: ADMIN_PASSWORD;
}
