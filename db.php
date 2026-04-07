<?php
/**
 * DB credentials are sourced from environment variables in production (Vercel).
 * Local fallback values keep XAMPP development working.
 */
$isVercel = (getenv('VERCEL') === '1');
$host = getenv('DB_HOST') ?: '127.0.0.1';
$port = (int)(getenv('DB_PORT') ?: 3306);
$dbname = getenv('DB_NAME') ?: 'stmartin_youthkona';
$username = getenv('DB_USER') ?: 'root';
$password = getenv('DB_PASS') ?: '';

$missingVars = [];
foreach (['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASS'] as $key) {
    $val = getenv($key);
    if ($val === false || $val === '') {
        $missingVars[] = $key;
    }
}

if ($isVercel && $missingVars) {
    error_log('Database env vars missing: ' . implode(', ', $missingVars));
    die('Database connection failed.');
}

$dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";

try {
    $pdo = new PDO($dsn, $username, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $e) {
    // Log detailed error server-side (Vercel Functions logs), but keep the UI message generic.
    error_log('Database connection failed: ' . $e->getMessage());

    $isProd = $isVercel || (getenv('APP_ENV') === 'production');
    die($isProd ? 'Database connection failed.' : ('Database connection failed: ' . $e->getMessage()));
}
