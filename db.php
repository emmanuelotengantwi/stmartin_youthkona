<?php
/**
 * DB credentials are sourced from environment variables in production (Vercel).
 * Local fallback values keep XAMPP development working.
 */
$host = getenv('DB_HOST') ?: '127.0.0.1';
$port = (int)(getenv('DB_PORT') ?: 3306);
$dbname = getenv('DB_NAME') ?: 'stmartin_youthkona';
$username = getenv('DB_USER') ?: 'root';
$password = getenv('DB_PASS') ?: '';

$dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";

try {
    $pdo = new PDO($dsn, $username, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $e) {
    $isProd = (getenv('VERCEL') === '1') || (getenv('APP_ENV') === 'production');
    $message = $isProd ? 'Database connection failed.' : ('Database connection failed: ' . $e->getMessage());
    die($message);
}
