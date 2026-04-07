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
    $pdoOptions = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];

    // Keep serverless cold starts from hanging too long on connect.
    if (defined('PDO::MYSQL_ATTR_CONNECT_TIMEOUT')) {
        $pdoOptions[PDO::MYSQL_ATTR_CONNECT_TIMEOUT] = (int)(getenv('DB_CONNECT_TIMEOUT') ?: 5);
    }

    // Some managed MySQL providers require SSL. If you set DB_SSL=require, we will negotiate SSL.
    // Note: verification is disabled unless you also provide DB_SSL_CA with a CA bundle path.
    $dbSsl = strtolower((string)(getenv('DB_SSL') ?: ''));
    if ($dbSsl === 'require' && defined('PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT')) {
        $pdoOptions[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = false;
        if (defined('PDO::MYSQL_ATTR_SSL_CA')) {
            $caPath = (string)(getenv('DB_SSL_CA') ?: '');
            if ($caPath !== '') {
                $pdoOptions[PDO::MYSQL_ATTR_SSL_CA] = $caPath;
            }
        }
    }

    $maxAttempts = $isVercel ? (int)(getenv('DB_CONNECT_ATTEMPTS') ?: 3) : 1;
    $lastError = null;

    for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {
        try {
            $pdo = new PDO($dsn, $username, $password, $pdoOptions);
            $lastError = null;
            break;
        } catch (PDOException $e) {
            $lastError = $e;
            error_log("Database connection failed (attempt {$attempt}/{$maxAttempts}): " . $e->getMessage());

            // Retry only for transient connection-type failures.
            $msg = strtolower($e->getMessage());
            $transient = str_contains($msg, 'server has gone away')
                || str_contains($msg, 'lost connection')
                || str_contains($msg, 'connection refused')
                || str_contains($msg, 'timed out')
                || str_contains($msg, 'can\'t connect');

            if ($attempt < $maxAttempts && $transient) {
                usleep(200000 * $attempt);
                continue;
            }

            throw $e;
        }
    }

    if ($lastError instanceof PDOException) {
        throw $lastError;
    }
} catch (PDOException $e) {
    // Log detailed error server-side (Vercel Functions logs), but keep the UI message generic.
    error_log('Database connection failed: ' . $e->getMessage());

    $isProd = $isVercel || (getenv('APP_ENV') === 'production');
    die($isProd ? 'Database connection failed.' : ('Database connection failed: ' . $e->getMessage()));
}
