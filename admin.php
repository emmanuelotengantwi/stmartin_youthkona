<?php
session_start();

require_once __DIR__ . '/db.php';

function defaultNewAdminPassword(): string
{
    return getenv('DEFAULT_NEW_ADMIN_PASSWORD') ?: 'ChangeMeNow!2026';
}

function adminRecoveryCode(): string
{
    return getenv('ADMIN_RECOVERY_CODE') ?: '';
}

function clientIp(): string
{
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
    if (str_contains($ip, ',')) {
        $parts = explode(',', $ip);
        return trim($parts[0]);
    }

    return trim($ip);
}

function auditLog(PDO $pdo, ?int $adminId, string $eventType, string $details = ''): void
{
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO audit_logs (admin_id, event_type, event_details, ip_address, user_agent)
             VALUES (:admin_id, :event_type, :event_details, :ip_address, :user_agent)'
        );

        $stmt->execute([
            ':admin_id' => $adminId,
            ':event_type' => $eventType,
            ':event_details' => substr($details, 0, 255),
            ':ip_address' => substr(clientIp(), 0, 45),
            ':user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 255),
        ]);
    } catch (Throwable $e) {
        // Keep app usable even if logging fails.
    }
}

function normalizeDobToDayMonth(string $rawDob): string
{
    $rawDob = trim($rawDob);
    if ($rawDob === '') {
        return '';
    }

    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $rawDob)) {
        $dobObj = DateTime::createFromFormat('Y-m-d', $rawDob);
        if ($dobObj && $dobObj->format('Y-m-d') === $rawDob) {
            return $dobObj->format('d/m');
        }
    }

    return $rawDob;
}

function dateOfBirthColumnIsDate(PDO $pdo): bool
{
    static $isDate = null;
    if ($isDate !== null) {
        return $isDate;
    }

    try {
        $stmt = $pdo->query(
            "SELECT DATA_TYPE
             FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = 'youth'
               AND COLUMN_NAME = 'date_of_birth'
             LIMIT 1"
        );
        $dataType = strtolower((string)$stmt->fetchColumn());
        $isDate = ($dataType === 'date');
    } catch (Throwable $e) {
        $isDate = false;
    }

    return $isDate;
}

function toDatabaseDob(PDO $pdo, string $dayMonthDob): string
{
    if (!dateOfBirthColumnIsDate($pdo)) {
        return $dayMonthDob;
    }

    [$day, $month] = array_map('intval', explode('/', $dayMonthDob));
    return sprintf('2000-%02d-%02d', $month, $day);
}

function splitDayMonth(string $dayMonth): array
{
    if (!preg_match('/^(0[1-9]|[12][0-9]|3[01])\/(0[1-9]|1[0-2])$/', $dayMonth, $matches)) {
        return ['', ''];
    }

    return [$matches[1], $matches[2]];
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return (string)$_SESSION['csrf_token'];
}

function isValidCsrfToken(string $token): bool
{
    return isset($_SESSION['csrf_token']) && hash_equals((string)$_SESSION['csrf_token'], $token);
}

function isLoginLocked(PDO $pdo, string $username, string $ipAddress): bool
{
    $stmt = $pdo->prepare(
        'SELECT locked_until
         FROM admin_login_attempts
         WHERE username = :username AND ip_address = :ip_address
         LIMIT 1'
    );
    $stmt->execute([
        ':username' => $username,
        ':ip_address' => $ipAddress,
    ]);

    $lockedUntil = $stmt->fetchColumn();
    if (!$lockedUntil) {
        return false;
    }

    return strtotime((string)$lockedUntil) > time();
}

function registerFailedLogin(PDO $pdo, string $username, string $ipAddress): void
{
    $pdo->prepare(
        'UPDATE admin_login_attempts
         SET failed_attempts = 0, locked_until = NULL
         WHERE username = :username
           AND ip_address = :ip_address
           AND locked_until IS NOT NULL
           AND locked_until < NOW()'
    )->execute([
        ':username' => $username,
        ':ip_address' => $ipAddress,
    ]);

    $pdo->prepare(
        'INSERT INTO admin_login_attempts (username, ip_address, failed_attempts, locked_until, last_failed_at)
         VALUES (:username, :ip_address, 1, NULL, NOW())
         ON DUPLICATE KEY UPDATE
           failed_attempts = failed_attempts + 1,
           last_failed_at = NOW(),
           locked_until = CASE
               WHEN failed_attempts + 1 >= 5 THEN DATE_ADD(NOW(), INTERVAL 15 MINUTE)
               ELSE locked_until
           END'
    )->execute([
        ':username' => $username,
        ':ip_address' => $ipAddress,
    ]);
}

function clearLoginFailures(PDO $pdo, string $username, string $ipAddress): void
{
    $pdo->prepare(
        'DELETE FROM admin_login_attempts
         WHERE username = :username AND ip_address = :ip_address'
    )->execute([
        ':username' => $username,
        ':ip_address' => $ipAddress,
    ]);
}

function passwordPolicyError(string $password, string $confirmPassword): string
{
    if ($password === '' || $confirmPassword === '') {
        return 'Password and confirmation are required.';
    }
    if (strlen($password) < 7) {
        return 'Password must be more than 6 characters.';
    }
    if (
        !preg_match('/[A-Z]/', $password) ||
        !preg_match('/[a-z]/', $password) ||
        !preg_match('/[0-9]/', $password) ||
        !preg_match('/[^A-Za-z0-9]/', $password)
    ) {
        return 'Password must include uppercase, lowercase, number, and symbol.';
    }
    if ($password !== $confirmPassword) {
        return 'Password confirmation does not match.';
    }

    return '';
}

$pdo->exec(
    'CREATE TABLE IF NOT EXISTS admins (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      full_name VARCHAR(120) NOT NULL,
      username VARCHAR(80) NOT NULL UNIQUE,
      role ENUM("super_admin","viewer") NOT NULL DEFAULT "super_admin",
      must_change_password TINYINT(1) NOT NULL DEFAULT 0,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
);

try {
    $pdo->exec('ALTER TABLE admins ADD COLUMN role ENUM("super_admin","viewer") NOT NULL DEFAULT "super_admin" AFTER username');
} catch (Throwable $e) {
    // Column may already exist.
}

try {
    $pdo->exec('ALTER TABLE admins ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 0 AFTER role');
} catch (Throwable $e) {
    // Column may already exist.
}

$pdo->exec(
    'CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      admin_id INT UNSIGNED NULL,
      event_type VARCHAR(80) NOT NULL,
      event_details VARCHAR(255) NOT NULL DEFAULT "",
      ip_address VARCHAR(45) NOT NULL,
      user_agent VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_audit_created_at (created_at),
      INDEX idx_audit_admin_id (admin_id),
      CONSTRAINT fk_audit_admin FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
);

$pdo->exec(
    'CREATE TABLE IF NOT EXISTS admin_login_attempts (
      username VARCHAR(80) NOT NULL,
      ip_address VARCHAR(45) NOT NULL,
      failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
      locked_until DATETIME NULL,
      last_failed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (username, ip_address),
      INDEX idx_locked_until (locked_until)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
);

try {
    $pdo->exec("UPDATE admins SET role = 'super_admin' WHERE role IS NULL OR role = ''");
} catch (Throwable $e) {
    // Ignore if role column is unavailable.
}

$adminCount = (int)$pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn();
$isAdmin = isset($_SESSION['admin_id']) && is_numeric($_SESSION['admin_id']);
$currentAdminId = $isAdmin ? (int)$_SESSION['admin_id'] : null;
$currentAdminName = $isAdmin ? (string)($_SESSION['admin_name'] ?? 'Admin') : 'Admin';

if ($isAdmin && !isset($_SESSION['admin_role'])) {
    try {
        $roleStmt = $pdo->prepare('SELECT role, must_change_password FROM admins WHERE id = :id LIMIT 1');
        $roleStmt->execute([':id' => $currentAdminId]);
        $adminInfo = $roleStmt->fetch();
        $_SESSION['admin_role'] = (string)($adminInfo['role'] ?? 'super_admin');
        $_SESSION['must_change_password'] = ((int)($adminInfo['must_change_password'] ?? 0) === 1);
    } catch (Throwable $e) {
        $_SESSION['admin_role'] = 'super_admin';
        $_SESSION['must_change_password'] = false;
    }
}

$currentAdminRole = $isAdmin ? (string)($_SESSION['admin_role'] ?? 'viewer') : 'viewer';
$isSuperAdmin = $isAdmin && $currentAdminRole === 'super_admin';
$mustChangePassword = $isAdmin ? (bool)($_SESSION['must_change_password'] ?? false) : false;

$loginError = '';
$setupError = '';
$setupSuccess = '';
$memberError = '';
$memberSuccess = '';
$passwordError = '';
$passwordSuccess = '';
$searchTerm = trim($_GET['q'] ?? '');
$editMember = null;
$postAction = (string)($_POST['action'] ?? '');
$csrfValid = true;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfValid = isValidCsrfToken((string)($_POST['csrf_token'] ?? ''));
    if (!$csrfValid) {
        if ($postAction === 'log_print') {
            http_response_code(403);
            echo 'forbidden';
            exit;
        }

        if (in_array($postAction, ['login'], true)) {
            $loginError = 'Session expired. Please refresh and try again.';
        } elseif (in_array($postAction, ['register_admin'], true)) {
            $setupError = 'Session expired. Please refresh and try again.';
        } elseif (in_array($postAction, ['change_password'], true)) {
            $passwordError = 'Session expired. Please refresh and try again.';
        } else {
            $memberError = 'Session expired. Please refresh and try again.';
        }
    }
}

$allowedStatuses = ['Single', 'Married', 'Separated', 'Divorced'];
$allowedGenders = ['Male', 'Female'];
$allowedSocietalGroups = [
    'No Society',
    'KLBS',
    'LECTORS',
    'USHERS',
    'DOMINIC CHOIR',
    'CHURCH BAND',
    'ST.THERESA',
    'CHRISTIAN SONS & DAUGHTERS',
    'MEDIA TEAM',
    'CHARISMATIC RENEWAL',
    'COSRA',
    'LEGION OF MARY',
    'CYO',
];

if (isset($_GET['logout']) && $isAdmin) {
    auditLog($pdo, $currentAdminId, 'admin_logout', 'Admin logged out');
    session_unset();
    session_destroy();
    header('Location: admin.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $csrfValid && $postAction === 'log_print') {
    if (!$isAdmin) {
        auditLog($pdo, null, 'unauthorized_print_attempt', 'Unauthenticated print attempt');
        http_response_code(403);
        echo 'forbidden';
        exit;
    }

    $printTarget = $_POST['target'] ?? '';
    if ($printTarget === 'records') {
        auditLog($pdo, $currentAdminId, 'print_records', 'Admin printed youth records');
    } elseif ($printTarget === 'audit') {
        auditLog($pdo, $currentAdminId, 'print_audit_logs', 'Admin printed audit log trail');
    } else {
        auditLog($pdo, $currentAdminId, 'print_unknown', 'Admin requested unknown print target');
    }
    echo 'ok';
    exit;
}

if (($_GET['action'] ?? '') === 'youth_stats') {
    header('Content-Type: application/json; charset=UTF-8');

    if (!$isAdmin) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'forbidden']);
        exit;
    }

    $totalYouth = (int)$pdo->query('SELECT COUNT(*) FROM youth')->fetchColumn();
    echo json_encode(['ok' => true, 'total_youth' => $totalYouth]);
    exit;
}

if (($_GET['action'] ?? '') === 'export_members_csv') {
    if (!$isAdmin) {
        http_response_code(403);
        echo 'forbidden';
        exit;
    }

    $q = trim((string)($_GET['q'] ?? ''));
    if ($q !== '') {
        $stmt = $pdo->prepare(
            'SELECT * FROM youth
             WHERE name LIKE :q
                OR contact LIKE :q
                OR marital_status LIKE :q
                OR gender LIKE :q
                OR profession LIKE :q
                OR area_of_interest LIKE :q
                OR societal_groups LIKE :q
             ORDER BY id DESC'
        );
        $stmt->execute([':q' => '%' . $q . '%']);
        $rows = $stmt->fetchAll();
    } else {
        $rows = $pdo->query('SELECT * FROM youth ORDER BY id DESC')->fetchAll();
    }

    auditLog($pdo, $currentAdminId, 'export_members_csv', 'Exported members CSV');
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="youth-members.csv"');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['ID', 'Name', 'Contact', 'Date of Birth', 'Gender', 'Marital Status', 'Profession', 'Area of Interest', 'Societal Groups', 'Created']);
    foreach ($rows as $row) {
        fputcsv($out, [
            (int)$row['id'],
            (string)$row['name'],
            (string)$row['contact'],
            normalizeDobToDayMonth((string)$row['date_of_birth']),
            (string)$row['gender'],
            (string)$row['marital_status'],
            (string)$row['profession'],
            (string)$row['area_of_interest'],
            (string)$row['societal_groups'],
            (string)$row['created_at'],
        ]);
    }
    fclose($out);
    exit;
}

if (($_GET['action'] ?? '') === 'export_audit_csv') {
    if (!$isAdmin) {
        http_response_code(403);
        echo 'forbidden';
        exit;
    }

    $rows = $pdo->query(
        'SELECT al.id, al.created_at, COALESCE(a.username, "N/A") AS username, al.event_type, al.event_details, al.ip_address
         FROM audit_logs al
         LEFT JOIN admins a ON a.id = al.admin_id
         ORDER BY al.id DESC'
    )->fetchAll();

    auditLog($pdo, $currentAdminId, 'export_audit_csv', 'Exported audit CSV');
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="audit-log-trail.csv"');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['Log ID', 'Time', 'Admin', 'Event', 'Details', 'IP']);
    foreach ($rows as $row) {
        fputcsv($out, [
            (int)$row['id'],
            (string)$row['created_at'],
            (string)$row['username'],
            (string)$row['event_type'],
            (string)$row['event_details'],
            (string)$row['ip_address'],
        ]);
    }
    fclose($out);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $csrfValid && $postAction === 'change_password') {
    if (!$isAdmin) {
        $passwordError = 'You must be logged in.';
    } else {
        $newPassword = (string)($_POST['new_password'] ?? '');
        $confirmPassword = (string)($_POST['confirm_password'] ?? '');
        $policyError = passwordPolicyError($newPassword, $confirmPassword);

        if ($policyError !== '') {
            $passwordError = $policyError;
        } else {
            $stmt = $pdo->prepare(
                'UPDATE admins
                 SET password_hash = :password_hash, must_change_password = 0
                 WHERE id = :id'
            );
            $stmt->execute([
                ':password_hash' => password_hash($newPassword, PASSWORD_DEFAULT),
                ':id' => $currentAdminId,
            ]);

            $_SESSION['must_change_password'] = false;
            $mustChangePassword = false;
            $passwordSuccess = 'Password changed successfully.';
            auditLog($pdo, $currentAdminId, 'admin_password_changed', 'Admin changed password');
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $csrfValid && $postAction === 'register_admin') {
    $canRegister = ($adminCount === 0) || $isSuperAdmin;
    $isRecoveryRegistration = false;
    $recoveryCode = trim((string)($_POST['recovery_code'] ?? ''));

    if (!$canRegister && !$isAdmin && $adminCount > 0) {
        $expectedRecoveryCode = adminRecoveryCode();
        if ($expectedRecoveryCode !== '' && hash_equals($expectedRecoveryCode, $recoveryCode)) {
            $canRegister = true;
            $isRecoveryRegistration = true;
        }
    }

    if (!$canRegister) {
        auditLog($pdo, null, 'unauthorized_register_attempt', 'Tried to register admin without access');
        $setupError = 'You are not allowed to create an admin account. Use login or provide a valid recovery code.';
    } else {
        $fullName = trim($_POST['full_name'] ?? '');
        $username = strtolower(trim($_POST['username'] ?? ''));
        $role = trim((string)($_POST['role'] ?? 'viewer'));
        if (!in_array($role, ['super_admin', 'viewer'], true)) {
            $role = 'viewer';
        }
        if ($adminCount === 0) {
            $role = 'super_admin';
        }
        if ($isRecoveryRegistration) {
            $role = 'super_admin';
        }

        $password = (string)($_POST['password'] ?? '');
        $confirmPassword = (string)($_POST['confirm_password'] ?? '');
        $newAdminMustChangePassword = 0;

        if ($fullName === '' || $username === '') {
            $setupError = 'Full name and username are required.';
        } elseif (!preg_match('/^[a-z0-9_.-]{3,40}$/', $username)) {
            $setupError = 'Username must be 3-40 chars and contain only letters, numbers, ., _, -';
        }

        if ($setupError === '' && ($adminCount === 0 || $isRecoveryRegistration)) {
            $policyError = passwordPolicyError($password, $confirmPassword);
            if ($policyError !== '') {
                $setupError = $policyError;
            }
        }

        if ($setupError === '' && $adminCount > 0 && !$isRecoveryRegistration) {
            $password = defaultNewAdminPassword();
            $confirmPassword = defaultNewAdminPassword();
            $newAdminMustChangePassword = 1;
        }

        if ($setupError === '') {
            $existingAdmin = $pdo->prepare('SELECT id FROM admins WHERE username = :username LIMIT 1');
            $existingAdmin->execute([':username' => $username]);

            if ($existingAdmin->fetch()) {
                $setupError = 'Username already exists.';
            } else {
                $stmt = $pdo->prepare(
                    'INSERT INTO admins (full_name, username, role, must_change_password, password_hash)
                     VALUES (:full_name, :username, :role, :must_change_password, :password_hash)'
                );

                $stmt->execute([
                    ':full_name' => $fullName,
                    ':username' => $username,
                    ':role' => $role,
                    ':must_change_password' => $newAdminMustChangePassword,
                    ':password_hash' => password_hash($password, PASSWORD_DEFAULT),
                ]);

                $newAdminId = (int)$pdo->lastInsertId();
                auditLog(
                    $pdo,
                    $isAdmin ? $currentAdminId : $newAdminId,
                    'admin_account_created',
                    'Created admin account: ' . $username . ' (' . $role . ')'
                );

                if ($adminCount === 0 || $isRecoveryRegistration) {
                    $_SESSION['admin_id'] = $newAdminId;
                    $_SESSION['admin_name'] = $fullName;
                    $_SESSION['admin_role'] = $role;
                    $_SESSION['must_change_password'] = false;
                    $isAdmin = true;
                    $currentAdminId = $newAdminId;
                    $currentAdminName = $fullName;
                    $currentAdminRole = $role;
                    $isSuperAdmin = ($role === 'super_admin');
                    $mustChangePassword = false;
                    $adminCount = 1;
                    $setupSuccess = $isRecoveryRegistration
                        ? 'Recovery admin account created and logged in.'
                        : 'Admin account created and logged in.';
                } else {
                    $setupSuccess = 'New admin account created. Default password: ' . defaultNewAdminPassword() . ' (user must change it at first login).';
                }
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $csrfValid && $postAction === 'login' && !$isAdmin) {
    $username = strtolower(trim($_POST['username'] ?? ''));
    $password = $_POST['password'] ?? '';
    $ipAddress = clientIp();

    if ($username === '' || $password === '') {
        $loginError = 'Username and password are required.';
    } elseif (isLoginLocked($pdo, $username, $ipAddress)) {
        $loginError = 'Too many failed attempts. Try again in 15 minutes.';
        auditLog($pdo, null, 'admin_login_locked', 'Blocked login for username: ' . $username);
    } else {
        $stmt = $pdo->prepare('SELECT id, full_name, username, role, must_change_password, password_hash FROM admins WHERE username = :username LIMIT 1');
        $stmt->execute([':username' => $username]);
        $adminRow = $stmt->fetch();

        if (!$adminRow || !password_verify($password, (string)$adminRow['password_hash'])) {
            $loginError = 'Invalid username or password.';
            registerFailedLogin($pdo, $username, $ipAddress);
            auditLog($pdo, null, 'admin_login_failed', 'Failed login for username: ' . $username);
        } else {
            clearLoginFailures($pdo, $username, $ipAddress);
            $_SESSION['admin_id'] = (int)$adminRow['id'];
            $_SESSION['admin_name'] = (string)$adminRow['full_name'];
            $_SESSION['admin_role'] = (string)$adminRow['role'];
            $_SESSION['must_change_password'] = ((int)$adminRow['must_change_password'] === 1);
            session_regenerate_id(true);

            auditLog($pdo, (int)$adminRow['id'], 'admin_login_success', 'Admin logged in');
            header('Location: admin.php');
            exit;
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $csrfValid && $postAction === 'update_member') {
    if (!$isSuperAdmin) {
        auditLog($pdo, null, 'unauthorized_member_update_attempt', 'Unauthenticated member update attempt');
        $memberError = 'Only super admins can edit member details.';
    } else {
        $memberId = (int)($_POST['member_id'] ?? 0);
        $name = trim($_POST['name'] ?? '');
        $contact = trim($_POST['contact'] ?? '');
        $dateOfBirth = normalizeDobToDayMonth((string)($_POST['date_of_birth'] ?? ''));
        $dobDay = trim((string)($_POST['dob_day'] ?? ''));
        $dobMonth = trim((string)($_POST['dob_month'] ?? ''));
        if ($dateOfBirth === '' && $dobDay !== '' && $dobMonth !== '') {
            $dateOfBirth = sprintf('%02d/%02d', (int)$dobDay, (int)$dobMonth);
        }
        $gender = trim($_POST['gender'] ?? '');
        $maritalStatus = trim($_POST['marital_status'] ?? '');
        $profession = trim($_POST['profession'] ?? '');
        $areaOfInterest = trim($_POST['area_of_interest'] ?? '');
        $societalGroups = $_POST['societal_groups'] ?? [];
        $searchTerm = trim($_POST['q'] ?? $searchTerm);

        if (!is_array($societalGroups)) {
            $societalGroups = [];
        }
        $societalGroups = array_values(array_unique(array_filter(array_map('trim', $societalGroups), static function ($value) {
            return $value !== '';
        })));

        if ($memberId <= 0) {
            $memberError = 'Invalid member selected.';
        } elseif ($name === '' || $contact === '' || $dateOfBirth === '' || $profession === '' || $areaOfInterest === '') {
            $memberError = 'All member fields are required.';
        } elseif (!in_array($gender, $allowedGenders, true)) {
            $memberError = 'Please select a valid gender.';
        } elseif (!in_array($maritalStatus, $allowedStatuses, true)) {
            $memberError = 'Please select a valid marital status.';
        } elseif (!preg_match('/^(0[1-9]|[12][0-9]|3[01])\/(0[1-9]|1[0-2])$/', $dateOfBirth)) {
            $memberError = 'Date of birth must be in DD/MM format.';
        } else {
            [$day, $month] = array_map('intval', explode('/', $dateOfBirth));
            if (!checkdate($month, $day, 2000)) {
                $memberError = 'Please provide a valid date of birth.';
            }
        }

        if ($memberError === '') {
            if (!$societalGroups) {
                $memberError = 'Please select at least one societal group.';
            } elseif (in_array('No Society', $societalGroups, true) && count($societalGroups) > 1) {
                $memberError = 'If "No Society" is selected, no other societal group can be selected.';
            } else {
                foreach ($societalGroups as $group) {
                    if (!in_array($group, $allowedSocietalGroups, true)) {
                        $memberError = 'Please select valid societal group values.';
                        break;
                    }
                }
            }
        }

        if ($memberError === '') {
            $existingStmt = $pdo->prepare('SELECT id FROM youth WHERE LOWER(name) = LOWER(:name) AND id <> :id LIMIT 1');
            $existingStmt->execute([
                ':name' => $name,
                ':id' => $memberId,
            ]);
            if ($existingStmt->fetch()) {
                $memberError = 'Another member already exists with this name.';
            }
        }

        if ($memberError === '') {
            $updateStmt = $pdo->prepare(
                'UPDATE youth
                 SET name = :name,
                     contact = :contact,
                     date_of_birth = :date_of_birth,
                     gender = :gender,
                     marital_status = :marital_status,
                     profession = :profession,
                     area_of_interest = :area_of_interest,
                     societal_groups = :societal_groups
                 WHERE id = :id'
            );
            $updateStmt->execute([
                ':name' => $name,
                ':contact' => $contact,
                ':date_of_birth' => toDatabaseDob($pdo, $dateOfBirth),
                ':gender' => $gender,
                ':marital_status' => $maritalStatus,
                ':profession' => $profession,
                ':area_of_interest' => $areaOfInterest,
                ':societal_groups' => implode(', ', $societalGroups),
                ':id' => $memberId,
            ]);

            auditLog($pdo, $currentAdminId, 'member_updated', 'Updated member ID: ' . $memberId);
            $memberSuccess = 'Member details updated successfully.';
            $_GET['edit_id'] = (string)$memberId;
        }
    }
}

$records = [];
$auditLogs = [];
$totalYouthCount = 0;
$editId = isset($_GET['edit_id']) ? (int)$_GET['edit_id'] : 0;
if ($editId <= 0 && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'update_member') {
    $editId = (int)($_POST['member_id'] ?? 0);
}

if ($isAdmin) {
    $totalYouthCount = (int)$pdo->query('SELECT COUNT(*) FROM youth')->fetchColumn();
    if ($searchTerm !== '') {
        $searchStmt = $pdo->prepare(
            'SELECT * FROM youth
             WHERE name LIKE :q
                OR contact LIKE :q
                OR marital_status LIKE :q
                OR gender LIKE :q
                OR profession LIKE :q
                OR area_of_interest LIKE :q
                OR societal_groups LIKE :q
             ORDER BY id DESC'
        );
        $searchStmt->execute([':q' => '%' . $searchTerm . '%']);
        $records = $searchStmt->fetchAll();
    } else {
        $records = $pdo->query('SELECT * FROM youth ORDER BY id DESC')->fetchAll();
    }

    if ($editId > 0) {
        $editStmt = $pdo->prepare('SELECT * FROM youth WHERE id = :id LIMIT 1');
        $editStmt->execute([':id' => $editId]);
        $editMember = $editStmt->fetch() ?: null;
    }

    $logStmt = $pdo->query(
        'SELECT al.id, al.event_type, al.event_details, al.ip_address, al.created_at, a.username
         FROM audit_logs al
         LEFT JOIN admins a ON a.id = al.admin_id
         ORDER BY al.id DESC
         LIMIT 150'
    );
    $auditLogs = $logStmt->fetchAll();

    if (!isset($_SESSION['dashboard_view_logged'])) {
        auditLog($pdo, $currentAdminId, 'view_dashboard', 'Admin opened dashboard');
        $_SESSION['dashboard_view_logged'] = true;
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ST. MARTIN DE-PORRES CATHOLIC CHURCH (YOUTH DATABASE) - Admin</title>
  <style>
    :root {
      --bg-1: #fdfaf1;
      --bg-2: #ece9df;
      --ink: #1f2937;
      --brand: #8b1e3f;
      --brand-dark: #5f152b;
      --gold: #c89a3d;
      --line: #e3ddcf;
      --card: #ffffff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      font-family: "Book Antiqua", "Palatino Linotype", Georgia, serif;
      background:
        radial-gradient(circle at 10% 10%, #fff8d8 0, transparent 35%),
        radial-gradient(circle at 90% 90%, #f8e3c2 0, transparent 28%),
        linear-gradient(140deg, var(--bg-1), var(--bg-2));
      min-height: 100vh;
      animation: fadeIn .6s ease-out;
      transition: opacity .45s ease;
    }
    .page-preload .container { opacity: 0; transform: translateY(8px); pointer-events: none; }
    .container { transition: opacity .45s ease, transform .45s ease; }
    .intro-loader {
      position: fixed;
      inset: 0;
      z-index: 1300;
      display: grid;
      place-items: center;
      overflow: hidden;
      background:
        radial-gradient(circle at 20% 20%, rgba(255, 246, 197, .5), transparent 44%),
        radial-gradient(circle at 80% 80%, rgba(232, 178, 147, .3), transparent 40%),
        linear-gradient(140deg, #f6f0df, #efe5cf 50%, #e8d8ba);
      transition: opacity .55s ease, visibility .55s ease;
    }
    .intro-loader.is-leaving {
      opacity: 0;
      visibility: hidden;
    }
    .intro-glow {
      position: absolute;
      width: 42vmax;
      height: 42vmax;
      border-radius: 50%;
      filter: blur(26px);
      opacity: .34;
      animation: floatGlow 4.8s ease-in-out infinite alternate;
    }
    .intro-glow-a { background: #d3ab64; top: -12vmax; left: -8vmax; }
    .intro-glow-b { background: #7f1435; bottom: -14vmax; right: -10vmax; animation-delay: 1s; }
    .intro-core {
      position: relative;
      width: min(620px, 92vw);
      border: 1px solid rgba(95, 21, 43, .18);
      border-radius: 26px;
      padding: 28px 20px 24px;
      background: rgba(255, 255, 255, .72);
      backdrop-filter: blur(6px);
      text-align: center;
      box-shadow: 0 14px 32px rgba(77, 28, 15, .22);
      animation: liftIn .8s ease-out;
    }
    .intro-logo-shell {
      width: 108px;
      height: 108px;
      margin: 0 auto 14px;
      border-radius: 50%;
      overflow: hidden;
      display: grid;
      place-items: center;
      border: 3px solid #c89a3d;
      box-shadow: 0 0 0 9px rgba(200, 154, 61, .15), 0 0 36px rgba(96, 14, 41, .26);
      background: #fff8e8;
      color: #5f152b;
      font-size: 31px;
      font-weight: 700;
      animation: pulseHalo 1.7s ease-in-out infinite;
    }
    .intro-logo-shell img { width: 100%; height: 100%; object-fit: cover; }
    .intro-core h2 {
      margin: 0;
      color: #5f152b;
      letter-spacing: .8px;
      font-size: clamp(20px, 2.7vw, 34px);
      line-height: 1.2;
      text-transform: uppercase;
    }
    .intro-core p {
      margin: 8px 0 0;
      color: #7f1435;
      font-size: clamp(14px, 2vw, 19px);
      letter-spacing: 1.6px;
      text-transform: uppercase;
      font-weight: 700;
    }
    .intro-line {
      width: min(320px, 72%);
      margin: 16px auto 0;
      height: 5px;
      border-radius: 999px;
      background: linear-gradient(90deg, transparent, #c89a3d, #8b1e3f, transparent);
      animation: sweepLine 1.4s ease-in-out infinite;
    }
    .container { width: 100%; max-width: none; margin: 0; padding: 0; }
    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 0;
      box-shadow: 0 12px 30px rgba(95, 21, 43, 0.12);
      padding: 22px 24px;
      overflow: hidden;
      margin-bottom: 0;
    }
    .brand {
      display: grid;
      grid-template-columns: 84px 1fr;
      gap: 16px;
      align-items: center;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--line);
      padding-bottom: 16px;
    }
    .logo-wrap {
      width: 84px;
      height: 84px;
      border-radius: 50%;
      border: 2px solid var(--gold);
      background: #fff8e8;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
      font-weight: 700;
      color: var(--brand-dark);
      letter-spacing: .5px;
    }
    .logo-wrap img { width: 100%; height: 100%; object-fit: cover; display: block; }
    .church-name {
      margin: 0;
      font-size: clamp(19px, 2.6vw, 28px);
      line-height: 1.2;
      color: var(--brand-dark);
    }
    .subtitle { margin: 6px 0 0; color: #5b6473; font-size: 14px; }
    .welcome { margin: 0 0 12px; color: #4b5563; }
    .section-title {
      margin: 0 0 10px;
      color: var(--brand-dark);
      font-size: 22px;
    }
    .section-note {
      margin: 0 0 14px;
      color: #5b6473;
      font-size: 14px;
    }
    .auth-wrap {
      max-width: 860px;
      border: 1px solid #ece5d6;
      border-radius: 14px;
      background: #fffdfa;
      padding: 16px;
    }
    .auth-wrap.compact {
      max-width: 460px;
    }
    .field-label {
      font-size: 13px;
      letter-spacing: .5px;
      text-transform: uppercase;
      font-weight: 700;
      margin-bottom: 6px;
      display: block;
      color: #4a5568;
    }
    input, select {
      width: 100%;
      max-width: 360px;
      padding: 12px;
      border: 1px solid #d9d4c7;
      border-radius: 10px;
      background: #fffefb;
      font: inherit;
    }
    input:focus, select:focus {
      outline: none;
      border-color: var(--gold);
      box-shadow: 0 0 0 3px rgba(200, 154, 61, 0.18);
    }
    .btn {
      border: 0;
      border-radius: 10px;
      padding: 11px 15px;
      font: inherit;
      font-weight: 700;
      color: #fff;
      cursor: pointer;
      text-decoration: none;
      display: inline-block;
      transition: transform .15s ease, box-shadow .15s ease;
    }
    .btn:hover { transform: translateY(-1px); box-shadow: 0 8px 14px rgba(95, 21, 43, 0.25); }
    .btn-main { background: linear-gradient(135deg, var(--brand), var(--brand-dark)); }
    .btn-muted { background: #0f766e; }
    .btn-gold { background: #8b6b19; }
    .btn-danger { background: #b91c1c; }
    .alert { padding: 11px 12px; border-radius: 10px; margin: 12px 0; }
    .alert.error { background: #fee7e8; color: #7f1d1d; border: 1px solid #fecdd3; }
    .alert.success { background: #e8f8ee; color: #166534; border: 1px solid #bbf7d0; }
    .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
    .search-form {
      display: flex;
      gap: 10px;
      align-items: center;
      margin: 0 0 14px;
      flex-wrap: wrap;
    }
    .search-form input[type="text"] {
      max-width: 420px;
    }
    .btn-light {
      background: #6b7280;
    }
    .table-action-link {
      display: inline-block;
      background: #8b1e3f;
      color: #fff;
      text-decoration: none;
      padding: 6px 10px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 700;
    }
    .table-action-link:hover {
      background: #5f152b;
    }
    table { width: 100%; border-collapse: collapse; min-width: 1120px; }
    th, td { text-align: left; border-bottom: 1px solid #ebe5d8; padding: 11px 8px; font-size: 14px; }
    th { background: #faf7ef; color: #374151; }
    .table-shell { overflow-x: auto; border: 1px solid #ebe5d8; border-radius: 12px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 10px;
      max-width: 740px;
      margin-bottom: 10px;
    }
    .grid .full { grid-column: 1 / -1; }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(220px, 1fr));
      gap: 12px;
      align-items: end;
    }
    .form-grid .full { grid-column: 1 / -1; }
    .form-actions {
      margin-top: 4px;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }
    .password-hint {
      margin: 0;
      font-size: 13px;
      color: #6b7280;
      background: #f7f3e8;
      border: 1px dashed #d8ccb0;
      border-radius: 10px;
      padding: 10px 12px;
    }
    .stats-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 12px;
      margin: 8px 0 14px;
    }
    .stat-card {
      border: 1px solid #e8dfcb;
      border-radius: 14px;
      padding: 14px;
      background: linear-gradient(140deg, #fffdfa, #f7f1e4);
      box-shadow: 0 8px 18px rgba(95, 21, 43, 0.08);
    }
    .stat-title {
      margin: 0 0 4px;
      color: #5b6473;
      font-size: 13px;
      letter-spacing: .4px;
      text-transform: uppercase;
      font-weight: 700;
    }
    .stat-value {
      margin: 0;
      color: #5f152b;
      font-size: clamp(30px, 5vw, 40px);
      line-height: 1;
      font-weight: 700;
    }
    .edit-card {
      margin-top: 16px;
      border: 1px solid #e8dfcb;
      border-radius: 14px;
      padding: 14px;
      background: linear-gradient(140deg, #fffdfa, #f7f1e4);
    }
    .checkbox-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 8px 12px;
      margin-top: 6px;
    }
    .checkbox-grid label {
      display: flex;
      align-items: center;
      gap: 8px;
      text-transform: none;
      letter-spacing: 0;
      font-size: 14px;
      margin: 0;
      font-weight: 600;
    }
    .checkbox-grid input[type="checkbox"] {
      width: auto;
      max-width: none;
      margin: 0;
    }
    .stat-note {
      margin: 8px 0 0;
      color: #6b7280;
      font-size: 12px;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulseHalo {
      0% { box-shadow: 0 0 0 9px rgba(200, 154, 61, .13), 0 0 22px rgba(96, 14, 41, .18); }
      100% { box-shadow: 0 0 0 14px rgba(200, 154, 61, .06), 0 0 36px rgba(96, 14, 41, .26); }
    }
    @keyframes sweepLine {
      0% { transform: scaleX(.28); opacity: .5; }
      50% { transform: scaleX(1); opacity: 1; }
      100% { transform: scaleX(.28); opacity: .5; }
    }
    @keyframes liftIn {
      from { opacity: 0; transform: translateY(12px) scale(.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    @keyframes floatGlow {
      from { transform: translateY(-6px) translateX(-6px); }
      to { transform: translateY(10px) translateX(10px); }
    }
    @media (max-width: 720px) {
      .brand { grid-template-columns: 1fr; text-align: center; }
      .logo-wrap { margin: 0 auto; }
      .form-grid { grid-template-columns: 1fr; }
    }
    @media print {
      body {
        background: #fff;
        animation: none;
      }
      .container {
        max-width: none;
        margin: 0;
        padding: 0;
      }
      .card {
        border: 0;
        box-shadow: none;
        margin: 0;
        padding: 0;
      }
      .container > .card { display: none; }
      body[data-print-target="records"] #records_card { display: block !important; }
      body[data-print-target="audit"] #audit_card { display: block !important; }
      body[data-print-target="audit"] #audit_card[hidden] { display: block !important; }
      .no-print { display: none !important; }
      .table-shell { border: 0; overflow: visible; }
      table { min-width: 0; }
      th, td { font-size: 12px; }
    }
  </style>
</head>
<body class="page-preload">
<div class="intro-loader" id="intro_loader" aria-hidden="true">
  <div class="intro-glow intro-glow-a"></div>
  <div class="intro-glow intro-glow-b"></div>
  <div class="intro-core">
    <div class="intro-logo-shell">
      <img src="assets/church_logo.png" alt="Church Logo" onerror="this.style.display='none'; this.parentNode.textContent='SM';">
    </div>
    <h2>ST. MARTIN DE-PORRES CATHOLIC CHURCH</h2>
    <p>Administration Portal</p>
    <div class="intro-line"></div>
  </div>
</div>
<div class="container">
  <div class="card" id="records_card">
    <div class="brand">
      <div class="logo-wrap">
        <img src="assets/church_logo.png" alt="Church Logo" onerror="this.style.display='none'; this.parentNode.textContent='SM';">
      </div>
      <div>
        <h1 class="church-name">ST. MARTIN DE-PORRES CATHOLIC CHURCH (YOUTH DATABASE)</h1>
        <p class="subtitle">Administration Dashboard</p>
      </div>
    </div>

    <?php if ($isAdmin && !$mustChangePassword): ?>
      <div class="actions no-print">
        <a class="btn btn-muted" href="index.php">Open Public Form</a>
        <a class="btn btn-muted" href="admin.php?action=export_members_csv<?php echo $searchTerm !== '' ? '&q=' . urlencode($searchTerm) : ''; ?>">Export Members CSV</a>
        <a class="btn btn-muted" href="admin.php?action=export_audit_csv">Export Audit CSV</a>
        <button id="print_records_btn" type="button" class="btn btn-gold">Print Member Details</button>
        <button id="toggle_audit_btn" type="button" class="btn btn-muted">View Audit Log Trail</button>
        <a class="btn btn-danger" href="admin.php?logout=1">Logout</a>
      </div>
    <?php endif; ?>

    <?php if (!$isAdmin): ?>
      <div class="auth-wrap no-print">
        <h2 class="section-title" style="font-size: 20px;">Admin Access</h2>
        <p class="section-note">Choose an option below.</p>
        <div class="actions" style="margin-top:0;">
          <button id="show_login_btn" type="button" class="btn btn-main">Login</button>
          <button id="show_create_btn" type="button" class="btn btn-muted">Create Account</button>
        </div>

        <div id="login_view" style="margin-top: 12px;">
          <?php if ($loginError !== ''): ?>
            <div class="alert error"><?php echo htmlspecialchars($loginError); ?></div>
          <?php endif; ?>
          <form method="post" action="">
            <input type="hidden" name="action" value="login">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(csrfToken()); ?>">
            <label class="field-label" for="login_username">Username</label>
            <input id="login_username" name="username" type="text" required>

            <div style="margin-top: 10px;">
              <label class="field-label" for="login_password">Password</label>
              <input id="login_password" name="password" type="password" required>
            </div>

            <div class="form-actions" style="margin-top: 12px;">
              <button class="btn btn-main" type="submit">Login</button>
            </div>
          </form>
        </div>

        <div id="create_view" style="margin-top: 12px;" hidden>
          <?php if ($setupError !== ''): ?>
            <div class="alert error"><?php echo htmlspecialchars($setupError); ?></div>
          <?php endif; ?>
          <?php if ($setupSuccess !== ''): ?>
            <div class="alert success"><?php echo htmlspecialchars($setupSuccess); ?></div>
          <?php endif; ?>

          <?php if ($adminCount === 0): ?>
            <p class="section-note">Create the first administrator account to control access to this dashboard.</p>
            <form method="post" action="">
              <input type="hidden" name="action" value="register_admin">
              <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(csrfToken()); ?>">
              <div class="form-grid">
                <div>
                  <label class="field-label" for="create_full_name">Full Name</label>
                  <input id="create_full_name" name="full_name" type="text" required>
                </div>
                <div>
                  <label class="field-label" for="create_username">Username</label>
                  <input id="create_username" name="username" type="text" required>
                </div>
                <div>
                  <label class="field-label" for="create_password">Password</label>
                  <input id="create_password" name="password" type="password" required>
                </div>
                <div>
                  <label class="field-label" for="create_confirm_password">Confirm Password</label>
                  <input id="create_confirm_password" name="confirm_password" type="password" required>
                </div>
                <div class="full">
                  <p class="password-hint">Password must be more than 6 characters and include uppercase, lowercase, number, and symbol.</p>
                </div>
                <div class="full form-actions">
                  <button class="btn btn-main" type="submit">Create Admin Account</button>
                </div>
              </div>
            </form>
          <?php else: ?>
            <?php if (adminRecoveryCode() !== ''): ?>
              <p class="section-note">If you are locked out, use the recovery code to create a new Super Admin account.</p>
              <form method="post" action="">
                <input type="hidden" name="action" value="register_admin">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(csrfToken()); ?>">
                <input type="hidden" name="role" value="super_admin">
                <div class="form-grid">
                  <div>
                    <label class="field-label" for="recovery_code">Recovery Code</label>
                    <input id="recovery_code" name="recovery_code" type="password" required>
                  </div>
                  <div>
                    <label class="field-label" for="recovery_full_name">Full Name</label>
                    <input id="recovery_full_name" name="full_name" type="text" required>
                  </div>
                  <div>
                    <label class="field-label" for="recovery_username">Username</label>
                    <input id="recovery_username" name="username" type="text" required>
                  </div>
                  <div>
                    <label class="field-label" for="recovery_password">Password</label>
                    <input id="recovery_password" name="password" type="password" required>
                  </div>
                  <div>
                    <label class="field-label" for="recovery_confirm_password">Confirm Password</label>
                    <input id="recovery_confirm_password" name="confirm_password" type="password" required>
                  </div>
                  <div class="full">
                    <p class="password-hint">Password must be more than 6 characters and include uppercase, lowercase, number, and symbol.</p>
                  </div>
                  <div class="full form-actions">
                    <button class="btn btn-main" type="submit">Create Recovery Admin</button>
                  </div>
                </div>
              </form>
            <?php else: ?>
              <div class="alert" style="background:#fff4dd;color:#7a4c06;border:1px solid #f4d4a5;">
                Account creation is available after Super Admin login. Please log in, then use "Create Additional Admin Account".
              </div>
            <?php endif; ?>
          <?php endif; ?>
        </div>
      </div>

    <?php elseif ($mustChangePassword): ?>
      <div class="auth-wrap compact no-print">
        <h2 class="section-title" style="font-size: 20px;">Change Your Password</h2>
        <p class="section-note">For security, you must change your default password before using the dashboard.</p>
        <?php if ($passwordError !== ''): ?>
          <div class="alert error"><?php echo htmlspecialchars($passwordError); ?></div>
        <?php endif; ?>
        <?php if ($passwordSuccess !== ''): ?>
          <div class="alert success"><?php echo htmlspecialchars($passwordSuccess); ?></div>
        <?php endif; ?>
        <form method="post" action="">
          <input type="hidden" name="action" value="change_password">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(csrfToken()); ?>">
          <label class="field-label" for="new_password">New Password</label>
          <input id="new_password" name="new_password" type="password" required>

          <div style="margin-top: 10px;">
            <label class="field-label" for="confirm_password_change">Confirm Password</label>
            <input id="confirm_password_change" name="confirm_password" type="password" required>
          </div>

          <div class="form-actions" style="margin-top: 12px;">
            <button class="btn btn-main" type="submit">Update Password</button>
          </div>
        </form>
      </div>

    <?php else: ?>
      <p class="welcome no-print">Signed in as <strong><?php echo htmlspecialchars($currentAdminName); ?></strong> (<?php echo htmlspecialchars(strtoupper(str_replace('_', ' ', $currentAdminRole))); ?>)</p>
      <?php if (!$isSuperAdmin): ?>
        <div class="alert no-print" style="background:#fff4dd;color:#7a4c06;border:1px solid #f4d4a5;">Viewer mode: You can view and export data, but you cannot edit members or create admin accounts.</div>
      <?php endif; ?>

      <?php if ($setupError !== ''): ?>
        <div class="alert error no-print"><?php echo htmlspecialchars($setupError); ?></div>
      <?php endif; ?>
      <?php if ($setupSuccess !== ''): ?>
        <div class="alert success no-print"><?php echo htmlspecialchars($setupSuccess); ?></div>
      <?php endif; ?>

      <div class="stats-row">
        <div class="stat-card">
          <p class="stat-title">Total Youth Submitted</p>
          <p class="stat-value" id="total_youth_value"><?php echo (int)$totalYouthCount; ?></p>
        </div>
      </div>

      <?php if ($memberError !== ''): ?>
        <div class="alert error no-print"><?php echo htmlspecialchars($memberError); ?></div>
      <?php endif; ?>
      <?php if ($memberSuccess !== ''): ?>
        <div class="alert success no-print"><?php echo htmlspecialchars($memberSuccess); ?></div>
      <?php endif; ?>

      <form method="get" action="admin.php" class="search-form no-print">
        <input type="text" name="q" value="<?php echo htmlspecialchars($searchTerm); ?>" placeholder="Search by name, contact, profession, group...">
        <button class="btn btn-main" type="submit">Search</button>
        <?php if ($searchTerm !== ''): ?>
          <a class="btn btn-light" href="admin.php">Clear</a>
        <?php endif; ?>
      </form>

      <div class="table-shell">
        <table>
          <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Contact</th>
            <th>Date of Birth</th>
            <th>Gender</th>
            <th>Marital Status</th>
            <th>Profession</th>
            <th>Area of Interest</th>
            <th>Societal Group(s)</th>
            <th>Created</th>
            <th class="no-print">Action</th>
          </tr>
          </thead>
          <tbody>
          <?php if (!$records): ?>
            <tr><td colspan="11">No records yet.</td></tr>
          <?php else: ?>
            <?php foreach ($records as $row): ?>
              <tr>
                <td><?php echo (int)$row['id']; ?></td>
                <td><?php echo htmlspecialchars($row['name']); ?></td>
                <td><?php echo htmlspecialchars($row['contact']); ?></td>
                <td><?php echo htmlspecialchars(normalizeDobToDayMonth((string)$row['date_of_birth'])); ?></td>
                <td><?php echo htmlspecialchars($row['gender']); ?></td>
                <td><?php echo htmlspecialchars($row['marital_status']); ?></td>
                <td><?php echo htmlspecialchars($row['profession']); ?></td>
                <td><?php echo htmlspecialchars($row['area_of_interest']); ?></td>
                <td><?php echo htmlspecialchars($row['societal_groups']); ?></td>
                <td><?php echo htmlspecialchars($row['created_at']); ?></td>
                <td class="no-print">
                  <?php if ($isSuperAdmin): ?>
                    <a class="table-action-link" href="admin.php?edit_id=<?php echo (int)$row['id']; ?><?php echo $searchTerm !== '' ? '&q=' . urlencode($searchTerm) : ''; ?>#edit_member_section">Edit</a>
                  <?php else: ?>
                    <span style="color:#6b7280;font-size:13px;">Read-only</span>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
          <?php endif; ?>
          </tbody>
        </table>
      </div>

      <?php if ($editMember && $isSuperAdmin): ?>
        <?php $editSelectedGroups = array_values(array_filter(array_map('trim', explode(',', (string)$editMember['societal_groups'])))); ?>
        <?php $editDobDisplay = normalizeDobToDayMonth((string)$editMember['date_of_birth']); ?>
        <div class="edit-card no-print" id="edit_member_section">
          <h2 class="section-title" style="margin-top:0;">Edit Member Details</h2>
          <form method="post" action="">
            <input type="hidden" name="action" value="update_member">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(csrfToken()); ?>">
            <input type="hidden" name="member_id" value="<?php echo (int)$editMember['id']; ?>">
            <input type="hidden" name="q" value="<?php echo htmlspecialchars($searchTerm); ?>">

            <div class="form-grid">
              <div>
                <label class="field-label" for="edit_name">Name</label>
                <input id="edit_name" name="name" type="text" value="<?php echo htmlspecialchars($editMember['name']); ?>" required>
              </div>
              <div>
                <label class="field-label" for="edit_contact">Contact</label>
                <input id="edit_contact" name="contact" type="text" value="<?php echo htmlspecialchars($editMember['contact']); ?>" required>
              </div>
              <div>
                <label class="field-label" for="edit_dob">Date of Birth</label>
                <?php [$editDobDay, $editDobMonth] = splitDayMonth($editDobDisplay); ?>
                <div class="grid" style="grid-template-columns: 1fr 1fr; gap: 10px; max-width: 360px; margin: 0;">
                  <div>
                    <select id="edit_dob_day" name="dob_day" required>
                      <option value="">Day</option>
                      <?php for ($d = 1; $d <= 31; $d++): $dayValue = str_pad((string)$d, 2, '0', STR_PAD_LEFT); ?>
                        <option value="<?php echo $dayValue; ?>" <?php echo ($editDobDay === $dayValue) ? 'selected' : ''; ?>>
                          <?php echo $dayValue; ?>
                        </option>
                      <?php endfor; ?>
                    </select>
                  </div>
                  <div>
                    <select id="edit_dob_month" name="dob_month" required>
                      <option value="">Month</option>
                      <?php for ($m = 1; $m <= 12; $m++): $monthValue = str_pad((string)$m, 2, '0', STR_PAD_LEFT); ?>
                        <option value="<?php echo $monthValue; ?>" <?php echo ($editDobMonth === $monthValue) ? 'selected' : ''; ?>>
                          <?php echo $monthValue; ?>
                        </option>
                      <?php endfor; ?>
                    </select>
                  </div>
                </div>
              </div>
              <div>
                <label class="field-label" for="edit_gender">Gender</label>
                <select id="edit_gender" name="gender" required>
                  <?php foreach ($allowedGenders as $gender): ?>
                    <option value="<?php echo htmlspecialchars($gender); ?>" <?php echo ($editMember['gender'] === $gender) ? 'selected' : ''; ?>>
                      <?php echo htmlspecialchars($gender); ?>
                    </option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div>
                <label class="field-label" for="edit_marital_status">Marital Status</label>
                <select id="edit_marital_status" name="marital_status" required>
                  <?php foreach ($allowedStatuses as $status): ?>
                    <option value="<?php echo htmlspecialchars($status); ?>" <?php echo ($editMember['marital_status'] === $status) ? 'selected' : ''; ?>>
                      <?php echo htmlspecialchars($status); ?>
                    </option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div>
                <label class="field-label" for="edit_profession">Profession</label>
                <input id="edit_profession" name="profession" type="text" value="<?php echo htmlspecialchars($editMember['profession']); ?>" required>
              </div>
              <div class="full">
                <label class="field-label" for="edit_area_of_interest">Area of Interest</label>
                <input id="edit_area_of_interest" name="area_of_interest" type="text" value="<?php echo htmlspecialchars($editMember['area_of_interest']); ?>" required>
              </div>
              <div class="full">
                <label class="field-label">Societal Group(s)</label>
                <div class="checkbox-grid">
                  <?php foreach ($allowedSocietalGroups as $group): ?>
                    <label>
                      <input type="checkbox" name="societal_groups[]" value="<?php echo htmlspecialchars($group); ?>" <?php echo in_array($group, $editSelectedGroups, true) ? 'checked' : ''; ?>>
                      <span><?php echo htmlspecialchars($group); ?></span>
                    </label>
                  <?php endforeach; ?>
                </div>
              </div>
              <div class="full form-actions">
                <button class="btn btn-main" type="submit">Update Member</button>
                <a class="btn btn-light" href="admin.php<?php echo $searchTerm !== '' ? '?q=' . urlencode($searchTerm) : ''; ?>">Cancel Edit</a>
              </div>
            </div>
          </form>
        </div>
      <?php endif; ?>
    <?php endif; ?>
  </div>

  <?php if ($isSuperAdmin && !$mustChangePassword): ?>
    <div class="card">
      <h2 class="section-title">Create Additional Admin Account</h2>
      <p class="section-note">Only logged-in admins can add new admin users.</p>
      <div class="auth-wrap no-print">
        <form method="post" action="">
          <input type="hidden" name="action" value="register_admin">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(csrfToken()); ?>">
          <div class="form-grid">
            <div>
              <label class="field-label" for="new_full_name">Full Name</label>
              <input id="new_full_name" name="full_name" type="text" required>
            </div>
            <div>
              <label class="field-label" for="new_username">Username</label>
              <input id="new_username" name="username" type="text" required>
            </div>
            <div>
              <label class="field-label" for="new_role">Role</label>
              <select id="new_role" name="role" required>
                <option value="viewer">Viewer</option>
                <option value="super_admin">Super Admin</option>
              </select>
            </div>
            <div class="full">
              <p class="password-hint">Default password for new accounts is <strong><?php echo htmlspecialchars(defaultNewAdminPassword()); ?></strong>. User must change password on first login.</p>
            </div>
            <div class="full form-actions">
              <button class="btn btn-main" type="submit">Create Admin</button>
            </div>
          </div>
        </form>
      </div>
    </div>

    <div class="card" id="audit_card" hidden>
      <h2 style="margin-top: 0;">Audit Log Trail</h2>
      <div class="actions no-print" style="margin-top: 0;">
        <button id="print_audit_btn" type="button" class="btn btn-gold">Print Audit Log Trail</button>
      </div>
      <div class="table-shell">
        <table>
          <thead>
          <tr>
            <th>Log ID</th>
            <th>Time</th>
            <th>Admin</th>
            <th>Event</th>
            <th>Details</th>
            <th>IP</th>
          </tr>
          </thead>
          <tbody>
          <?php if (!$auditLogs): ?>
            <tr><td colspan="6">No audit logs yet.</td></tr>
          <?php else: ?>
            <?php foreach ($auditLogs as $log): ?>
              <tr>
                <td><?php echo (int)$log['id']; ?></td>
                <td><?php echo htmlspecialchars($log['created_at']); ?></td>
                <td><?php echo htmlspecialchars($log['username'] ?? 'N/A'); ?></td>
                <td><?php echo htmlspecialchars($log['event_type']); ?></td>
                <td><?php echo htmlspecialchars($log['event_details']); ?></td>
                <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
              </tr>
            <?php endforeach; ?>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>
  <?php endif; ?>
</div>

<script>
  (function () {
    var loader = document.getElementById('intro_loader');
    if (!loader) return;

    window.addEventListener('load', function () {
      setTimeout(function () {
        loader.classList.add('is-leaving');
        document.body.classList.remove('page-preload');
      }, 1100);
    });
  })();
</script>

<?php if (!$isAdmin): ?>
<script>
  (function () {
    var showLoginBtn = document.getElementById('show_login_btn');
    var showCreateBtn = document.getElementById('show_create_btn');
    var loginView = document.getElementById('login_view');
    var createView = document.getElementById('create_view');
    if (!showLoginBtn || !showCreateBtn || !loginView || !createView) return;

    var shouldShowCreate = <?php echo (($setupError !== '' || $setupSuccess !== '') ? 'true' : 'false'); ?>;

    function showLogin() {
      loginView.hidden = false;
      createView.hidden = true;
      showLoginBtn.classList.add('btn-main');
      showLoginBtn.classList.remove('btn-muted');
      showCreateBtn.classList.add('btn-muted');
      showCreateBtn.classList.remove('btn-main');
    }

    function showCreate() {
      loginView.hidden = true;
      createView.hidden = false;
      showCreateBtn.classList.add('btn-main');
      showCreateBtn.classList.remove('btn-muted');
      showLoginBtn.classList.add('btn-muted');
      showLoginBtn.classList.remove('btn-main');
    }

    showLoginBtn.addEventListener('click', showLogin);
    showCreateBtn.addEventListener('click', showCreate);

    if (shouldShowCreate) {
      showCreate();
    } else {
      showLogin();
    }
  })();
</script>
<?php endif; ?>

<?php if ($isAdmin && !$mustChangePassword): ?>
<script>
  (function () {
    var csrfToken = '<?php echo htmlspecialchars(csrfToken(), ENT_QUOTES); ?>';
    var recordsBtn = document.getElementById('print_records_btn');
    var auditBtn = document.getElementById('print_audit_btn');
    var toggleAuditBtn = document.getElementById('toggle_audit_btn');
    var auditCard = document.getElementById('audit_card');
    var totalYouthValue = document.getElementById('total_youth_value');
    if (!recordsBtn && !auditBtn && !toggleAuditBtn) return;

    if (toggleAuditBtn && auditCard) {
      toggleAuditBtn.addEventListener('click', function () {
        var isHidden = auditCard.hasAttribute('hidden');
        if (isHidden) {
          auditCard.removeAttribute('hidden');
          toggleAuditBtn.textContent = 'Hide Audit Log Trail';
          auditCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } else {
          auditCard.setAttribute('hidden', '');
          toggleAuditBtn.textContent = 'View Audit Log Trail';
        }
      });
    }

    function runPrint(target) {
      var body = new URLSearchParams({ action: 'log_print', target: target, csrf_token: csrfToken }).toString();

      fetch('admin.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
        body: body,
        credentials: 'same-origin'
      }).finally(function () {
        document.body.setAttribute('data-print-target', target);
        window.print();
        document.body.removeAttribute('data-print-target');
      });
    }

    if (recordsBtn) {
      recordsBtn.addEventListener('click', function () {
        runPrint('records');
      });
    }

    if (auditBtn) {
      auditBtn.addEventListener('click', function () {
        runPrint('audit');
      });
    }

    function refreshYouthStats() {
      if (!totalYouthValue) return;

      fetch('admin.php?action=youth_stats', { credentials: 'same-origin' })
        .then(function (response) {
          if (!response.ok) throw new Error('Failed');
          return response.json();
        })
        .then(function (data) {
          if (data && data.ok && typeof data.total_youth !== 'undefined') {
            totalYouthValue.textContent = data.total_youth;
          }
        })
        .catch(function () {
          // Keep current value on temporary request errors.
        });
    }

    refreshYouthStats();
    setInterval(refreshYouthStats, 5000);

    var editNoSociety = document.querySelector('#edit_member_section input[name="societal_groups[]"][value="No Society"]');
    if (editNoSociety) {
      var editGroupBoxes = document.querySelectorAll('#edit_member_section input[name="societal_groups[]"]');
      var enforceEditNoSociety = function (changedBox) {
        if (changedBox === editNoSociety && editNoSociety.checked) {
          editGroupBoxes.forEach(function (box) {
            if (box !== editNoSociety) {
              box.checked = false;
              box.disabled = true;
            }
          });
        } else if (changedBox !== editNoSociety && changedBox.checked) {
          editNoSociety.checked = false;
        }

        if (!editNoSociety.checked) {
          editGroupBoxes.forEach(function (box) {
            if (box !== editNoSociety) {
              box.disabled = false;
            }
          });
        }
      };

      editGroupBoxes.forEach(function (box) {
        box.addEventListener('change', function () {
          enforceEditNoSociety(box);
        });
      });

      enforceEditNoSociety(editNoSociety.checked ? editNoSociety : editGroupBoxes[0]);
    }
  })();
</script>
<?php endif; ?>
</body>
</html>

