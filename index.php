<?php
session_start();

require_once __DIR__ . '/db.php';

function normalizeDobToDayMonth(string $rawDob): string
{
    $rawDob = trim($rawDob);
    if ($rawDob === '') {
        return '';
    }

    // Accept native date input (YYYY-MM-DD) and store only DD/MM.
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

$errors = [];
$success = '';
$showPreview = false;
$formShowSubmitOnly = false;
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
    'Sunday School',
    'Students Union',
    'CWA',
];
$formInput = [
    'name' => '',
    'contact' => '',
    'date_of_birth' => '',
    'gender' => '',
    'marital_status' => '',
    'profession' => '',
    'area_of_interest' => '',
    'societal_groups' => [],
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = (string)($_POST['csrf_token'] ?? '');
    $csrfValid = isValidCsrfToken($csrf);
    if (!$csrfValid) {
        $errors[] = 'Your session expired. Please try again.';
    }

    $action = trim($_POST['action'] ?? 'preview');
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
    if (!is_array($societalGroups)) {
        $societalGroups = [];
    }
    $societalGroups = array_values(array_unique(array_filter(array_map('trim', $societalGroups), static function ($value) {
        return $value !== '';
    })));

    if ($csrfValid && $name === '') {
        $errors[] = 'Name is required.';
    }

    if ($csrfValid && $contact === '') {
        $errors[] = 'Contact is required.';
    }

    if ($csrfValid) {
        if ($dateOfBirth === '') {
            $errors[] = 'Date of birth is required.';
        } elseif (!preg_match('/^(0[1-9]|[12][0-9]|3[01])\/(0[1-9]|1[0-2])$/', $dateOfBirth)) {
            $errors[] = 'Date of birth must be in DD/MM format.';
        } else {
            [$day, $month] = array_map('intval', explode('/', $dateOfBirth));
            if (!checkdate($month, $day, 2000)) {
                $errors[] = 'Please enter a valid date of birth.';
            }
        }
    }

    if ($csrfValid && !in_array($maritalStatus, $allowedStatuses, true)) {
        $errors[] = 'Please select a valid marital status.';
    }

    if ($csrfValid && !in_array($gender, $allowedGenders, true)) {
        $errors[] = 'Please select a valid gender.';
    }

    if ($csrfValid && $profession === '') {
        $errors[] = 'Profession is required.';
    }

    if ($csrfValid && !$societalGroups) {
        $errors[] = 'Please select at least one societal group.';
    } else {
        if ($csrfValid && in_array('No Society', $societalGroups, true) && count($societalGroups) > 1) {
            $errors[] = 'If "No Society" is selected, no other societal group can be selected.';
        }
        foreach ($societalGroups as $group) {
            if ($csrfValid && !in_array($group, $allowedSocietalGroups, true)) {
                $errors[] = 'Please select valid societal group values.';
                break;
            }
        }
    }

    if ($csrfValid && $name !== '') {
        $existing = $pdo->prepare('SELECT id FROM youth WHERE LOWER(name) = LOWER(:name) LIMIT 1');
        $existing->execute([':name' => $name]);
        if ($existing->fetch()) {
            $errors[] = 'Name already exists.';
        }
    }

    $formInput = [
        'name' => $name,
        'contact' => $contact,
        'date_of_birth' => $dateOfBirth,
        'gender' => $gender,
        'marital_status' => $maritalStatus,
        'profession' => $profession,
        'area_of_interest' => $areaOfInterest,
        'societal_groups' => $societalGroups,
    ];

    if (!$errors && $action === 'preview') {
        $showPreview = true;
    }

    if (!$errors && $action === 'edit_after_preview') {
        $formShowSubmitOnly = true;
    }

    if (!$errors && $action === 'final_submit') {
        $societalGroupsText = implode(', ', $societalGroups);
        $stmt = $pdo->prepare(
            'INSERT INTO youth (name, contact, date_of_birth, gender, marital_status, profession, area_of_interest, societal_groups)
             VALUES (:name, :contact, :date_of_birth, :gender, :marital_status, :profession, :area_of_interest, :societal_groups)'
        );
        try {
            $stmt->execute([
                ':name' => $name,
                ':contact' => $contact,
                ':date_of_birth' => toDatabaseDob($pdo, $dateOfBirth),
                ':gender' => $gender,
                ':marital_status' => $maritalStatus,
                ':profession' => $profession,
                ':area_of_interest' => $areaOfInterest,
                ':societal_groups' => $societalGroupsText,
            ]);

            $success = 'Thank you. Your details have been submitted.';
            $formInput = [
                'name' => '',
                'contact' => '',
                'date_of_birth' => '',
                'gender' => '',
                'marital_status' => '',
                'profession' => '',
                'area_of_interest' => '',
                'societal_groups' => [],
            ];
            $formShowSubmitOnly = false;
        } catch (PDOException $e) {
            // 23000 handles unique-key violations if database constraint is enabled.
            if ($e->getCode() === '23000') {
                $errors[] = 'Name already exists.';
            } else {
                $errors[] = 'Unable to save at the moment. Please try again.';
            }
        }
    }

    if ($action === 'final_submit' && $errors) {
        $formShowSubmitOnly = true;
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ST. MARTIN DE-PORRES CATHOLIC CHURCH (YOUTH DATABASE)</title>
  <style>
    :root {
      --bg-1: #fffdf6;
      --bg-2: #f1efe7;
      --ink: #1e293b;
      --brand: #8b1e3f;
      --brand-dark: #5f152b;
      --gold: #c89a3d;
      --line: #e3ddcf;
      --card: #ffffff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Book Antiqua", "Palatino Linotype", Georgia, serif;
      color: var(--ink);
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
      z-index: 1200;
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
    .container { max-width: 860px; margin: 26px auto; padding: 0 16px; }
    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: 0 12px 30px rgba(95, 21, 43, 0.12);
      padding: 22px;
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
    .logo-wrap img {
      width: 100%;
      height: 100%;
      object-fit: cover;
      display: block;
    }
    .church-name {
      margin: 0;
      font-size: clamp(20px, 2.8vw, 29px);
      line-height: 1.2;
      color: var(--brand-dark);
    }
    .subtitle {
      margin: 6px 0 0;
      font-size: 14px;
      color: #5b6473;
    }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    .full { grid-column: 1 / -1; }
    label {
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
    .multi-select { position: relative; }
    .multi-select-toggle {
      width: 100%;
      text-align: left;
      padding: 12px;
      border: 1px solid #d9d4c7;
      border-radius: 10px;
      background: #fffefb;
      color: #1e293b;
      font: inherit;
      cursor: pointer;
    }
    .multi-select-toggle:focus {
      outline: none;
      border-color: var(--gold);
      box-shadow: 0 0 0 3px rgba(200, 154, 61, 0.18);
    }
    .multi-select-panel {
      position: absolute;
      left: 0;
      right: 0;
      top: calc(100% + 6px);
      background: #fffefb;
      border: 1px solid #d9d4c7;
      border-radius: 10px;
      box-shadow: 0 12px 24px rgba(0, 0, 0, 0.12);
      padding: 8px;
      max-height: 220px;
      overflow-y: auto;
      z-index: 20;
      display: none;
    }
    .multi-select-panel.open { display: block; }
    .multi-select-item {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 4px;
      border-radius: 6px;
    }
    .multi-select-item:hover { background: #f7f3e8; }
    .multi-select-item input {
      width: auto;
      padding: 0;
      margin: 0;
    }
    .btn {
      background: linear-gradient(135deg, var(--brand), var(--brand-dark));
      color: #fff;
      border: 0;
      border-radius: 10px;
      padding: 12px 20px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      transition: transform .15s ease, box-shadow .15s ease;
    }
    .btn:hover { transform: translateY(-1px); box-shadow: 0 8px 14px rgba(95, 21, 43, 0.25); }
    .alert { padding: 11px 12px; border-radius: 10px; margin-bottom: 12px; }
    .alert.error { background: #fee7e8; color: #7f1d1d; border: 1px solid #fecdd3; }
    .alert.success { background: #e8f8ee; color: #166534; border: 1px solid #bbf7d0; }
    .note {
      margin: 12px 0 0;
      font-size: 13px;
      color: #6b7280;
      text-align: center;
    }
    .preview-box {
      margin-top: 16px;
      border: 1px solid #e3ddcf;
      border-radius: 12px;
      background: #fffaf0;
      padding: 14px;
    }
    .preview-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px 14px;
      margin-top: 8px;
    }
    .preview-item strong { color: #5f152b; }
    .preview-actions {
      margin-top: 12px;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }
    .btn-secondary {
      background: #0f766e;
      color: #fff;
      border: 0;
      border-radius: 10px;
      padding: 12px 20px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
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
      .grid { grid-template-columns: 1fr; }
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
    <p>Youth Database</p>
    <div class="intro-line"></div>
  </div>
</div>
<div class="container">
  <div class="card">
    <div class="brand">
      <div class="logo-wrap">
        <img src="assets/church_logo.png" alt="Church Logo" onerror="this.style.display='none'; this.parentNode.textContent='SM';">
      </div>
      <div>
        <h1 class="church-name">ST. MARTIN DE-PORRES CATHOLIC CHURCH (YOUTH DATABASE)</h1>
        <p class="subtitle">Youth Registration Form</p>
      </div>
    </div>

    <?php if ($errors): ?>
      <div class="alert error"><?php echo htmlspecialchars(implode(' ', $errors)); ?></div>
    <?php endif; ?>

    <?php if ($success): ?>
      <div class="alert success"><?php echo htmlspecialchars($success); ?></div>
    <?php endif; ?>

    <?php if (!$showPreview || $formShowSubmitOnly || $errors): ?>
    <form method="post" action="">
      <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(csrfToken()); ?>">
      <div class="grid">
        <div>
          <label for="name">Name</label>
          <input id="name" name="name" type="text" value="<?php echo htmlspecialchars($formInput['name']); ?>" required>
        </div>

        <div>
          <label for="contact">Contact</label>
          <input id="contact" name="contact" type="text" value="<?php echo htmlspecialchars($formInput['contact']); ?>" required>
        </div>

        <div>
          <label>Date of Birth</label>
          <?php [$dobDayValue, $dobMonthValue] = splitDayMonth((string)$formInput['date_of_birth']); ?>
          <div class="grid" style="grid-template-columns: 1fr 1fr; gap: 10px;">
            <div>
              <select id="dob_day" name="dob_day" required>
                <option value="">Day</option>
                <?php for ($d = 1; $d <= 31; $d++): $dayValue = str_pad((string)$d, 2, '0', STR_PAD_LEFT); ?>
                  <option value="<?php echo $dayValue; ?>" <?php echo ($dobDayValue === $dayValue) ? 'selected' : ''; ?>>
                    <?php echo $dayValue; ?>
                  </option>
                <?php endfor; ?>
              </select>
            </div>
            <div>
              <select id="dob_month" name="dob_month" required>
                <option value="">Month</option>
                <?php for ($m = 1; $m <= 12; $m++): $monthValue = str_pad((string)$m, 2, '0', STR_PAD_LEFT); ?>
                  <option value="<?php echo $monthValue; ?>" <?php echo ($dobMonthValue === $monthValue) ? 'selected' : ''; ?>>
                    <?php echo $monthValue; ?>
                  </option>
                <?php endfor; ?>
              </select>
            </div>
          </div>
        </div>

        <div>
          <label for="gender">Gender</label>
          <select id="gender" name="gender" required>
            <option value="">Select gender</option>
            <?php foreach ($allowedGenders as $genderOption): ?>
              <option value="<?php echo htmlspecialchars($genderOption); ?>" <?php echo ($formInput['gender'] === $genderOption) ? 'selected' : ''; ?>>
                <?php echo htmlspecialchars($genderOption); ?>
              </option>
            <?php endforeach; ?>
          </select>
        </div>

        <div>
          <label for="marital_status">Marital Status</label>
          <select id="marital_status" name="marital_status" required>
            <option value="">Select status</option>
            <?php foreach ($allowedStatuses as $status): ?>
              <option value="<?php echo $status; ?>" <?php echo ($formInput['marital_status'] === $status) ? 'selected' : ''; ?>>
                <?php echo $status; ?>
              </option>
            <?php endforeach; ?>
          </select>
        </div>

        <div>
          <label for="profession">Profession</label>
          <input id="profession" name="profession" type="text" value="<?php echo htmlspecialchars($formInput['profession']); ?>" required>
        </div>

        <div class="full">
          <label for="area_of_interest">Area of Interest</label>
          <input id="area_of_interest" name="area_of_interest" type="text" value="<?php echo htmlspecialchars($formInput['area_of_interest']); ?>">
        </div>

        <div class="full">
          <label for="societal_groups">Societal Group</label>
          <?php $selectedGroups = $formInput['societal_groups']; ?>
          <div class="multi-select" id="societal_group_select">
            <button type="button" class="multi-select-toggle" id="societal_group_toggle">Select group(s)</button>
            <div class="multi-select-panel" id="societal_group_panel">
              <?php foreach ($allowedSocietalGroups as $group): ?>
                <label class="multi-select-item">
                  <input
                    type="checkbox"
                    name="societal_groups[]"
                    value="<?php echo htmlspecialchars($group); ?>"
                    <?php echo in_array($group, $selectedGroups, true) ? 'checked' : ''; ?>
                  >
                  <span><?php echo htmlspecialchars($group); ?></span>
                </label>
              <?php endforeach; ?>
            </div>
          </div>
        </div>

        <div class="full" style="text-align:center;">
          <?php if ($formShowSubmitOnly): ?>
            <button class="btn" type="submit" name="action" value="final_submit">Submit</button>
          <?php else: ?>
            <button class="btn" type="submit" name="action" value="preview">Preview Submission</button>
          <?php endif; ?>
        </div>
      </div>
    </form>
    <?php endif; ?>

    <?php if ($showPreview): ?>
      <div class="preview-box">
        <h3 style="margin:0;color:#5f152b;">Preview Before Final Submission</h3>
        <div class="preview-grid">
          <div class="preview-item"><strong>Name:</strong> <?php echo htmlspecialchars($formInput['name']); ?></div>
          <div class="preview-item"><strong>Contact:</strong> <?php echo htmlspecialchars($formInput['contact']); ?></div>
          <div class="preview-item"><strong>Date of Birth:</strong> <?php echo htmlspecialchars($formInput['date_of_birth']); ?></div>
          <div class="preview-item"><strong>Gender:</strong> <?php echo htmlspecialchars($formInput['gender']); ?></div>
          <div class="preview-item"><strong>Marital Status:</strong> <?php echo htmlspecialchars($formInput['marital_status']); ?></div>
          <div class="preview-item"><strong>Profession:</strong> <?php echo htmlspecialchars($formInput['profession']); ?></div>
          <div class="preview-item" style="grid-column:1/-1;"><strong>Area of Interest:</strong> <?php echo htmlspecialchars($formInput['area_of_interest']); ?></div>
          <div class="preview-item" style="grid-column:1/-1;"><strong>Societal Group(s):</strong> <?php echo htmlspecialchars(implode(', ', $formInput['societal_groups'])); ?></div>
        </div>
        <form method="post" action="">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(csrfToken()); ?>">
          <input type="hidden" name="name" value="<?php echo htmlspecialchars($formInput['name']); ?>">
          <input type="hidden" name="contact" value="<?php echo htmlspecialchars($formInput['contact']); ?>">
          <input type="hidden" name="date_of_birth" value="<?php echo htmlspecialchars($formInput['date_of_birth']); ?>">
          <input type="hidden" name="gender" value="<?php echo htmlspecialchars($formInput['gender']); ?>">
          <input type="hidden" name="marital_status" value="<?php echo htmlspecialchars($formInput['marital_status']); ?>">
          <input type="hidden" name="profession" value="<?php echo htmlspecialchars($formInput['profession']); ?>">
          <input type="hidden" name="area_of_interest" value="<?php echo htmlspecialchars($formInput['area_of_interest']); ?>">
          <?php foreach ($formInput['societal_groups'] as $group): ?>
            <input type="hidden" name="societal_groups[]" value="<?php echo htmlspecialchars($group); ?>">
          <?php endforeach; ?>
          <div class="preview-actions">
            <button class="btn" type="submit" name="action" value="final_submit">Submit</button>
            <button class="btn-secondary" type="submit" name="action" value="edit_after_preview">Edit</button>
          </div>
        </form>
      </div>
    <?php endif; ?>

    <p class="note">Please complete this form once. Church administration will review submissions privately.</p>
  </div>
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
<script>
  (function () {
    var root = document.getElementById('societal_group_select');
    if (!root) return;

    var toggle = document.getElementById('societal_group_toggle');
    var panel = document.getElementById('societal_group_panel');
    var boxes = root.querySelectorAll('input[type="checkbox"][name="societal_groups[]"]');
    var noSociety = root.querySelector('input[type="checkbox"][name="societal_groups[]"][value="No Society"]');

    function updateLabel() {
      var selectedNames = [];
      boxes.forEach(function (box) {
        if (box.checked) selectedNames.push(box.value);
      });
      toggle.textContent = selectedNames.length > 0 ? selectedNames.join(', ') : 'Select group(s)';
    }

    function enforceNoSocietyRule(changedBox) {
      if (!noSociety) return;

      if (changedBox === noSociety && noSociety.checked) {
        boxes.forEach(function (box) {
          if (box !== noSociety) {
            box.checked = false;
            box.disabled = true;
          }
        });
      } else if (changedBox !== noSociety && changedBox && changedBox.checked) {
        noSociety.checked = false;
      }

      if (!noSociety.checked) {
        boxes.forEach(function (box) {
          if (box !== noSociety) {
            box.disabled = false;
          }
        });
      }
    }

    toggle.addEventListener('click', function () {
      panel.classList.toggle('open');
    });

    document.addEventListener('click', function (event) {
      if (!root.contains(event.target)) {
        panel.classList.remove('open');
      }
    });

    boxes.forEach(function (box) {
      box.addEventListener('change', function () {
        enforceNoSocietyRule(box);
        updateLabel();
      });
    });

    enforceNoSocietyRule(noSociety && noSociety.checked ? noSociety : null);
    updateLabel();
  })();
</script>
</body>
</html>


