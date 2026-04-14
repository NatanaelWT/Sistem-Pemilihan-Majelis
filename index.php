<?php
declare(strict_types=1);

const PRIMARY_DATA_DIR = __DIR__ . '/../../majelis_secure_data';
const FALLBACK_SESSION_DIR = __DIR__ . '/.session_store';

const LEGACY_BIDANG_FILE = __DIR__ . '/bidang.json';
const LEGACY_KANDIDAT_FILE = __DIR__ . '/kandidat.json';
const LEGACY_PEMILIHAN_FILE = __DIR__ . '/pemilihan.json';
const LEGACY_VOTE_LOG_FILE = __DIR__ . '/vote_log.json';
const LEGACY_USER_FILE = __DIR__ . '/users.json';
const LEGACY_FLAGGING_FILE = __DIR__ . '/flagging.json';
const LEGACY_ASSIGNMENT_FILE = __DIR__ . '/wawancara_assignment.json';
const LEGACY_KESEDIAAN_FORM_FILE = __DIR__ . '/kesediaan_form.json';
const LEGACY_SCORECARD_TEMPLATE_FILE = __DIR__ . '/scorecard_templates.json';
const LEGACY_SCORECARD_SUBMISSION_FILE = __DIR__ . '/scorecard_submissions.json';

const DATA_MAX_BYTES = 3 * 1024 * 1024;
const IMPORT_MAX_BYTES = 8 * 1024 * 1024;
const KESEDIAAN_UPLOAD_MAX_BYTES = 8 * 1024 * 1024;
const LOGIN_MAX_ATTEMPTS = 6;
const LOGIN_MAX_ATTEMPTS_PER_IP = 25;
const LOGIN_WINDOW_SECONDS = 15 * 60;
const LOGIN_BLOCK_SECONDS = 15 * 60;

const APP_DEFAULT_TIMEZONE = 'Asia/Jakarta';

const ELECTION_DEADLINE_END = '2026-03-29 16:59:59';
const ELECTION_DEADLINE_LABEL = '29 Maret 2026';

$GLOBALS['MAJELIS_LEGACY_DEFAULT_TIMEZONE'] = date_default_timezone_get();
date_default_timezone_set(APP_DEFAULT_TIMEZONE);
@ini_set('date.timezone', APP_DEFAULT_TIMEZONE);

function is_https_request(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    return ((string)($_SERVER['SERVER_PORT'] ?? '')) === '443';
}

function ensure_session_directory(string $dir): bool
{
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
            return false;
        }
    }

    @chmod($dir, 0700);
    return is_writable($dir);
}

function protect_session_directory_if_local(string $dir): void
{
    if (realpath($dir) !== realpath(FALLBACK_SESSION_DIR)) {
        return;
    }

    $htaccessPath = $dir . '/.htaccess';
    if (!is_file($htaccessPath)) {
        $content = "# Session files protection\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Deny from all\n</IfModule>\n";
        @file_put_contents($htaccessPath, $content, LOCK_EX);
    }

    $indexPath = $dir . '/index.php';
    if (!is_file($indexPath)) {
        $guard = "<?php\nhttp_response_code(403);\nexit('403 - Forbidden');\n";
        @file_put_contents($indexPath, $guard, LOCK_EX);
    }
}

function resolve_session_path(): string
{
    static $resolved = null;
    if (is_string($resolved)) {
        return $resolved;
    }

    $candidates = [];
    $env = getenv('MAJELIS_SESSION_DIR');
    if (is_string($env)) {
        $env = trim($env);
        if ($env !== '') {
            $candidates[] = $env;
        }
    }
    $candidates[] = PRIMARY_DATA_DIR . '/sessions';
    $candidates[] = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'majelis_secure_sessions';
    $candidates[] = FALLBACK_SESSION_DIR;

    foreach ($candidates as $candidate) {
        if (ensure_session_directory($candidate)) {
            $resolved = $candidate;
            protect_session_directory_if_local($resolved);
            break;
        }
    }

    if (!is_string($resolved)) {
        $resolved = sys_get_temp_dir();
    }

    return $resolved;
}

function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $cookiePath = '/';
    if (!empty($_SERVER['SCRIPT_NAME'])) {
        $base = str_replace('\\', '/', dirname((string)$_SERVER['SCRIPT_NAME']));
        $base = trim($base, '/');
        if ($base !== '') {
            $cookiePath = '/' . $base . '/';
        }
    }

    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    if (is_https_request()) {
        ini_set('session.cookie_secure', '1');
    }

    session_name('MAJELISSESSID');
    session_save_path(resolve_session_path());
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => $cookiePath,
        'domain' => '',
        'secure' => is_https_request(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

function send_security_headers(): void
{
    if (headers_sent()) {
        return;
    }

    @ini_set('expose_php', '0');
    header_remove('X-Powered-By');
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    header("Content-Security-Policy: default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
}

function random_hex(int $bytes = 16): string
{
    try {
        return bin2hex(random_bytes($bytes));
    } catch (Throwable $e) {
        return sha1(uniqid((string)mt_rand(), true));
    }
}

function generate_id(string $prefix): string
{
    return $prefix . random_hex(16);
}

function normalize_role(string $role): string
{
    $role = strtolower(trim($role));
    $role = str_replace(['-', ' '], '_', $role);
    return match ($role) {
        'admin' => 'admin',
        'pewawancara' => 'pewawancara',
        'gembala_lokal', 'gembalalokal' => 'gembala_lokal',
        default => 'user',
    };
}

function role_priority(string $role): int
{
    return match (normalize_role($role)) {
        'admin' => 0,
        'pewawancara' => 1,
        'gembala_lokal' => 2,
        default => 3,
    };
}

function normalize_role_list($roles): array
{
    $items = [];
    if (is_array($roles)) {
        $items = $roles;
    } elseif (is_string($roles)) {
        $trimmed = trim($roles);
        if ($trimmed !== '') {
            $items = preg_split('/\s*[,;|]\s*/', $trimmed) ?: [$trimmed];
        }
    }

    $normalized = [];
    $seen = [];
    foreach ($items as $item) {
        if (!is_string($item) && !is_numeric($item)) {
            continue;
        }
        $role = normalize_role((string)$item);
        if (isset($seen[$role])) {
            continue;
        }
        $normalized[] = $role;
        $seen[$role] = true;
    }

    if ($normalized === []) {
        return ['user'];
    }

    usort($normalized, static function (string $left, string $right): int {
        return role_priority($left) <=> role_priority($right);
    });

    return $normalized;
}

function user_roles_from_record(array $user): array
{
    $rawRoles = [];
    if (array_key_exists('roles', $user)) {
        $rawRoles = (array)$user['roles'];
    }
    $rawRole = trim((string)($user['role'] ?? ''));
    if ($rawRole !== '') {
        $rawRoles[] = $rawRole;
    }
    if ($rawRoles === []) {
        $rawRoles[] = 'user';
    }
    return normalize_role_list($rawRoles);
}

function primary_role_from_record(array $user): string
{
    $roles = user_roles_from_record($user);
    return (string)($roles[0] ?? 'user');
}

function user_has_role(array $user, string $role): bool
{
    return in_array(normalize_role($role), user_roles_from_record($user), true);
}

function current_session_roles(): array
{
    $sessionRoles = $_SESSION['roles'] ?? null;
    if (is_array($sessionRoles)) {
        return normalize_role_list($sessionRoles);
    }
    return normalize_role_list((string)($_SESSION['role'] ?? 'user'));
}

function sync_session_roles(array $user): void
{
    $_SESSION['role'] = primary_role_from_record($user);
    $_SESSION['roles'] = user_roles_from_record($user);
}

start_secure_session();
send_security_headers();

function app_base_path(): string
{
    $base = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? ''));
    $base = rtrim($base, '/');
    return $base === '/' ? '' : $base;
}

function app_index_url(array $params = []): string
{
    $url = app_base_path() . '/index.php';
    if ($params !== []) {
        $url .= '?' . http_build_query($params);
    }
    return $url;
}

function route_page(): string
{
    $page = strtolower(trim((string)($_GET['page'] ?? '')));
    return $page;
}

function redirect_to_page(string $page, array $params = []): void
{
    $params = array_merge(['page' => $page], $params);
    header('Location: ' . app_index_url($params));
    exit;
}

function is_logged_in(): bool
{
    return !empty($_SESSION['logged_in']);
}

function is_admin_user(): bool
{
    return in_array('admin', current_session_roles(), true);
}

function can_access_wawancara_role(string $role): bool
{
    return can_access_wawancara_roles([$role]);
}

function can_access_wawancara_roles(array $roles): bool
{
    $roles = normalize_role_list($roles);
    return in_array('admin', $roles, true) || in_array('pewawancara', $roles, true);
}

function can_access_wawancara_user(array $user): bool
{
    return can_access_wawancara_roles(user_roles_from_record($user));
}

function can_access_gembala_lokal_roles(array $roles): bool
{
    $roles = normalize_role_list($roles);
    return in_array('gembala_lokal', $roles, true);
}

function can_access_gembala_lokal_user(array $user): bool
{
    return can_access_gembala_lokal_roles(user_roles_from_record($user));
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function render_language_switcher_head(): void
{
    ?>
    <style>
        .language-switcher {
            position: fixed;
            right: 18px;
            bottom: 18px;
            z-index: 120;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 6px;
            border-radius: 999px;
            background: rgba(17, 24, 39, 0.92);
            box-shadow: 0 14px 32px rgba(15, 23, 42, 0.24);
            backdrop-filter: blur(10px);
        }
        .language-switcher-btn {
            border: 0;
            min-width: 54px;
            padding: 10px 14px;
            border-radius: 999px;
            background: transparent;
            color: rgba(255, 255, 255, 0.78);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.04em;
            cursor: pointer;
            transition: background 0.18s ease, color 0.18s ease, transform 0.18s ease;
        }
        .language-switcher-btn:hover {
            color: #fff;
            transform: translateY(-1px);
        }
        .language-switcher-btn.is-active {
            background: #fff;
            color: #111827;
        }
        .language-switcher-btn:focus-visible {
            outline: 3px solid #93c5fd;
            outline-offset: 2px;
        }
        @media (max-width: 640px) {
            .language-switcher {
                right: 14px;
                bottom: 14px;
            }
            .language-switcher-btn {
                min-width: 50px;
                padding: 9px 12px;
            }
        }
    </style>
    <?php
}

function render_language_switcher(): void
{
    ?>
    <div class="language-switcher" aria-label="Pengganti bahasa">
        <button class="language-switcher-btn" type="button" data-language-option="id">ID</button>
        <button class="language-switcher-btn" type="button" data-language-option="en">EN</button>
    </div>
    <?php
}

function render_language_script(array $translations): void
{
    $payload = json_encode($translations, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if (!is_string($payload) || $payload === '') {
        $payload = '{}';
    }
    ?>
    <script>
        (function () {
            const STORAGE_KEY = 'majelis_language';
            const DEFAULT_LANG = 'id';
            const translations = <?= $payload ?>;
            const languageButtons = Array.from(document.querySelectorAll('[data-language-option]'));

            function normalizeLanguage(value) {
                return value === 'en' ? 'en' : 'id';
            }

            function readStoredLanguage() {
                try {
                    return normalizeLanguage(localStorage.getItem(STORAGE_KEY) || DEFAULT_LANG);
                } catch (error) {
                    return DEFAULT_LANG;
                }
            }

            function writeStoredLanguage(value) {
                try {
                    localStorage.setItem(STORAGE_KEY, normalizeLanguage(value));
                } catch (error) {
                    // Ignore storage failures.
                }
            }

            function readVars(element) {
                const raw = String(element.getAttribute('data-i18n-vars') || '').trim();
                if (raw === '') {
                    return {};
                }
                try {
                    const parsed = JSON.parse(raw);
                    return parsed && typeof parsed === 'object' ? parsed : {};
                } catch (error) {
                    return {};
                }
            }

            function interpolate(template, vars) {
                return String(template || '').replace(/\{([a-zA-Z0-9_]+)\}/g, function (_, key) {
                    return Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : '';
                });
            }

            function translate(key, lang, vars, fallback) {
                const entry = key && Object.prototype.hasOwnProperty.call(translations, key) ? translations[key] : null;
                const source = entry && typeof entry === 'object' ? (entry[lang] || entry.id || entry.en || fallback || '') : (fallback || '');
                return interpolate(source, vars || {});
            }

            function applyLanguage(lang) {
                const nextLang = normalizeLanguage(lang);
                document.documentElement.lang = nextLang;
                document.querySelectorAll('[data-i18n]').forEach(function (element) {
                    const key = element.getAttribute('data-i18n');
                    const fallback = element.getAttribute('data-i18n-fallback') || element.textContent || '';
                    element.textContent = translate(key, nextLang, readVars(element), fallback);
                });
                document.querySelectorAll('[data-i18n-html]').forEach(function (element) {
                    const key = element.getAttribute('data-i18n-html');
                    const fallback = element.getAttribute('data-i18n-fallback') || element.innerHTML || '';
                    element.innerHTML = translate(key, nextLang, readVars(element), fallback);
                });
                document.querySelectorAll('[data-i18n-placeholder]').forEach(function (element) {
                    const key = element.getAttribute('data-i18n-placeholder');
                    const fallback = element.getAttribute('placeholder') || '';
                    element.setAttribute('placeholder', translate(key, nextLang, readVars(element), fallback));
                });
                document.querySelectorAll('[data-i18n-aria-label]').forEach(function (element) {
                    const key = element.getAttribute('data-i18n-aria-label');
                    const fallback = element.getAttribute('aria-label') || '';
                    element.setAttribute('aria-label', translate(key, nextLang, readVars(element), fallback));
                });
                document.querySelectorAll('[data-i18n-title]').forEach(function (element) {
                    const key = element.getAttribute('data-i18n-title');
                    const fallback = element.getAttribute('title') || '';
                    element.setAttribute('title', translate(key, nextLang, readVars(element), fallback));
                });
                document.querySelectorAll('[data-i18n-value]').forEach(function (element) {
                    const key = element.getAttribute('data-i18n-value');
                    const fallback = element.value || '';
                    element.value = translate(key, nextLang, readVars(element), fallback);
                });
                document.querySelectorAll('[data-lang-text-id][data-lang-text-en]').forEach(function (element) {
                    const value = nextLang === 'en'
                        ? (element.getAttribute('data-lang-text-en') || '')
                        : (element.getAttribute('data-lang-text-id') || '');
                    element.textContent = value;
                });
                document.querySelectorAll('[data-lang-html-id][data-lang-html-en]').forEach(function (element) {
                    const value = nextLang === 'en'
                        ? (element.getAttribute('data-lang-html-en') || '')
                        : (element.getAttribute('data-lang-html-id') || '');
                    element.innerHTML = value;
                });
                document.querySelectorAll('[data-lang-title-id][data-lang-title-en]').forEach(function (element) {
                    const value = nextLang === 'en'
                        ? (element.getAttribute('data-lang-title-en') || '')
                        : (element.getAttribute('data-lang-title-id') || '');
                    element.setAttribute('title', value);
                });
                languageButtons.forEach(function (button) {
                    const buttonLang = normalizeLanguage(button.getAttribute('data-language-option') || '');
                    button.classList.toggle('is-active', buttonLang === nextLang);
                    button.setAttribute('aria-pressed', buttonLang === nextLang ? 'true' : 'false');
                });
                window.majelisLang = {
                    current: nextLang,
                    t: function (key, vars, fallback) {
                        return translate(key, nextLang, vars || {}, fallback || '');
                    }
                };
                document.dispatchEvent(new CustomEvent('majelis:languagechange', {
                    detail: { lang: nextLang }
                }));
            }

            languageButtons.forEach(function (button) {
                button.addEventListener('click', function () {
                    const nextLang = normalizeLanguage(button.getAttribute('data-language-option') || DEFAULT_LANG);
                    writeStoredLanguage(nextLang);
                    applyLanguage(nextLang);
                });
            });

            applyLanguage(readStoredLanguage());
        })();
    </script>
    <?php
}

function display_name_text(string $value): string
{
    $value = trim($value);
    if ($value === '') {
        return '';
    }

    if (function_exists('mb_strtoupper')) {
        return mb_strtoupper($value, 'UTF-8');
    }

    return strtoupper($value);
}

function h_name(string $value): string
{
    return h(display_name_text($value));
}

function election_deadline_timestamp(): int
{
    $ts = strtotime(ELECTION_DEADLINE_END);
    return $ts === false ? 0 : $ts;
}

function is_election_closed(): bool
{
    $deadlineTs = election_deadline_timestamp();
    if ($deadlineTs <= 0) {
        return false;
    }
    return current_time() > $deadlineTs;
}

function normalize_username(string $username): string
{
    $username = trim($username);
    $username = preg_replace('/\s+/', ' ', $username);
    return is_string($username) ? $username : '';
}

function normalize_login_username(string $username): string
{
    $username = strtolower(trim($username));
    $username = preg_replace('/[^a-z0-9]/', '', $username);
    return is_string($username) ? $username : '';
}

function normalize_query_choice(string $value, array $allowed, string $default = 'all'): string
{
    $value = strtolower(trim($value));
    $default = strtolower(trim($default));
    $normalizedAllowed = [];
    foreach ($allowed as $allowedValue) {
        $allowedText = strtolower(trim((string)$allowedValue));
        if ($allowedText !== '') {
            $normalizedAllowed[$allowedText] = true;
        }
    }

    if ($value !== '' && isset($normalizedAllowed[$value])) {
        return $value;
    }

    return isset($normalizedAllowed[$default]) ? $default : (array_key_first($normalizedAllowed) ?? 'all');
}

function short_username_from_fullname(string $fullName): string
{
    $fullName = normalize_username($fullName);
    if ($fullName === '') {
        return '';
    }

    $parts = preg_split('/\s+/', $fullName) ?: [];
    if ($parts === []) {
        return '';
    }

    $firstName = normalize_login_username((string)($parts[0] ?? ''));
    $initials = '';
    for ($i = 1; $i < count($parts); $i++) {
        $nextName = normalize_login_username((string)($parts[$i] ?? ''));
        if ($nextName !== '') {
            $initials .= substr($nextName, 0, 1);
        }
    }

    $base = $firstName . $initials;
    return substr($base, 0, 32);
}

function ensure_unique_login_username(string $base, array &$used): string
{
    $base = normalize_login_username($base);
    if ($base === '') {
        $base = 'user';
    }

    $candidate = $base;
    $counter = 1;
    while (isset($used[$candidate])) {
        $candidate = $base . $counter;
        $counter++;
    }
    $used[$candidate] = true;

    return $candidate;
}

function normalize_password(string $password): string
{
    return trim($password);
}

function default_user_data(): array
{
    return [
        [
            'nama_lengkap' => 'Natanael Wijaya Tiono',
            'username' => 'natanaelwt',
            'password' => '010180',
            'asal_cabang' => 'REC Kutisari',
            'role' => 'admin',
        ]
    ];
}

function default_login_rate_data(): array
{
    return ['records' => []];
}

function ensure_directory_writable(string $dir): bool
{
    if (is_dir($dir)) {
        return is_writable($dir);
    }

    if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
        return false;
    }

    @chmod($dir, 0700);
    return is_writable($dir);
}

function append_security_block_to_htaccess(string $path, string $blockId, string $blockContent): void
{
    $begin = '# BEGIN ' . $blockId;
    $end = '# END ' . $blockId;
    $fullBlock = $begin . PHP_EOL . trim($blockContent) . PHP_EOL . $end . PHP_EOL;

    $existing = '';
    if (is_file($path)) {
        $raw = @file_get_contents($path);
        if (is_string($raw)) {
            $existing = $raw;
        }
    }

    if (strpos($existing, $begin) !== false && strpos($existing, $end) !== false) {
        $pattern = '/' . preg_quote($begin, '/') . '.*?' . preg_quote($end, '/') . '\s*/s';
        $replaced = preg_replace($pattern, $fullBlock, $existing, 1);
        if (is_string($replaced) && $replaced !== $existing) {
            @file_put_contents($path, $replaced, LOCK_EX);
        }
        return;
    }

    $prefix = $existing !== '' && substr($existing, -1) !== "\n" ? PHP_EOL : '';
    @file_put_contents($path, $existing . $prefix . $fullBlock, LOCK_EX);
}

function ensure_webroot_json_protection(): void
{
    $htaccessPath = __DIR__ . '/.htaccess';
    $block = <<<'HTACCESS'
Options -Indexes
<FilesMatch "\.json$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Deny from all
    </IfModule>
</FilesMatch>
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^\.session_store(/|$) - [F,L]
    RewriteRule (^|/)sess_[A-Za-z0-9]+$ - [F,L]
</IfModule>
HTACCESS;
    append_security_block_to_htaccess($htaccessPath, 'MAJELIS_SECURITY', $block);
}

function legacy_file_for(string $filename): string
{
    return match ($filename) {
        'users.json' => LEGACY_USER_FILE,
        'bidang.json' => LEGACY_BIDANG_FILE,
        'kandidat.json' => LEGACY_KANDIDAT_FILE,
        'pemilihan.json' => LEGACY_PEMILIHAN_FILE,
        'vote_log.json' => LEGACY_VOTE_LOG_FILE,
        'flagging.json' => LEGACY_FLAGGING_FILE,
        'wawancara_assignment.json' => LEGACY_ASSIGNMENT_FILE,
        'kesediaan_form.json' => LEGACY_KESEDIAAN_FORM_FILE,
        'scorecard_templates.json' => LEGACY_SCORECARD_TEMPLATE_FILE,
        'scorecard_submissions.json' => LEGACY_SCORECARD_SUBMISSION_FILE,
        default => '',
    };
}

function migration_sources_for(string $filename): array
{
    $sources = [];
    $legacy = legacy_file_for($filename);
    if ($legacy !== '') {
        $sources[] = $legacy;
    }

    return $sources;
}

function default_payload_for_file(string $filename): array
{
    return match ($filename) {
        'users.json' => ['users' => default_user_data()],
        'bidang.json' => ['bidang' => default_bidang_data()],
        'kandidat.json' => ['kandidat' => default_kandidat_data()],
        'pemilihan.json' => ['pemilihan' => []],
        'vote_log.json' => ['logs' => []],
        'flagging.json' => ['flags' => []],
        'wawancara_assignment.json' => ['assignments' => []],
        'kesediaan_form.json' => ['forms' => []],
        'scorecard_templates.json' => default_scorecard_templates_data(),
        'scorecard_submissions.json' => ['submissions' => []],
        'login_rate.json' => default_login_rate_data(),
        default => [],
    };
}

function read_json_file(string $path, array $fallback): array
{
    if (!is_file($path)) {
        return $fallback;
    }

    $size = @filesize($path);
    if (is_int($size) && $size > DATA_MAX_BYTES) {
        return $fallback;
    }

    $raw = @file_get_contents($path);
    if (!is_string($raw)) {
        return $fallback;
    }

    // Tolerate UTF-8 BOM produced by some editors/tools.
    if (strncmp($raw, "\xEF\xBB\xBF", 3) === 0) {
        $raw = substr($raw, 3);
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : $fallback;
}

function write_json_file_atomic(string $path, array $payload): bool
{
    $encoded = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    if (!is_string($encoded)) {
        return false;
    }

    $tmpPath = $path . '.tmp.' . random_hex(6);
    if (@file_put_contents($tmpPath, $encoded . PHP_EOL, LOCK_EX) === false) {
        return false;
    }

    @chmod($tmpPath, 0600);
    if (!@rename($tmpPath, $path)) {
        @unlink($path);
        if (!@rename($tmpPath, $path)) {
            @unlink($tmpPath);
            return false;
        }
    }

    @chmod($path, 0600);
    return true;
}

function legacy_default_timezone(): string
{
    $timezone = trim((string)($GLOBALS['MAJELIS_LEGACY_DEFAULT_TIMEZONE'] ?? ''));
    if ($timezone === '') {
        return 'UTC';
    }
    return $timezone;
}

function is_valid_timezone_name(string $timezone): bool
{
    $timezone = trim($timezone);
    if ($timezone === '') {
        return false;
    }

    try {
        new DateTimeZone($timezone);
        return true;
    } catch (Throwable $e) {
        return false;
    }
}

function parse_timezone_migration_datetime(string $value, DateTimeZone $timezone): ?DateTimeImmutable
{
    $value = trim($value);
    if ($value === '') {
        return null;
    }

    $date = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $value, $timezone);
    $errors = DateTimeImmutable::getLastErrors();
    $hasErrors = is_array($errors)
        && (((int)($errors['warning_count'] ?? 0)) > 0 || ((int)($errors['error_count'] ?? 0)) > 0);
    if (!($date instanceof DateTimeImmutable) || $hasErrors) {
        return null;
    }

    return $date;
}

function convert_datetime_timezone_value(string $value, string $sourceTimezone, string $targetTimezone): string
{
    $value = trim($value);
    if ($value === '' || $sourceTimezone === $targetTimezone) {
        return $value;
    }

    try {
        $source = new DateTimeZone($sourceTimezone);
        $target = new DateTimeZone($targetTimezone);
    } catch (Throwable $e) {
        return $value;
    }

    $date = parse_timezone_migration_datetime($value, $source);
    if (!($date instanceof DateTimeImmutable)) {
        return $value;
    }

    return $date->setTimezone($target)->format('Y-m-d H:i:s');
}

function timezone_migration_definitions(): array
{
    return [
        [
            'filename' => 'pemilihan.json',
            'collection_key' => 'pemilihan',
            'fields' => ['waktu_pemilihan'],
        ],
        [
            'filename' => 'vote_log.json',
            'collection_key' => 'logs',
            'fields' => ['timestamp'],
        ],
        [
            'filename' => 'flagging.json',
            'collection_key' => 'flags',
            'fields' => ['updated_at'],
        ],
        [
            'filename' => 'wawancara_assignment.json',
            'collection_key' => 'assignments',
            'fields' => ['updated_at'],
        ],
        [
            'filename' => 'kesediaan_form.json',
            'collection_key' => 'forms',
            'fields' => ['updated_at'],
        ],
        [
            'filename' => 'scorecard_submissions.json',
            'collection_key' => 'submissions',
            'fields' => ['submitted_at', 'updated_at'],
        ],
    ];
}

function migrate_payload_timestamps(
    array $payload,
    string $collectionKey,
    array $fields,
    string $sourceTimezone,
    string $targetTimezone
): array {
    $items = $payload[$collectionKey] ?? null;
    if (!is_array($items)) {
        return [
            'payload' => $payload,
            'changed' => false,
            'records_changed' => 0,
        ];
    }

    $changed = false;
    $recordsChanged = 0;
    foreach ($items as $index => $item) {
        if (!is_array($item)) {
            continue;
        }

        $recordChanged = false;
        foreach ($fields as $field) {
            $originalValue = trim((string)($item[$field] ?? ''));
            if ($originalValue === '') {
                continue;
            }

            $convertedValue = convert_datetime_timezone_value($originalValue, $sourceTimezone, $targetTimezone);
            if ($convertedValue === $originalValue) {
                continue;
            }

            $payload[$collectionKey][$index][$field] = $convertedValue;
            $recordChanged = true;
            $changed = true;
        }

        if ($recordChanged) {
            $recordsChanged++;
        }
    }

    return [
        'payload' => $payload,
        'changed' => $changed,
        'records_changed' => $recordsChanged,
    ];
}

function restore_timezone_migration_backup(array $writtenPaths, array $backupMap): void
{
    foreach ($writtenPaths as $writtenPath) {
        $backupPath = $backupMap[$writtenPath] ?? '';
        if (!is_string($backupPath) || $backupPath === '' || !is_file($backupPath)) {
            continue;
        }

        @copy($backupPath, $writtenPath);
        @chmod($writtenPath, 0600);
    }
}

function run_timezone_data_migration(string $dir): void
{
    static $processed = [];
    if (isset($processed[$dir])) {
        return;
    }
    $processed[$dir] = true;

    $markerPath = $dir . '/timezone_migration.json';
    if (is_file($markerPath)) {
        return;
    }

    $sourceTimezone = legacy_default_timezone();
    $targetTimezone = APP_DEFAULT_TIMEZONE;
    $markerPayload = [
        'status' => 'pending',
        'source_timezone' => $sourceTimezone,
        'target_timezone' => $targetTimezone,
        'processed_at' => date('Y-m-d H:i:s', current_time()),
        'backup_dir' => '',
        'files' => [],
    ];

    if (!is_valid_timezone_name($sourceTimezone) || !is_valid_timezone_name($targetTimezone)) {
        $markerPayload['status'] = 'skipped_invalid_timezone';
        write_json_file_atomic($markerPath, $markerPayload);
        return;
    }

    if ($sourceTimezone === $targetTimezone) {
        $markerPayload['status'] = 'skipped_same_timezone';
        write_json_file_atomic($markerPath, $markerPayload);
        return;
    }

    $pendingWrites = [];
    foreach (timezone_migration_definitions() as $definition) {
        $filename = trim((string)($definition['filename'] ?? ''));
        $collectionKey = trim((string)($definition['collection_key'] ?? ''));
        $fields = (array)($definition['fields'] ?? []);
        if ($filename === '' || $collectionKey === '' || $fields === []) {
            continue;
        }

        $path = $dir . '/' . $filename;
        if (!is_file($path)) {
            continue;
        }

        $payload = read_json_file($path, []);
        if (!is_array($payload) || $payload === []) {
            continue;
        }

        $migration = migrate_payload_timestamps($payload, $collectionKey, $fields, $sourceTimezone, $targetTimezone);
        $markerPayload['files'][] = [
            'filename' => $filename,
            'records_changed' => (int)($migration['records_changed'] ?? 0),
            'status' => !empty($migration['changed']) ? 'migrated' : 'unchanged',
        ];

        if (!empty($migration['changed'])) {
            $pendingWrites[] = [
                'filename' => $filename,
                'path' => $path,
                'payload' => (array)($migration['payload'] ?? $payload),
            ];
        }
    }

    if ($pendingWrites === []) {
        $markerPayload['status'] = 'no_changes';
        write_json_file_atomic($markerPath, $markerPayload);
        return;
    }

    $backupDirName = 'backup_timezone_migration_' . date('Ymd_His', current_time());
    $backupDir = $dir . '/' . $backupDirName;
    if (!ensure_directory_writable($backupDir)) {
        return;
    }
    @chmod($backupDir, 0700);

    $backupMap = [];
    foreach ($pendingWrites as $writeItem) {
        $sourcePath = (string)($writeItem['path'] ?? '');
        $backupPath = $backupDir . '/' . (string)($writeItem['filename'] ?? basename($sourcePath));
        if ($sourcePath === '' || !is_file($sourcePath) || !@copy($sourcePath, $backupPath)) {
            return;
        }
        @chmod($backupPath, 0600);
        $backupMap[$sourcePath] = $backupPath;
    }

    $writtenPaths = [];
    foreach ($pendingWrites as $writeItem) {
        $path = (string)($writeItem['path'] ?? '');
        $payload = (array)($writeItem['payload'] ?? []);
        if ($path === '' || !write_json_file_atomic($path, $payload)) {
            restore_timezone_migration_backup($writtenPaths, $backupMap);
            return;
        }
        $writtenPaths[] = $path;
    }

    $markerPayload['status'] = 'migrated';
    $markerPayload['backup_dir'] = $backupDirName;
    write_json_file_atomic($markerPath, $markerPayload);
}

function is_password_hash_value(string $value): bool
{
    return preg_match('/^\$(2y|2a|argon2id|argon2i)\$/', $value) === 1;
}

function upgrade_user_password_hashes(): void
{
    $file = user_file_path();
    $data = read_json_file($file, ['users' => default_user_data()]);
    if (!isset($data['users']) || !is_array($data['users'])) {
        return;
    }

    $changed = false;
    foreach ($data['users'] as $idx => $item) {
        if (!is_array($item)) {
            continue;
        }

        $password = normalize_password((string)($item['password'] ?? ''));
        if ($password === '' || is_password_hash_value($password)) {
            continue;
        }

        $hashed = password_hash($password, PASSWORD_DEFAULT);
        if (!is_string($hashed) || $hashed === '') {
            continue;
        }

        $data['users'][$idx]['password'] = $hashed;
        $changed = true;
    }

    if ($changed) {
        write_json_file_atomic($file, $data);
    }
}

function bootstrap_data_storage(string $dir): void
{
    static $bootstrapped = [];
    if (isset($bootstrapped[$dir])) {
        return;
    }

    ensure_webroot_json_protection();
    $requiredFiles = [
        'users.json',
        'bidang.json',
        'kandidat.json',
        'pemilihan.json',
        'vote_log.json',
        'flagging.json',
        'wawancara_assignment.json',
        'kesediaan_form.json',
        'scorecard_templates.json',
        'scorecard_submissions.json',
        'login_rate.json',
    ];

    foreach ($requiredFiles as $filename) {
        $target = $dir . '/' . $filename;
        if (is_file($target)) {
            @chmod($target, 0600);
            continue;
        }

        $sourceFile = '';
        $sourceData = [];
        $migrated = false;
        foreach (migration_sources_for($filename) as $candidateSource) {
            if (!is_string($candidateSource) || $candidateSource === '') {
                continue;
            }
            if (!is_file($candidateSource)) {
                continue;
            }

            $decodedSource = read_json_file($candidateSource, []);
            if ($decodedSource !== []) {
                $sourceFile = $candidateSource;
                $sourceData = $decodedSource;
                $migrated = true;
                break;
            }
        }

        $payload = $migrated ? $sourceData : default_payload_for_file($filename);
        if (write_json_file_atomic($target, $payload) && $migrated) {
            $legacyFile = legacy_file_for($filename);
            if ($legacyFile !== '' && $sourceFile === $legacyFile && is_file($legacyFile)) {
                @unlink($legacyFile);
            }
        }
    }

    $bootstrapped[$dir] = true;
}

function secure_data_dir(): string
{
    static $resolved = null;
    if (is_string($resolved)) {
        return $resolved;
    }

    $resolved = PRIMARY_DATA_DIR;
    if (!ensure_directory_writable($resolved)) {
        http_response_code(500);
        exit('500 - Folder penyimpanan utama tidak tersedia: ' . PRIMARY_DATA_DIR);
    }

    bootstrap_data_storage($resolved);
    run_timezone_data_migration($resolved);
    return $resolved;
}

function user_file_path(): string
{
    return secure_data_dir() . '/users.json';
}

function bidang_file_path(): string
{
    return secure_data_dir() . '/bidang.json';
}

function kandidat_file_path(): string
{
    return secure_data_dir() . '/kandidat.json';
}

function pemilihan_file_path(): string
{
    return secure_data_dir() . '/pemilihan.json';
}

function vote_log_file_path(): string
{
    return secure_data_dir() . '/vote_log.json';
}

function login_rate_file_path(): string
{
    return secure_data_dir() . '/login_rate.json';
}

function flagging_file_path(): string
{
    return secure_data_dir() . '/flagging.json';
}

function wawancara_assignment_file_path(): string
{
    return secure_data_dir() . '/wawancara_assignment.json';
}

function kesediaan_form_file_path(): string
{
    return secure_data_dir() . '/kesediaan_form.json';
}

function scorecard_template_file_path(): string
{
    return secure_data_dir() . '/scorecard_templates.json';
}

function scorecard_submission_file_path(): string
{
    return secure_data_dir() . '/scorecard_submissions.json';
}

function load_user_data(): array
{
    $fallback = default_user_data();
    upgrade_user_password_hashes();
    $decoded = read_json_file(user_file_path(), ['users' => $fallback]);
    if (!is_array($decoded) || !isset($decoded['users']) || !is_array($decoded['users'])) {
        return $fallback;
    }

    $result = [];
    foreach ($decoded['users'] as $item) {
        if (!is_array($item)) {
            continue;
        }

        $rawNamaLengkap = normalize_username((string)($item['nama_lengkap'] ?? ''));
        $rawUsername = normalize_username((string)($item['username'] ?? ''));
        if ($rawNamaLengkap === '') {
            $rawNamaLengkap = $rawUsername;
        }

        $loginUsername = '';
        if ($rawUsername !== '' && strpos($rawUsername, ' ') === false) {
            $loginUsername = normalize_login_username($rawUsername);
        }
        if ($loginUsername === '') {
            $loginUsername = short_username_from_fullname($rawNamaLengkap);
        }
        $loginUsername = normalize_login_username($loginUsername);

        $password = normalize_password((string)($item['password'] ?? ''));
        $asalCabang = trim((string)($item['asal_cabang'] ?? ''));
        $roles = user_roles_from_record($item);
        $role = (string)($roles[0] ?? 'user');

        if ($rawNamaLengkap === '' || $loginUsername === '' || $password === '' || $asalCabang === '') {
            continue;
        }

        $result[] = [
            'nama_lengkap' => $rawNamaLengkap,
            'username' => $loginUsername,
            'password' => $password,
            'asal_cabang' => $asalCabang,
            'role' => $role,
            'roles' => $roles,
        ];
    }

    return $result !== [] ? $result : $fallback;
}

function verify_user_password(string $inputPassword, string $storedPassword): bool
{
    if ($storedPassword === '') {
        return false;
    }

    if (is_password_hash_value($storedPassword)) {
        return password_verify($inputPassword, $storedPassword);
    }

    return hash_equals($storedPassword, $inputPassword);
}

function find_user_for_login(array $users, string $username, string $password): ?array
{
    $username = normalize_login_username($username);
    foreach ($users as $user) {
        if (!is_array($user)) {
            continue;
        }

        $storedUsername = normalize_login_username((string)($user['username'] ?? ''));
        $storedPassword = normalize_password((string)($user['password'] ?? ''));
        if (hash_equals($storedUsername, $username) && verify_user_password($password, $storedPassword)) {
            return $user;
        }
    }

    return null;
}

function get_user_cabang_list(array $users): array
{
    $set = [];
    foreach ($users as $user) {
        if (!is_array($user)) {
            continue;
        }

        $cabang = trim((string)($user['asal_cabang'] ?? ''));
        if ($cabang !== '') {
            $set[$cabang] = true;
        }
    }

    $list = array_keys($set);
    sort($list, SORT_NATURAL | SORT_FLAG_CASE);
    return $list;
}

function default_bidang_description(string $title): string
{
    return bidang_default_description_text($title, 'id');
}

function bidang_base_title_translations(): array
{
    return [
        'Ketua Majelis' => ['id' => 'Ketua Majelis', 'en' => 'Chairman of Elder'],
        'Sekretaris Majelis' => ['id' => 'Sekretaris Majelis', 'en' => 'Secretary'],
        'Bendahara Majelis' => ['id' => 'Bendahara Majelis', 'en' => 'Treasurer'],
        'Majelis Bidang Pemuridan' => ['id' => 'Majelis Bidang Pemuridan', 'en' => 'Elder of Discipleship'],
        'Majelis Bidang Misi' => ['id' => 'Majelis Bidang Misi', 'en' => 'Elder of Mission'],
        'Majelis Bidang Diakonia' => ['id' => 'Majelis Bidang Diakonia', 'en' => 'Elder of Mercy Ministry'],
        'Majelis Bidang Ibadah' => ['id' => 'Majelis Bidang Ibadah', 'en' => 'Elder of Worship'],
        'Ketua Pengurus Lokal' => ['id' => 'Ketua Pengurus Lokal', 'en' => 'Leader for Local Branch'],
    ];
}

function bidang_default_description_map(): array
{
    return [
        'Ketua Majelis' => [
            'id' => 'Bertanggung jawab untuk memimpin, memfasilitasi, dan mengoordinasikan fungsi Majelis Jemaat (Penatua dan Diaken) agar berjalan sesuai dengan tata gereja dan visi misi gereja. Ketua Majelis memastikan bahwa seluruh keputusan dan arah gereja tetap setia pada doktrin Reformed, berpusat pada Injil (Gospel-Centered), dan dilaksanakan dengan tata kelola yang rapi dan transparan.',
            'en' => 'Responsible for leading, facilitating, and coordinating the functions of the church elders and deacons so that they operate in accordance with church order and the church\'s vision and mission. The Chairman of Elder ensures that every decision and direction of the church remains faithful to Reformed doctrine, centered on the Gospel (Gospel-Centered), and carried out with orderly and transparent governance.',
        ],
        'Sekretaris Majelis' => [
            'id' => 'Bertanggung jawab mengelola seluruh administrasi, dokumentasi, korespondensi, dan arsip gerejawi. Sekretaris memastikan bahwa sejarah gereja tercatat rapi, keputusan majelis terdokumentasi akurat, dan operasional organisasi berjalan sesuai dengan Tata Gereja yang berlaku.',
            'en' => 'Responsible for managing all administration, documentation, correspondence, and church archives. The Secretary ensures that the history of the church is recorded properly, elder decisions are documented accurately, and organizational operations run in accordance with the applicable Church Order.',
        ],
        'Bendahara Majelis' => [
            'id' => 'Bertanggung jawab mengelola keuangan gereja dengan integritas mutlak, transparansi, dan prinsip penatalayanan Alkitabiah. Bendahara memastikan bahwa setiap sen uang persembahan jemaat dikelola secara bijaksana, dicatat dengan akurat, dan disalurkan untuk mendukung pekerjaan pemberitaan Injil dan pelayanan kasih.',
            'en' => 'Responsible for managing church finances with absolute integrity, transparency, and the principles of Biblical stewardship. The Treasurer ensures that every cent of the congregation\'s offerings is managed wisely, recorded accurately, and allocated to support the work of proclaiming the Gospel and ministries of mercy.',
        ],
        'Majelis Bidang Pemuridan' => [
            'id' => 'Merancang dan mengevaluasi strategi jalur pertumbuhan jemaat yang sistematis mulai dari pengunjung baru hingga menjadi pemurid yang mampu melatih orang lain, dengan memastikan seluruh materi pendidikan, kurikulum, dan proses pendampingan berakar kuat pada doktrin Reformed, berpusat pada Injil, serta membekali jemaat dengan wawasan dunia Kristen yang utuh.',
            'en' => 'Designs and evaluates a systematic congregational growth pathway strategy, from new visitors to becoming disciples who are able to train others, while ensuring that all educational materials, curriculum, and mentoring processes are firmly rooted in Reformed doctrine, centered on the Gospel, and equip the congregation with a comprehensive Christian worldview.',
        ],
        'Majelis Bidang Misi' => [
            'id' => 'Bertanggung jawab merumuskan strategi, mengelola, dan mengawasi pelaksanaan Amanat Agung (Matius 28:19-20) di tingkat lokal (Penginjilan) dan lintas budaya (Misi/Zending). Ketua Bidang Misi memastikan gereja tidak menjadi "klub rohani" yang tertutup, melainkan komunitas yang bergerak keluar untuk memberitakan Injil Kerajaan Allah, baik melalui perkataan maupun perbuatan.',
            'en' => 'Responsible for formulating strategy, managing, and overseeing the implementation of the Great Commission (Matthew 28:19-20) at the local level (Evangelism) and across cultures (Mission/Zending). The Elder of Mission ensures that the church does not become a closed "spiritual club," but rather a community that moves outward to proclaim the Gospel of the Kingdom of God, both through word and deed.',
        ],
        'Majelis Bidang Diakonia' => [
            'id' => 'Bertanggung jawab mengelola pelayanan kasih dan bantuan sosial gereja. Ketua Bidang Diakonia memimpin para diaken untuk mendeteksi, memverifikasi, dan merespons kebutuhan jemaat (janda, yatim piatu, orang sakit, yang kekurangan ekonomi) dengan bijaksana, serta memastikan fasilitas fisik gereja siap mendukung ibadah sebagai wujud pelayanan yang nyata.',
            'en' => 'Responsible for managing the church\'s mercy ministry and social assistance. The Elder of Mercy Ministry leads the deacons to detect, verify, and respond wisely to the needs of the congregation (widows, orphans, the sick, and those with economic hardship), while also ensuring that the church\'s physical facilities are ready to support worship as a tangible expression of ministry.',
        ],
        'Majelis Bidang Ibadah' => [
            'id' => 'Bertanggung jawab merancang dan mengawasi seluruh tata ibadah (liturgi) agar teologis, tertib, dan berpusat pada Injil. Ketua Bidang Ibadah memastikan bahwa nyanyian, doa, dan sakramen yang dilakukan bukan untuk "menghibur" jemaat, melainkan untuk memuliakan Allah dan membangun iman jemaat melalui sarana anugerah yang benar.',
            'en' => 'Responsible for designing and overseeing the entire order of worship (liturgy) so that it is theological, orderly, and Gospel-centered. The Elder of Worship ensures that the songs, prayers, and sacraments carried out are not meant to "entertain" the congregation, but to glorify God and build the faith of the congregation through the proper means of grace.',
        ],
        'Ketua Pengurus Lokal' => [
            'id' => 'Bertanggung jawab memimpin operasional dan penggembalaan di tingkat wilayah/cabang sesuai arahan Majelis Pusat. Ketua Pengurus memastikan bahwa visi besar gereja "mendarat" dan terimplementasi secara kontekstual di wilayahnya, serta menciptakan persekutuan yang hangat di mana setiap jemaat merasa diperhatikan dan bertumbuh.',
            'en' => 'Responsible for leading operations and shepherding at the regional/branch level in accordance with the direction of the central elders. The Leader for Local Branch ensures that the church\'s larger vision "lands" and is implemented contextually in the branch, while also creating a warm fellowship where every congregant feels cared for and grows.',
        ],
    ];
}

function bidang_translate_main_title(string $title, string $language = 'id'): string
{
    $language = strtolower(trim($language)) === 'en' ? 'en' : 'id';
    $map = bidang_base_title_translations();
    if (isset($map[$title][$language])) {
        return (string)$map[$title][$language];
    }
    return $title;
}

function bidang_display_title(string $title, string $language = 'id'): string
{
    $parts = bidang_title_parts($title);
    $main = trim((string)($parts['main'] ?? ''));
    $cabang = trim((string)($parts['cabang'] ?? ''));
    if ($main === '') {
        return '';
    }

    $translatedMain = bidang_translate_main_title($main, $language);
    if ($cabang === '') {
        return $translatedMain;
    }

    return $translatedMain . ' - ' . $cabang;
}

function bidang_default_description_text(string $title, string $language = 'id'): string
{
    $language = strtolower(trim($language)) === 'en' ? 'en' : 'id';
    $parts = bidang_title_parts($title);
    $main = trim((string)($parts['main'] ?? $title));
    $map = bidang_default_description_map();
    if (isset($map[$main][$language])) {
        return (string)$map[$main][$language];
    }

    if ($language === 'en') {
        return 'Description for ' . bidang_display_title($title, 'en') . '.';
    }

    return 'Deskripsi untuk ' . bidang_display_title($title, 'id') . '.';
}

function bidang_display_description(array $bidangItem, string $language = 'id'): string
{
    $language = strtolower(trim($language)) === 'en' ? 'en' : 'id';
    $title = trim((string)($bidangItem['title'] ?? ''));
    $description = trim((string)($bidangItem['description'] ?? ''));
    $descriptionEn = trim((string)($bidangItem['description_en'] ?? ''));
    if ($description === '') {
        $description = bidang_default_description_text($title, 'id');
    }
    if ($descriptionEn === '') {
        $descriptionEn = bidang_default_description_text($title, 'en');
    }

    return $language === 'en' ? $descriptionEn : $description;
}

function is_legacy_bidang_placeholder_description(string $title, string $description): bool
{
    $title = trim($title);
    $description = trim($description);
    if ($title === '' || $description === '') {
        return false;
    }

    return $description === ('Template deskripsi sementara untuk ' . $title . '. Silakan ubah isi deskripsi sesuai kebutuhan.');
}

function is_ketua_pengurus_lokal_bidang(string $title): bool
{
    $normalized = strtolower(trim($title));
    $normalized = preg_replace('/\s+/', ' ', $normalized);
    if (!is_string($normalized) || $normalized === '') {
        return false;
    }

    return strpos($normalized, 'ketua pengurus lokal') === 0;
}

function extract_ketua_pengurus_lokal_cabang(string $title): string
{
    if (!is_ketua_pengurus_lokal_bidang($title)) {
        return '';
    }

    $rest = preg_replace('/^ketua\s+pengurus\s+lokal/i', '', trim($title));
    $rest = is_string($rest) ? trim($rest) : '';
    if ($rest === '') {
        return '';
    }

    if (preg_match('/^\[(.+)\]$/', $rest, $matches) === 1) {
        return trim((string)($matches[1] ?? ''));
    }
    if (preg_match('/^-\s*(.+)$/', $rest, $matches) === 1) {
        return trim((string)($matches[1] ?? ''));
    }
    if (preg_match('/^\((.+)\)$/', $rest, $matches) === 1) {
        return trim((string)($matches[1] ?? ''));
    }

    $rest = ltrim($rest, "- \t");
    return trim($rest);
}

function bidang_title_parts(string $title): array
{
    $title = trim($title);
    if ($title === '') {
        return [
            'main' => '',
            'cabang' => '',
        ];
    }

    if (!is_ketua_pengurus_lokal_bidang($title)) {
        return [
            'main' => $title,
            'cabang' => '',
        ];
    }

    return [
        'main' => 'Ketua Pengurus Lokal',
        'cabang' => extract_ketua_pengurus_lokal_cabang($title),
    ];
}

function bidang_title_for_cabang(string $title, string $asalCabang): string
{
    $title = trim($title);
    if ($title === '') {
        return '';
    }
    if (!is_ketua_pengurus_lokal_bidang($title)) {
        return $title;
    }

    $asalCabang = trim($asalCabang);
    if ($asalCabang === '' || $asalCabang === '-') {
        $asalCabang = extract_ketua_pengurus_lokal_cabang($title);
    }
    if ($asalCabang === '' || $asalCabang === '-') {
        return 'Ketua Pengurus Lokal';
    }

    return 'Ketua Pengurus Lokal - ' . $asalCabang;
}

function normalize_vote_bidang_title(string $bidang, string $asalCabangUser): string
{
    return bidang_title_for_cabang($bidang, $asalCabangUser);
}

function personalize_bidang_list_for_cabang(array $bidangList, string $asalCabang): array
{
    $result = [];
    foreach ($bidangList as $item) {
        if (!is_array($item)) {
            continue;
        }

        $title = bidang_title_for_cabang((string)($item['title'] ?? ''), $asalCabang);
        if ($title === '') {
            continue;
        }

        $item['title'] = $title;
        $result[] = $item;
    }

    return $result;
}

function default_bidang_data(): array
{
    $titles = [
        'Ketua Majelis',
        'Sekretaris Majelis',
        'Bendahara Majelis',
        'Majelis Bidang Pemuridan',
        'Majelis Bidang Misi',
        'Majelis Bidang Diakonia',
        'Majelis Bidang Ibadah',
        'Ketua Pengurus Lokal',
    ];

    $result = [];
    foreach ($titles as $title) {
        $result[] = [
            'title' => $title,
            'description' => default_bidang_description($title),
            'description_en' => bidang_default_description_text($title, 'en'),
        ];
    }

    return $result;
}

function load_bidang_data(): array
{
    $fallback = default_bidang_data();
    $decoded = read_json_file(bidang_file_path(), ['bidang' => $fallback]);
    if (!is_array($decoded) || !isset($decoded['bidang']) || !is_array($decoded['bidang'])) {
        return $fallback;
    }

    $result = [];
    foreach ($decoded['bidang'] as $item) {
        if (is_string($item)) {
            $title = trim($item);
            if ($title === '') {
                continue;
            }

            $result[] = [
                'title' => $title,
                'description' => default_bidang_description($title),
                'description_en' => bidang_default_description_text($title, 'en'),
            ];
            continue;
        }

        if (!is_array($item)) {
            continue;
        }

        $title = trim((string)($item['title'] ?? ''));
        if ($title === '') {
            continue;
        }

        $description = trim((string)($item['description'] ?? ''));
        if ($description === '') {
            $description = default_bidang_description($title);
        } elseif (is_legacy_bidang_placeholder_description($title, $description)) {
            $description = bidang_default_description_text($title, 'id');
        }
        $descriptionEn = trim((string)($item['description_en'] ?? ''));
        if ($descriptionEn === '') {
            $descriptionEn = bidang_default_description_text($title, 'en');
        }

        $result[] = [
            'title' => $title,
            'description' => $description,
            'description_en' => $descriptionEn,
        ];
    }

    return $result !== [] ? $result : $fallback;
}

function default_scorecard_final_ranges(): array
{
    return [
        ['min' => 1.00, 'max' => 1.80, 'label' => 'Sangat Tidak Direkomendasikan'],
        ['min' => 1.81, 'max' => 2.60, 'label' => 'Tidak Direkomendasikan'],
        ['min' => 2.61, 'max' => 3.40, 'label' => 'Dipertimbangkan Kembali'],
        ['min' => 3.41, 'max' => 4.20, 'label' => 'Direkomendasikan'],
        ['min' => 4.21, 'max' => 5.00, 'label' => 'Sangat Direkomendasikan'],
    ];
}

function default_scorecard_decision_options(): array
{
    return [
        'Sangat Direkomendasikan',
        'Direkomendasikan dengan Catatan',
        'Dipertimbangkan Kembali (Hold)',
        'Tidak Direkomendasikan',
    ];
}

function default_scorecard_ketua_majelis_sections(): array
{
    return [
        [
            'id' => 'A',
            'title' => 'Kesesuaian Teologis & Visi',
            'focus' => 'Apakah teologi kandidat hidup dan berdampak pada cara pandangnya terhadap pelayanan?',
            'weight' => 0.30,
            'note_label' => 'Catatan Bagian A',
            'questions' => [
                [
                    'id' => 'A1',
                    'label' => 'Definisi Gospel-Centered',
                    'low_indicator' => [
                        'Jawaban bersifat moralis atau legalis.',
                        'Melihat Injil hanya sebagai pintu masuk keselamatan, bukan pola hidup.',
                    ],
                    'high_indicator' => [
                        'Memahami Injil sebagai kuasa yang mengubahkan, bukan sekadar aturan.',
                        'Kasih karunia Allah menjadi motivasi pelayanan, bukan rasa bersalah atau kewajiban semata.',
                    ],
                ],
                [
                    'id' => 'A2',
                    'label' => 'Kedaulatan Allah vs Tanggung Jawab',
                    'low_indicator' => [
                        'Terlalu pasif atau fatalis dengan alasan menunggu Tuhan.',
                        'Terlalu mengandalkan strategi manusia tanpa doa dan ketergantungan pada Tuhan.',
                    ],
                    'high_indicator' => [
                        'Seimbang antara perencanaan yang matang dan penyerahan pada providensia Allah.',
                        'Melihat strategi sebagai wujud tanggung jawab di hadapan Tuhan.',
                    ],
                ],
                [
                    'id' => 'A3',
                    'label' => 'Identitas Reformed',
                    'low_indicator' => [
                        'Hanya menguasai istilah akademis namun kaku atau sombong dalam aplikasinya.',
                        'Doktrin tidak terlihat membentuk penggembalaan dan kerendahan hati.',
                    ],
                    'high_indicator' => [
                        'Memegang teguh doktrin Reformed dengan hati yang hangat dan rendah hati.',
                        'Mampu mengaplikasikan doktrin dalam penggembalaan yang nyata.',
                    ],
                ],
                [
                    'id' => 'A4',
                    'label' => 'Respon Isu Kontemporer',
                    'low_indicator' => [
                        'Jawaban pragmatis ikut arus zaman atau sangat menghakimi tanpa kasih.',
                        'Tidak memiliki landasan Alkitab yang kuat.',
                    ],
                    'high_indicator' => [
                        'Berpegang pada otoritas Alkitab namun menyampaikannya dengan hikmat dan kasih.',
                        'Mampu speaking truth in love tanpa mengorbankan prinsip.',
                    ],
                ],
            ],
        ],
        [
            'id' => 'B',
            'title' => 'Karakter & Spiritualitas',
            'focus' => 'Kualifikasi 1 Timotius 3 dan Titus 1. Apakah ada buah Roh yang nyata?',
            'weight' => 0.30,
            'note_label' => 'Catatan Bagian B',
            'questions' => [
                [
                    'id' => 'B1',
                    'label' => 'Kehidupan Doa Pribadi',
                    'low_indicator' => [
                        'Jawaban klise atau umum dan terlihat mengandalkan kekuatan sendiri.',
                        'Tidak dapat menceritakan pengalaman rohani pribadi yang aktual.',
                    ],
                    'high_indicator' => [
                        'Jujur, rutin, dan menjadikan doa sebagai napas pelayanan.',
                        'Terlihat memiliki relasi yang hidup dengan Tuhan.',
                    ],
                ],
                [
                    'id' => 'B2',
                    'label' => 'Kegagalan & Pertobatan',
                    'low_indicator' => [
                        'Defensif, menyalahkan orang lain, atau mengaku tidak pernah gagal.',
                        'Tidak terlihat adanya pertobatan yang hancur hati.',
                    ],
                    'high_indicator' => [
                        'Terbuka mengakui kelemahan dan tidak menyembunyikan dosa.',
                        'Menunjukkan bagaimana Injil memulihkan dan menguatkan untuk bangkit.',
                    ],
                ],
                [
                    'id' => 'B3',
                    'label' => 'Manajemen Keluarga',
                    'low_indicator' => [
                        'Menganggap pelayanan gereja lebih suci daripada keluarga.',
                        'Istri atau anak terlihat sebagai beban pelayanan.',
                    ],
                    'high_indicator' => [
                        'Menempatkan keluarga sebagai pelayanan utama.',
                        'Ada keseimbangan sehat dan dukungan penuh dari keluarga.',
                    ],
                ],
                [
                    'id' => 'B4',
                    'label' => 'Ketahanan Terhadap Kritik',
                    'low_indicator' => [
                        'Menjadi pahit, defensif, atau merasa diserang secara personal.',
                        'Tidak stabil saat menerima kritik dari sesama majelis.',
                    ],
                    'high_indicator' => [
                        'Merespons kritik dengan hikmat dan penguasaan diri.',
                        'Tetap stabil secara rohani di tengah perbedaan pendapat.',
                    ],
                ],
            ],
        ],
        [
            'id' => 'C',
            'title' => 'Kepemimpinan & Tata Kelola',
            'focus' => 'Kompetensi sebagai yang utama di antara yang sederajat.',
            'weight' => 0.25,
            'note_label' => 'Catatan Bagian C',
            'questions' => [
                [
                    'id' => 'C1',
                    'label' => 'Gaya Kepemimpinan',
                    'low_indicator' => [
                        'Otoriter, dominan, atau sebaliknya pasif dan takut mengambil keputusan.',
                        'Cenderung menjadi people pleaser atau one man show.',
                    ],
                    'high_indicator' => [
                        'Fasilitator yang baik dan mampu membangun konsensus.',
                        'Tegas namun lembut dalam memimpin.',
                    ],
                ],
                [
                    'id' => 'C2',
                    'label' => 'Pengambilan Keputusan',
                    'low_indicator' => [
                        'Memaksakan pendapat atau terlalu bimbang sehingga tidak ada keputusan.',
                        'Tidak menghargai proses kolektif-kolegial.',
                    ],
                    'high_indicator' => [
                        'Memandu proses keputusan secara kolektif-kolegial.',
                        'Berani mengambil keputusan sulit setelah mendengar masukan.',
                    ],
                ],
                [
                    'id' => 'C3',
                    'label' => 'Resolusi Konflik',
                    'low_indicator' => [
                        'Menghindari konflik atau memihak tanpa objektivitas.',
                        'Emosional dan tidak mencari akar masalah.',
                    ],
                    'high_indicator' => [
                        'Mengedepankan rekonsiliasi dan objektivitas.',
                        'Mengutamakan keutuhan tubuh Kristus dan kebenaran.',
                    ],
                ],
                [
                    'id' => 'C4',
                    'label' => 'Delegasi & Kaderisasi',
                    'low_indicator' => [
                        'One-man show dan sulit mempercayai orang lain.',
                        'Tidak memikirkan penerus atau pemimpin muda.',
                    ],
                    'high_indicator' => [
                        'Mampu mempercayakan tugas sesuai karunia rekan lain.',
                        'Aktif memberdayakan dan membimbing pemimpin muda.',
                    ],
                ],
            ],
        ],
        [
            'id' => 'D',
            'title' => 'Studi Kasus / Penyelesaian Masalah',
            'focus' => 'Hikmat praktis dalam situasi nyata.',
            'weight' => 0.15,
            'note_label' => 'Catatan Bagian D',
            'questions' => [
                [
                    'id' => 'D1',
                    'label' => 'Disiplin Gereja',
                    'low_indicator' => [
                        'Terlalu kejam tanpa pendampingan atau terlalu permisif demi alasan kasih.',
                        'Tidak menyeimbangkan kekudusan dan pemulihan.',
                    ],
                    'high_indicator' => [
                        'Seimbang antara kekudusan Allah dan kasih pengampunan.',
                        'Prosedural sesuai tata gereja namun tetap pastoral dan memulihkan.',
                    ],
                ],
                [
                    'id' => 'D2',
                    'label' => 'Visi vs Tradisi',
                    'low_indicator' => [
                        'Memaksakan perubahan tanpa peduli jemaat lama atau menyerah total pada tradisi yang kaku.',
                        'Tidak komunikatif dalam proses perubahan.',
                    ],
                    'high_indicator' => [
                        'Mencari jalan tengah tanpa mengorbankan prinsip.',
                        'Sabar dalam perubahan dan komunikatif terhadap seluruh pihak.',
                    ],
                ],
            ],
        ],
    ];
}

function default_scorecard_generic_sections(): array
{
    return [
        [
            'id' => 'A',
            'title' => 'Panggilan & Visi Pelayanan',
            'focus' => 'Seberapa jelas kandidat memahami panggilan dan arah pelayanan pada bidang ini.',
            'weight' => 0.30,
            'note_label' => 'Catatan Bagian A',
            'questions' => [
                [
                    'id' => 'A1',
                    'label' => 'Pemahaman Peran Bidang',
                    'low_indicator' => [
                        'Tidak memahami tanggung jawab inti bidang yang dilamar.',
                        'Jawaban terlalu umum dan tidak menyentuh kebutuhan pelayanan nyata.',
                    ],
                    'high_indicator' => [
                        'Memahami mandat, prioritas, dan tantangan inti bidang secara jelas.',
                        'Mampu menjelaskan kontribusi spesifik yang relevan dengan bidang.',
                    ],
                ],
                [
                    'id' => 'A2',
                    'label' => 'Visi Pelayanan',
                    'low_indicator' => [
                        'Tidak memiliki arah pelayanan yang jelas.',
                        'Visi hanya berupa slogan tanpa langkah yang realistis.',
                    ],
                    'high_indicator' => [
                        'Memiliki visi yang jelas, realistis, dan terukur.',
                        'Visi selaras dengan kebutuhan jemaat dan arah gereja.',
                    ],
                ],
                [
                    'id' => 'A3',
                    'label' => 'Landasan Alkitabiah',
                    'low_indicator' => [
                        'Jawaban pragmatis tanpa dasar Alkitab yang kuat.',
                        'Sulit menjelaskan alasan rohani di balik arah pelayanannya.',
                    ],
                    'high_indicator' => [
                        'Menunjukkan pemikiran yang berakar pada Firman Tuhan.',
                        'Mampu menghubungkan prinsip Alkitab dengan praktik pelayanan.',
                    ],
                ],
                [
                    'id' => 'A4',
                    'label' => 'Keselarasan dengan Tim Majelis',
                    'low_indicator' => [
                        'Berpikir sangat individual dan kurang terbuka pada arah bersama.',
                        'Sulit melihat bidangnya sebagai bagian dari tubuh yang lebih besar.',
                    ],
                    'high_indicator' => [
                        'Melihat bidangnya sebagai bagian dari arah majelis secara utuh.',
                        'Siap bekerja selaras dengan keputusan dan prioritas bersama.',
                    ],
                ],
            ],
        ],
        [
            'id' => 'B',
            'title' => 'Karakter & Spiritualitas',
            'focus' => 'Buah Roh, integritas, dan kedewasaan rohani kandidat.',
            'weight' => 0.30,
            'note_label' => 'Catatan Bagian B',
            'questions' => [
                [
                    'id' => 'B1',
                    'label' => 'Kehidupan Rohani Pribadi',
                    'low_indicator' => [
                        'Jawaban normatif, sulit menunjukkan relasi pribadi dengan Tuhan.',
                        'Terlihat bergantung pada kemampuan diri sendiri.',
                    ],
                    'high_indicator' => [
                        'Menunjukkan kebiasaan doa dan pembacaan Firman yang hidup.',
                        'Memperlihatkan ketergantungan yang nyata kepada Tuhan.',
                    ],
                ],
                [
                    'id' => 'B2',
                    'label' => 'Kerendahan Hati & Teachability',
                    'low_indicator' => [
                        'Defensif terhadap koreksi dan sulit diajar.',
                        'Cenderung merasa paling benar atau paling mampu.',
                    ],
                    'high_indicator' => [
                        'Mudah menerima masukan dan mau belajar dari orang lain.',
                        'Menunjukkan kerendahan hati dalam proses bertumbuh.',
                    ],
                ],
                [
                    'id' => 'B3',
                    'label' => 'Integritas & Akuntabilitas',
                    'low_indicator' => [
                        'Tidak konsisten antara perkataan dan tindakan.',
                        'Menghindari pertanggungjawaban atau transparansi.',
                    ],
                    'high_indicator' => [
                        'Menjaga integritas dalam tugas dan relasi.',
                        'Terbuka terhadap akuntabilitas dan proses evaluasi.',
                    ],
                ],
                [
                    'id' => 'B4',
                    'label' => 'Pengelolaan Diri & Keluarga',
                    'low_indicator' => [
                        'Kesulitan mengatur prioritas pribadi, keluarga, dan pelayanan.',
                        'Lingkungan terdekat tidak mendukung pelayanan.',
                    ],
                    'high_indicator' => [
                        'Mampu menata prioritas secara sehat.',
                        'Ada dukungan dan keseimbangan yang baik antara keluarga dan pelayanan.',
                    ],
                ],
            ],
        ],
        [
            'id' => 'C',
            'title' => 'Kompetensi Pelayanan & Kolaborasi',
            'focus' => 'Kemampuan bekerja, memimpin, dan mengeksekusi tanggung jawab bidang.',
            'weight' => 0.25,
            'note_label' => 'Catatan Bagian C',
            'questions' => [
                [
                    'id' => 'C1',
                    'label' => 'Komunikasi & Kerja Tim',
                    'low_indicator' => [
                        'Kurang mampu mendengar atau menyampaikan ide dengan jelas.',
                        'Sulit bekerja sama dengan tim dan lintas bidang.',
                    ],
                    'high_indicator' => [
                        'Komunikatif, mendengar dengan baik, dan mudah berkolaborasi.',
                        'Mampu menjaga relasi kerja yang sehat.',
                    ],
                ],
                [
                    'id' => 'C2',
                    'label' => 'Pengambilan Keputusan',
                    'low_indicator' => [
                        'Bingung menentukan prioritas atau terlalu reaktif.',
                        'Keputusan tidak memiliki dasar yang jelas.',
                    ],
                    'high_indicator' => [
                        'Mampu menimbang data, masukan, dan prinsip sebelum memutuskan.',
                        'Tegas namun tidak gegabah.',
                    ],
                ],
                [
                    'id' => 'C3',
                    'label' => 'Delegasi & Tindak Lanjut',
                    'low_indicator' => [
                        'Semua ingin dikerjakan sendiri atau tidak melakukan follow-up.',
                        'Sulit mempercayai orang lain dalam tim.',
                    ],
                    'high_indicator' => [
                        'Mampu membagi tugas secara sehat dan memantau pelaksanaannya.',
                        'Memberdayakan anggota tim sesuai kapasitasnya.',
                    ],
                ],
                [
                    'id' => 'C4',
                    'label' => 'Ketahanan dalam Konflik',
                    'low_indicator' => [
                        'Mudah tersulut, menghindari konflik, atau memihak tanpa objektivitas.',
                        'Tidak memiliki pola penyelesaian masalah yang sehat.',
                    ],
                    'high_indicator' => [
                        'Stabil secara emosi dan objektif dalam konflik.',
                        'Mendorong rekonsiliasi dan solusi yang membangun.',
                    ],
                ],
            ],
        ],
        [
            'id' => 'D',
            'title' => 'Studi Kasus & Eksekusi',
            'focus' => 'Hikmat praktis dan kemampuan mengeksekusi solusi pada situasi nyata.',
            'weight' => 0.15,
            'note_label' => 'Catatan Bagian D',
            'questions' => [
                [
                    'id' => 'D1',
                    'label' => 'Penyelesaian Kasus Bidang',
                    'low_indicator' => [
                        'Jawaban normatif, reaktif, atau tidak operasional.',
                        'Tidak menunjukkan pemahaman pada risiko dan dampak keputusan.',
                    ],
                    'high_indicator' => [
                        'Jawaban sistematis, relevan, dan dapat dijalankan.',
                        'Mampu mempertimbangkan dampak pastoral maupun operasional.',
                    ],
                ],
                [
                    'id' => 'D2',
                    'label' => 'Prioritas 90 Hari Pertama',
                    'low_indicator' => [
                        'Tidak jelas menentukan prioritas awal pelayanan.',
                        'Langkah yang diusulkan tidak realistis atau tidak terukur.',
                    ],
                    'high_indicator' => [
                        'Mampu menentukan prioritas awal yang jelas dan realistis.',
                        'Menunjukkan cara eksekusi yang terukur dan bertahap.',
                    ],
                ],
            ],
        ],
    ];
}

function default_scorecard_templates_data(): array
{
    return [
        'default_template_key' => 'generic_majelis_v1',
        'templates' => [
            [
                'template_key' => 'ketua_majelis_v1',
                'title' => 'Scorecard Wawancara Ketua Majelis',
                'version' => 1,
                'bidang_titles' => ['Ketua Majelis'],
                'decision_options' => default_scorecard_decision_options(),
                'final_ranges' => default_scorecard_final_ranges(),
                'sections' => default_scorecard_ketua_majelis_sections(),
            ],
            [
                'template_key' => 'generic_majelis_v1',
                'title' => 'Scorecard Wawancara Majelis',
                'version' => 1,
                'bidang_titles' => [
                    'Sekretaris Majelis',
                    'Bendahara Majelis',
                    'Majelis Bidang Pemuridan',
                    'Majelis Bidang Misi',
                    'Majelis Bidang Diakonia',
                    'Majelis Bidang Ibadah',
                    'Ketua Pengurus Lokal',
                ],
                'decision_options' => default_scorecard_decision_options(),
                'final_ranges' => default_scorecard_final_ranges(),
                'sections' => default_scorecard_generic_sections(),
            ],
        ],
    ];
}

function default_kandidat_data(): array
{
    $cabangList = [
        'REC Kutisari',
        'REC Nginden',
        'REC Darmo',
        'REC Merr',
        'REC Galaxy Mall',
        'REC Batam',
    ];

    $firstNames = [
        'Yohanes', 'Maria', 'Daniel', 'Debora', 'Samuel',
        'Lidia', 'Andre', 'Michelle', 'Ricky', 'Cynthia',
        'Kevin', 'Stefani', 'Jonathan', 'Grace', 'Ester',
        'Albert', 'Felicia', 'Nathaniel', 'Caroline', 'Timothy',
    ];
    $middleNames = [
        'Aditya', 'Gabriella', 'Kristianto', 'Natalia', 'Jonathan',
        'Evelyn', 'Saputra', 'Olivia', 'Fernando', 'Angelia',
        'Nathanael', 'Aurelia', 'Pranata', 'Marcella', 'Christina',
        'William', 'Anastasia', 'Benedict', 'Clarissa', 'Raphael',
    ];
    $lastNames = [
        'Pratama', 'Sari', 'Wijaya', 'Putri', 'Halim',
        'Gunawan', 'Setiawan', 'Santoso', 'Hartono', 'Kurnia',
        'Tanujaya', 'Liem', 'Sutanto', 'Hendrawan', 'Saputri',
        'Widjaja', 'Susanto', 'Lukito', 'Winata', 'Permana',
    ];

    $result = [];
    foreach ($cabangList as $cabangIndex => $cabang) {
        $slug = strtolower((string)preg_replace('/[^a-z0-9]+/', '-', str_replace('REC ', '', $cabang)));
        $slug = trim($slug, '-');

        for ($i = 0; $i < 20; $i++) {
            $first = $firstNames[($i + $cabangIndex) % count($firstNames)];
            $middle = $middleNames[(($i * 2) + $cabangIndex) % count($middleNames)];
            $last = $lastNames[(($i * 3) + $cabangIndex) % count($lastNames)];
            $num = str_pad((string)($i + 1), 2, '0', STR_PAD_LEFT);

            $result[] = [
                'id' => $slug . '-' . $num,
                'nama_lengkap' => $first . ' ' . $middle . ' ' . $last,
                'asal_cabang' => $cabang,
                'bisa_semua_posisi' => true,
                'bisa_ketua_pengurus_lokal' => true,
            ];
        }
    }

    return $result;
}

function default_kandidat_pencalonan_flags(): array
{
    return [
        'bisa_semua_posisi' => true,
        'bisa_ketua_pengurus_lokal' => true,
    ];
}

function normalize_boolean_flag($value, bool $default = false): bool
{
    if (is_bool($value)) {
        return $value;
    }

    if (is_int($value) || is_float($value)) {
        return ((int)$value) !== 0;
    }

    $normalized = normalize_header_key((string)$value);
    if ($normalized === '') {
        return $default;
    }

    if (in_array($normalized, ['1', 'true', 'ya', 'yes', 'y', 'bisa', 'aktif'], true)) {
        return true;
    }

    if (in_array($normalized, ['0', 'false', 'tidak', 'no', 'n', 'tidakbisa', 'nonaktif'], true)) {
        return false;
    }

    return $default;
}

function kandidat_pencalonan_flags_from_record(array $item, ?array $fallbackFlags = null): array
{
    $defaults = default_kandidat_pencalonan_flags();
    if (is_array($fallbackFlags)) {
        $defaults = [
            'bisa_semua_posisi' => normalize_boolean_flag(
                $fallbackFlags['bisa_semua_posisi'] ?? $defaults['bisa_semua_posisi'],
                $defaults['bisa_semua_posisi']
            ),
            'bisa_ketua_pengurus_lokal' => normalize_boolean_flag(
                $fallbackFlags['bisa_ketua_pengurus_lokal'] ?? $defaults['bisa_ketua_pengurus_lokal'],
                $defaults['bisa_ketua_pengurus_lokal']
            ),
        ];
    }

    return [
        'bisa_semua_posisi' => normalize_boolean_flag(
            $item['bisa_semua_posisi'] ?? $defaults['bisa_semua_posisi'],
            $defaults['bisa_semua_posisi']
        ),
        'bisa_ketua_pengurus_lokal' => normalize_boolean_flag(
            $item['bisa_ketua_pengurus_lokal'] ?? $defaults['bisa_ketua_pengurus_lokal'],
            $defaults['bisa_ketua_pengurus_lokal']
        ),
    ];
}

function build_kandidat_record(string $id, string $namaLengkap, string $asalCabang, array $flags = []): array
{
    $normalizedFlags = kandidat_pencalonan_flags_from_record($flags);
    return [
        'id' => $id,
        'nama_lengkap' => $namaLengkap,
        'asal_cabang' => $asalCabang,
        'bisa_semua_posisi' => $normalizedFlags['bisa_semua_posisi'],
        'bisa_ketua_pengurus_lokal' => $normalizedFlags['bisa_ketua_pengurus_lokal'],
    ];
}

function normalize_kandidat_tipe_pencalonan(string $value): string
{
    $normalized = normalize_header_key($value);
    if ($normalized === '') {
        return '';
    }

    $allValues = [
        'semua',
        'all',
        'semuadanketualokal',
        'semuaposisidanketualokal',
        'semuabidangdanketualokal',
    ];
    if (in_array($normalized, $allValues, true)) {
        return 'semua';
    }

    $allExceptKetuaLokalValues = [
        'semuakecualiketualokal',
        'semuakecualiketuapenguruslokal',
        'semuaposisikecualiketualokal',
        'semuaposisikecualiketuapenguruslokal',
        'semuabidangkecualiketualokal',
        'semuabidangkecualiketuapenguruslokal',
        'tanpaketualokal',
        'tanpaketuapenguruslokal',
        'nonketualokal',
        'nonketuapenguruslokal',
    ];
    if (in_array($normalized, $allExceptKetuaLokalValues, true)) {
        return 'semua_kecuali_ketua_lokal';
    }

    $ketuaLokalOnlyValues = [
        'ketualokalsaja',
        'ketuapenguruslokalsaja',
        'hanyaketualokal',
        'hanyaketuapenguruslokal',
    ];
    if (in_array($normalized, $ketuaLokalOnlyValues, true)) {
        return 'ketua_lokal_saja';
    }

    return '';
}

function kandidat_pencalonan_flags_from_import(string $value, array $fallbackFlags): ?array
{
    $value = trim($value);
    if ($value === '') {
        return kandidat_pencalonan_flags_from_record($fallbackFlags);
    }

    $normalizedType = normalize_kandidat_tipe_pencalonan($value);
    if ($normalizedType === 'semua') {
        return [
            'bisa_semua_posisi' => true,
            'bisa_ketua_pengurus_lokal' => true,
        ];
    }
    if ($normalizedType === 'semua_kecuali_ketua_lokal') {
        return [
            'bisa_semua_posisi' => true,
            'bisa_ketua_pengurus_lokal' => false,
        ];
    }
    if ($normalizedType === 'ketua_lokal_saja') {
        return [
            'bisa_semua_posisi' => false,
            'bisa_ketua_pengurus_lokal' => true,
        ];
    }

    return null;
}

function kandidat_bisa_dipilih_untuk_bidang(array $kandidat, string $bidang): bool
{
    $flags = kandidat_pencalonan_flags_from_record($kandidat);
    if (is_ketua_pengurus_lokal_bidang($bidang)) {
        return $flags['bisa_ketua_pengurus_lokal'];
    }

    return $flags['bisa_semua_posisi'];
}

function load_kandidat_data(): array
{
    $fallback = default_kandidat_data();
    $decoded = read_json_file(kandidat_file_path(), ['kandidat' => $fallback]);
    if (!is_array($decoded) || !isset($decoded['kandidat']) || !is_array($decoded['kandidat'])) {
        return $fallback;
    }

    $result = [];
    foreach ($decoded['kandidat'] as $idx => $item) {
        if (!is_array($item)) {
            continue;
        }

        $id = trim((string)($item['id'] ?? ''));
        if ($id === '') {
            $id = 'kandidat-' . ($idx + 1);
        }

        $namaLengkap = trim((string)($item['nama_lengkap'] ?? ''));
        $asalCabang = trim((string)($item['asal_cabang'] ?? ''));
        if ($namaLengkap === '' || $asalCabang === '') {
            continue;
        }

        $result[] = build_kandidat_record(
            $id,
            $namaLengkap,
            $asalCabang,
            kandidat_pencalonan_flags_from_record($item)
        );
    }

    // Jika file kandidat valid tapi kosong, pertahankan kosong (jangan fallback ke data sample).
    return $result;
}

function normalize_header_key(string $value): string
{
    $value = strtolower(trim($value));
    $value = preg_replace('/[^a-z0-9]+/', '', $value);
    return is_string($value) ? $value : '';
}

function slugify_identifier(string $value): string
{
    $value = strtolower(trim($value));
    $value = preg_replace('/[^a-z0-9]+/', '-', $value);
    $value = is_string($value) ? trim($value, '-') : '';
    return $value;
}

function normalize_import_cabang(string $cabang, array $knownCabang): string
{
    $cabang = normalize_username($cabang);
    if ($cabang === '') {
        return '';
    }

    $cabangKey = normalize_header_key($cabang);
    foreach ($knownCabang as $known) {
        $knownText = trim((string)$known);
        if ($knownText === '') {
            continue;
        }
        if (hash_equals(normalize_header_key($knownText), $cabangKey)) {
            return $knownText;
        }
    }

    $withoutRec = preg_replace('/^rec[\s\.\-_]*/i', '', $cabang);
    $withoutRec = is_string($withoutRec) ? trim($withoutRec) : $cabang;
    if ($withoutRec === '') {
        return '';
    }

    $withoutRec = preg_replace('/\s+/', ' ', $withoutRec);
    if (!is_string($withoutRec) || trim($withoutRec) === '') {
        return '';
    }

    return 'REC ' . ucwords(strtolower(trim($withoutRec)));
}

function known_cabang_values(): array
{
    $known = [
        'REC Kutisari',
        'REC Nginden',
        'REC Darmo',
        'REC Merr',
        'REC Galaxy Mall',
        'REC Batam',
    ];

    foreach (load_user_data() as $user) {
        if (!is_array($user)) {
            continue;
        }

        $cabang = trim((string)($user['asal_cabang'] ?? ''));
        if ($cabang !== '') {
            $known[] = $cabang;
        }
    }

    foreach (load_kandidat_data() as $kandidat) {
        if (!is_array($kandidat)) {
            continue;
        }

        $cabang = trim((string)($kandidat['asal_cabang'] ?? ''));
        if ($cabang !== '') {
            $known[] = $cabang;
        }
    }

    $map = [];
    foreach ($known as $item) {
        $item = trim((string)$item);
        if ($item === '') {
            continue;
        }

        $key = normalize_header_key($item);
        if ($key !== '' && !isset($map[$key])) {
            $map[$key] = $item;
        }
    }

    return array_values($map);
}

function resolve_zip_internal_path(string $basePath, string $targetPath): string
{
    $basePath = str_replace('\\', '/', $basePath);
    $targetPath = str_replace('\\', '/', $targetPath);

    if (str_starts_with($targetPath, '/')) {
        $combined = ltrim($targetPath, '/');
    } else {
        $baseDir = trim(dirname($basePath), '.');
        $baseDir = trim(str_replace('\\', '/', $baseDir), '/');
        $combined = ($baseDir !== '' ? $baseDir . '/' : '') . $targetPath;
    }

    $parts = explode('/', $combined);
    $normalized = [];
    foreach ($parts as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            array_pop($normalized);
            continue;
        }
        $normalized[] = $part;
    }

    return implode('/', $normalized);
}

function read_xlsx_xml(ZipArchive $zip, string $entry): ?DOMDocument
{
    $xml = $zip->getFromName($entry);
    if (!is_string($xml)) {
        return null;
    }

    $dom = new DOMDocument();
    if (!@$dom->loadXML($xml, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING)) {
        return null;
    }

    return $dom;
}

function xlsx_shared_strings(ZipArchive $zip): array
{
    $dom = read_xlsx_xml($zip, 'xl/sharedStrings.xml');
    if ($dom === null) {
        return [];
    }

    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('x', 'http://schemas.openxmlformats.org/spreadsheetml/2006/main');

    $result = [];
    $nodes = $xpath->query('/x:sst/x:si');
    if ($nodes === false) {
        return [];
    }

    foreach ($nodes as $node) {
        $parts = $xpath->query('.//x:t', $node);
        if ($parts === false) {
            $result[] = trim((string)$node->textContent);
            continue;
        }

        $text = '';
        foreach ($parts as $part) {
            $text .= (string)$part->textContent;
        }
        $result[] = trim($text);
    }

    return $result;
}

function xlsx_sheet_name_path_map(ZipArchive $zip): array
{
    $workbookPath = 'xl/workbook.xml';
    $workbookRelsPath = 'xl/_rels/workbook.xml.rels';

    $workbookDom = read_xlsx_xml($zip, $workbookPath);
    $relsDom = read_xlsx_xml($zip, $workbookRelsPath);
    if ($workbookDom === null || $relsDom === null) {
        return [];
    }

    $relXpath = new DOMXPath($relsDom);
    $relXpath->registerNamespace('r', 'http://schemas.openxmlformats.org/package/2006/relationships');
    $relNodes = $relXpath->query('/r:Relationships/r:Relationship');
    if ($relNodes === false) {
        return [];
    }

    $rels = [];
    foreach ($relNodes as $relNode) {
        if (!($relNode instanceof DOMElement)) {
            continue;
        }
        $id = trim((string)$relNode->getAttribute('Id'));
        $target = trim((string)$relNode->getAttribute('Target'));
        if ($id !== '' && $target !== '') {
            $rels[$id] = $target;
        }
    }

    $workbookXpath = new DOMXPath($workbookDom);
    $workbookXpath->registerNamespace('x', 'http://schemas.openxmlformats.org/spreadsheetml/2006/main');
    $workbookXpath->registerNamespace('r', 'http://schemas.openxmlformats.org/officeDocument/2006/relationships');
    $sheetNodes = $workbookXpath->query('/x:workbook/x:sheets/x:sheet');
    if ($sheetNodes === false) {
        return [];
    }

    $result = [];
    foreach ($sheetNodes as $sheetNode) {
        if (!($sheetNode instanceof DOMElement)) {
            continue;
        }

        $name = trim((string)$sheetNode->getAttribute('name'));
        $rid = trim((string)$sheetNode->getAttributeNS('http://schemas.openxmlformats.org/officeDocument/2006/relationships', 'id'));
        if ($rid === '') {
            $rid = trim((string)$sheetNode->getAttribute('r:id'));
        }
        if ($name === '' || $rid === '' || !isset($rels[$rid])) {
            continue;
        }

        $sheetPath = resolve_zip_internal_path($workbookPath, $rels[$rid]);
        if ($sheetPath !== '') {
            $result[$name] = $sheetPath;
        }
    }

    return $result;
}

function xlsx_column_index(string $cellRef): int
{
    if (!preg_match('/^([A-Z]+)[0-9]+$/i', strtoupper(trim($cellRef)), $matches)) {
        return -1;
    }

    $letters = strtoupper((string)($matches[1] ?? ''));
    if ($letters === '') {
        return -1;
    }

    $index = 0;
    for ($i = 0; $i < strlen($letters); $i++) {
        $index = ($index * 26) + (ord($letters[$i]) - 64);
    }

    return $index - 1;
}

function xlsx_cell_text(DOMXPath $xpath, DOMElement $cellNode, array $sharedStrings): string
{
    $type = trim((string)$cellNode->getAttribute('t'));

    if ($type === 'inlineStr') {
        $textNodes = $xpath->query('.//x:is//x:t', $cellNode);
        if ($textNodes === false) {
            return trim((string)$cellNode->textContent);
        }
        $text = '';
        foreach ($textNodes as $textNode) {
            $text .= (string)$textNode->textContent;
        }
        return trim($text);
    }

    $valueNodeList = $xpath->query('./x:v', $cellNode);
    if ($valueNodeList === false || $valueNodeList->length === 0) {
        return '';
    }

    $rawValue = trim((string)$valueNodeList->item(0)?->textContent);
    if ($rawValue === '') {
        return '';
    }

    if ($type === 's') {
        $idx = (int)$rawValue;
        return isset($sharedStrings[$idx]) ? (string)$sharedStrings[$idx] : '';
    }

    return $rawValue;
}

function xlsx_sheet_rows(ZipArchive $zip, string $sheetPath, array $sharedStrings): array
{
    $dom = read_xlsx_xml($zip, $sheetPath);
    if ($dom === null) {
        return [];
    }

    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('x', 'http://schemas.openxmlformats.org/spreadsheetml/2006/main');
    $rowNodes = $xpath->query('/x:worksheet/x:sheetData/x:row');
    if ($rowNodes === false) {
        return [];
    }

    $rows = [];
    foreach ($rowNodes as $rowNode) {
        $cellNodes = $xpath->query('./x:c', $rowNode);
        if ($cellNodes === false || $cellNodes->length === 0) {
            continue;
        }

        $rowData = [];
        $maxCol = -1;
        foreach ($cellNodes as $cellNode) {
            if (!($cellNode instanceof DOMElement)) {
                continue;
            }

            $cellRef = strtoupper(trim((string)$cellNode->getAttribute('r')));
            $colIndex = xlsx_column_index($cellRef);
            if ($colIndex < 0) {
                $colIndex = $maxCol + 1;
            }

            $rowData[$colIndex] = xlsx_cell_text($xpath, $cellNode, $sharedStrings);
            if ($colIndex > $maxCol) {
                $maxCol = $colIndex;
            }
        }

        if ($maxCol < 0) {
            continue;
        }

        ksort($rowData);
        $normalizedRow = [];
        $hasValue = false;
        for ($i = 0; $i <= $maxCol; $i++) {
            $value = (string)($rowData[$i] ?? '');
            if (trim($value) !== '') {
                $hasValue = true;
            }
            $normalizedRow[$i] = $value;
        }

        if ($hasValue) {
            $rows[] = $normalizedRow;
        }
    }

    return $rows;
}

function load_xlsx_sheets(string $xlsxPath): array
{
    if (!class_exists('ZipArchive')) {
        return [
            'ok' => false,
            'error' => 'Ekstensi ZIP tidak tersedia di PHP server.',
            'sheets' => [],
        ];
    }

    $zip = new ZipArchive();
    $openResult = $zip->open($xlsxPath);
    if ($openResult !== true) {
        return [
            'ok' => false,
            'error' => 'File Excel tidak bisa dibuka.',
            'sheets' => [],
        ];
    }

    $sheetMap = xlsx_sheet_name_path_map($zip);
    if ($sheetMap === []) {
        $zip->close();
        return [
            'ok' => false,
            'error' => 'Sheet Excel tidak ditemukan atau format workbook tidak valid.',
            'sheets' => [],
        ];
    }

    $sharedStrings = xlsx_shared_strings($zip);
    $sheets = [];
    foreach ($sheetMap as $sheetName => $sheetPath) {
        $rows = xlsx_sheet_rows($zip, $sheetPath, $sharedStrings);
        $sheets[(string)$sheetName] = $rows;
    }
    $zip->close();

    return [
        'ok' => true,
        'error' => '',
        'sheets' => $sheets,
    ];
}

function find_xlsx_sheet_name(array $sheetNames, array $keywordGroups): ?string
{
    $normalizedNames = [];
    foreach ($sheetNames as $name) {
        $normalizedNames[(string)$name] = normalize_header_key((string)$name);
    }

    foreach ($keywordGroups as $keywords) {
        if (!is_array($keywords) || $keywords === []) {
            continue;
        }

        $needleParts = [];
        foreach ($keywords as $keyword) {
            $key = normalize_header_key((string)$keyword);
            if ($key !== '') {
                $needleParts[] = $key;
            }
        }
        if ($needleParts === []) {
            continue;
        }

        foreach ($normalizedNames as $originalName => $normalizedName) {
            $matched = true;
            foreach ($needleParts as $needle) {
                if (!str_contains($normalizedName, $needle)) {
                    $matched = false;
                    break;
                }
            }
            if ($matched) {
                return $originalName;
            }
        }
    }

    return null;
}

function extract_sheet_header_map(array $headerRow): array
{
    $map = [];
    foreach ($headerRow as $idx => $headerText) {
        $key = normalize_header_key((string)$headerText);
        if ($key !== '' && !isset($map[$key])) {
            $map[$key] = (int)$idx;
        }
    }
    return $map;
}

function header_index(array $headerMap, array $candidates): ?int
{
    foreach ($candidates as $candidate) {
        $key = normalize_header_key((string)$candidate);
        if ($key !== '' && isset($headerMap[$key])) {
            return (int)$headerMap[$key];
        }
    }
    return null;
}

function phone_tail_to_password(string $rawValue): string
{
    $rawValue = trim($rawValue);
    if ($rawValue === '') {
        return '';
    }
    $digits = preg_replace('/\D+/', '', $rawValue);
    if (!is_string($digits) || $digits === '' || strlen($digits) < 6) {
        return '';
    }

    return substr($digits, -6);
}

function generate_import_kandidat_id(string $namaLengkap, string $asalCabang, array &$usedIds): string
{
    $base = slugify_identifier($asalCabang . '-' . $namaLengkap);
    if ($base === '') {
        $base = 'kandidat';
    }
    if (strlen($base) > 42) {
        $base = substr($base, 0, 42);
    }

    $candidate = $base;
    $suffix = 2;
    while (isset($usedIds[$candidate])) {
        $suffixText = '-' . $suffix;
        $trimmedBase = $base;
        $maxBaseLen = 48 - strlen($suffixText);
        if ($maxBaseLen < 1) {
            $maxBaseLen = 1;
        }
        if (strlen($trimmedBase) > $maxBaseLen) {
            $trimmedBase = substr($trimmedBase, 0, $maxBaseLen);
        }
        $candidate = $trimmedBase . $suffixText;
        $suffix++;
    }

    $usedIds[$candidate] = true;
    return $candidate;
}

function upload_error_message(int $errorCode): string
{
    return match ($errorCode) {
        UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'Ukuran file melebihi batas upload.',
        UPLOAD_ERR_PARTIAL => 'Upload file tidak selesai.',
        UPLOAD_ERR_NO_FILE => 'File Excel belum dipilih.',
        UPLOAD_ERR_NO_TMP_DIR => 'Folder temporary upload tidak tersedia.',
        UPLOAD_ERR_CANT_WRITE => 'File upload gagal ditulis ke disk.',
        UPLOAD_ERR_EXTENSION => 'Upload file dibatalkan oleh ekstensi PHP.',
        default => 'Terjadi kesalahan saat upload file.',
    };
}

function import_users_and_kandidat_from_xlsx(string $xlsxPath): array
{
    $result = [
        'ok' => false,
        'errors' => [],
        'warnings' => [],
        'summary' => [
            'users_inserted' => 0,
            'users_updated' => 0,
            'users_skipped' => 0,
            'kandidat_inserted' => 0,
            'kandidat_updated' => 0,
            'kandidat_skipped' => 0,
        ],
    ];

    $xlsx = load_xlsx_sheets($xlsxPath);
    if (!(bool)($xlsx['ok'] ?? false)) {
        $result['errors'][] = (string)($xlsx['error'] ?? 'File Excel tidak valid.');
        return $result;
    }

    $sheets = (array)($xlsx['sheets'] ?? []);
    $sheetNames = array_keys($sheets);
    $userSheetName = find_xlsx_sheet_name($sheetNames, [
        ['master', 'pemilih'],
        ['pemilih'],
        ['user'],
    ]);
    $kandidatSheetName = find_xlsx_sheet_name($sheetNames, [
        ['master', 'kandidat'],
        ['kandidat'],
    ]);

    if ($userSheetName === null) {
        $result['errors'][] = 'Sheet user tidak ditemukan. Gunakan sheet MASTER PEMILIH.';
    }
    if ($kandidatSheetName === null) {
        $result['errors'][] = 'Sheet kandidat tidak ditemukan. Gunakan sheet MASTER KANDIDAT.';
    }
    if ($result['errors'] !== []) {
        return $result;
    }

    $knownCabang = known_cabang_values();

    $existingUsers = load_user_data();
    $userKeyIndex = [];
    foreach ($existingUsers as $idx => $user) {
        if (!is_array($user)) {
            continue;
        }
        $nama = normalize_username((string)($user['nama_lengkap'] ?? ''));
        $cabang = trim((string)($user['asal_cabang'] ?? ''));
        $role = normalize_role((string)($user['role'] ?? 'user'));
        if ($nama === '' || $cabang === '' || $role !== 'user') {
            continue;
        }
        $key = strtolower($nama) . '|' . strtolower($cabang) . '|user';
        $userKeyIndex[$key] = (int)$idx;
    }

    $userRows = (array)($sheets[$userSheetName] ?? []);
    if (count($userRows) < 2) {
        $result['errors'][] = 'Sheet ' . $userSheetName . ' tidak berisi data user.';
        return $result;
    }

    $userHeaderMap = extract_sheet_header_map((array)$userRows[0]);
    $idxUserNama = header_index($userHeaderMap, ['nama lengkap', 'namalengkap', 'nama']);
    $idxUserNomorTelpon = header_index($userHeaderMap, [
        'nomor telpon',
        'nomor telepon',
        'no telpon',
        'no telepon',
        'nomor hp',
        'no hp',
        'telepon',
        'telpon',
        'hp',
    ]);
    $idxUserCabang = header_index($userHeaderMap, ['cabang']);
    if ($idxUserNama === null || $idxUserNomorTelpon === null || $idxUserCabang === null) {
        $result['errors'][] = 'Header sheet user wajib berisi: NAMA LENGKAP, NOMOR TELPON, CABANG.';
        return $result;
    }

    for ($i = 1; $i < count($userRows); $i++) {
        $row = (array)$userRows[$i];
        $nama = normalize_username((string)($row[$idxUserNama] ?? ''));
        $nomorTelponRaw = trim((string)($row[$idxUserNomorTelpon] ?? ''));
        $cabangRaw = trim((string)($row[$idxUserCabang] ?? ''));

        if ($nama === '' && $nomorTelponRaw === '' && $cabangRaw === '') {
            continue;
        }

        $cabang = normalize_import_cabang($cabangRaw, $knownCabang);
        if ($nama === '' || $nomorTelponRaw === '' || $cabang === '') {
            $result['summary']['users_skipped']++;
            if (count($result['warnings']) < 200) {
                $result['warnings'][] = 'Baris user #' . ($i + 1) . ' dilewati karena data tidak lengkap.';
            }
            continue;
        }

        $username = short_username_from_fullname($nama);
        $passwordPlain = phone_tail_to_password($nomorTelponRaw);
        if ($username === '' || $passwordPlain === '') {
            $result['summary']['users_skipped']++;
            if (count($result['warnings']) < 200) {
                $result['warnings'][] = 'Baris user #' . ($i + 1) . ' dilewati karena format nama/nomor telpon tidak valid (minimal 6 digit).';
            }
            continue;
        }

        $passwordHash = password_hash($passwordPlain, PASSWORD_DEFAULT);
        if (!is_string($passwordHash) || $passwordHash === '') {
            $result['summary']['users_skipped']++;
            if (count($result['warnings']) < 200) {
                $result['warnings'][] = 'Baris user #' . ($i + 1) . ' gagal di-hash.';
            }
            continue;
        }

        $userItem = [
            'nama_lengkap' => $nama,
            'username' => $username,
            'password' => $passwordHash,
            'asal_cabang' => $cabang,
            'role' => 'user',
        ];

        $userKey = strtolower($nama) . '|' . strtolower($cabang) . '|user';
        if (isset($userKeyIndex[$userKey])) {
            $existingUsers[$userKeyIndex[$userKey]] = $userItem;
            $result['summary']['users_updated']++;
        } else {
            $existingUsers[] = $userItem;
            $userKeyIndex[$userKey] = count($existingUsers) - 1;
            $result['summary']['users_inserted']++;
            $knownCabang[] = $cabang;
        }
    }

    $existingKandidat = load_kandidat_data();
    $usedKandidatIds = [];
    $kandidatKeyIndex = [];
    foreach ($existingKandidat as $idx => $kandidat) {
        if (!is_array($kandidat)) {
            continue;
        }

        $id = trim((string)($kandidat['id'] ?? ''));
        $nama = normalize_username((string)($kandidat['nama_lengkap'] ?? ''));
        $cabang = trim((string)($kandidat['asal_cabang'] ?? ''));
        if ($id !== '') {
            $usedKandidatIds[$id] = true;
        }
        if ($nama !== '' && $cabang !== '') {
            $kandidatKey = strtolower($nama) . '|' . strtolower($cabang);
            $kandidatKeyIndex[$kandidatKey] = (int)$idx;
        }
    }

    $kandidatRows = (array)($sheets[$kandidatSheetName] ?? []);
    if (count($kandidatRows) < 2) {
        $result['errors'][] = 'Sheet ' . $kandidatSheetName . ' tidak berisi data kandidat.';
        return $result;
    }

    $kandidatHeaderMap = extract_sheet_header_map((array)$kandidatRows[0]);
    $idxKandidatNama = header_index($kandidatHeaderMap, ['nama lengkap', 'namalengkap', 'nama']);
    $idxKandidatCabang = header_index($kandidatHeaderMap, ['cabang']);
    $idxKandidatTipePencalonan = header_index($kandidatHeaderMap, [
        'tipe pencalonan',
        'kategori pencalonan',
        'jenis pencalonan',
    ]);
    if ($idxKandidatNama === null || $idxKandidatCabang === null) {
        $result['errors'][] = 'Header sheet kandidat wajib berisi: NAMA LENGKAP, CABANG.';
        return $result;
    }

    for ($i = 1; $i < count($kandidatRows); $i++) {
        $row = (array)$kandidatRows[$i];
        $nama = normalize_username((string)($row[$idxKandidatNama] ?? ''));
        $cabangRaw = trim((string)($row[$idxKandidatCabang] ?? ''));
        $tipePencalonanRaw = $idxKandidatTipePencalonan !== null
            ? trim((string)($row[$idxKandidatTipePencalonan] ?? ''))
            : '';

        if ($nama === '' && $cabangRaw === '') {
            continue;
        }

        $cabang = normalize_import_cabang($cabangRaw, $knownCabang);
        if ($nama === '' || $cabang === '') {
            $result['summary']['kandidat_skipped']++;
            if (count($result['warnings']) < 200) {
                $result['warnings'][] = 'Baris kandidat #' . ($i + 1) . ' dilewati karena data tidak lengkap.';
            }
            continue;
        }

        $kandidatKey = strtolower($nama) . '|' . strtolower($cabang);
        $existingFlags = default_kandidat_pencalonan_flags();
        if (isset($kandidatKeyIndex[$kandidatKey])) {
            $existingFlags = kandidat_pencalonan_flags_from_record((array)$existingKandidat[$kandidatKeyIndex[$kandidatKey]]);
        }
        $importedFlags = kandidat_pencalonan_flags_from_import($tipePencalonanRaw, $existingFlags);
        if ($importedFlags === null) {
            $result['summary']['kandidat_skipped']++;
            if (count($result['warnings']) < 200) {
                $result['warnings'][] = 'Baris kandidat #' . ($i + 1)
                    . ' dilewati karena TIPE PENCALONAN tidak valid. Gunakan: SEMUA, SEMUA_KECUALI_KETUA_LOKAL, atau KETUA_LOKAL_SAJA.';
            }
            continue;
        }

        if (isset($kandidatKeyIndex[$kandidatKey])) {
            $idx = $kandidatKeyIndex[$kandidatKey];
            $existingId = trim((string)($existingKandidat[$idx]['id'] ?? ''));
            if ($existingId === '') {
                $existingId = generate_import_kandidat_id($nama, $cabang, $usedKandidatIds);
            } else {
                $usedKandidatIds[$existingId] = true;
            }

            $existingKandidat[$idx] = build_kandidat_record($existingId, $nama, $cabang, $importedFlags);
            $result['summary']['kandidat_updated']++;
        } else {
            $newId = generate_import_kandidat_id($nama, $cabang, $usedKandidatIds);
            $existingKandidat[] = build_kandidat_record($newId, $nama, $cabang, $importedFlags);
            $kandidatKeyIndex[$kandidatKey] = count($existingKandidat) - 1;
            $result['summary']['kandidat_inserted']++;
            $knownCabang[] = $cabang;
        }
    }

    if (!write_json_file_atomic(user_file_path(), ['users' => $existingUsers])) {
        $result['errors'][] = 'Gagal menyimpan data user hasil import.';
        return $result;
    }

    if (!write_json_file_atomic(kandidat_file_path(), ['kandidat' => $existingKandidat])) {
        $result['errors'][] = 'Gagal menyimpan data kandidat hasil import.';
        return $result;
    }

    $result['ok'] = true;
    return $result;
}

function find_kandidat_by_id(array $kandidatList, string $kandidatId): ?array
{
    foreach ($kandidatList as $kandidat) {
        if ((string)($kandidat['id'] ?? '') === $kandidatId) {
            return $kandidat;
        }
    }

    return null;
}

function kandidat_option_label(array $kandidat): string
{
    $nama = trim((string)($kandidat['nama_lengkap'] ?? ''));
    $cabang = trim((string)($kandidat['asal_cabang'] ?? ''));
    return display_name_text($nama) . ' - ' . $cabang;
}

function find_kandidat_by_option_label(array $kandidatList, string $label): ?array
{
    $label = strtolower(trim($label));
    if ($label === '') {
        return null;
    }

    foreach ($kandidatList as $kandidat) {
        if (strtolower(kandidat_option_label($kandidat)) === $label) {
            return $kandidat;
        }
    }

    return null;
}

function load_pemilihan_data(): array
{
    $empty = ['pemilihan' => []];
    $decoded = read_json_file(pemilihan_file_path(), $empty);
    if (!is_array($decoded) || !isset($decoded['pemilihan']) || !is_array($decoded['pemilihan'])) {
        return $empty;
    }

    $normalizedItems = [];
    foreach ($decoded['pemilihan'] as $item) {
        if (!is_array($item)) {
            continue;
        }

        $item['bidang'] = normalize_vote_bidang_title(
            (string)($item['bidang'] ?? ''),
            (string)($item['asal_cabang_user'] ?? '')
        );
        $normalizedItems[] = $item;
    }

    return ['pemilihan' => $normalizedItems];
}

function load_vote_log_data(): array
{
    $empty = ['logs' => []];
    $decoded = read_json_file(vote_log_file_path(), $empty);
    if (!is_array($decoded) || !isset($decoded['logs']) || !is_array($decoded['logs'])) {
        return $empty;
    }

    $normalizedLogs = [];
    foreach ($decoded['logs'] as $log) {
        if (!is_array($log)) {
            continue;
        }

        $log['bidang'] = normalize_vote_bidang_title(
            (string)($log['bidang'] ?? ''),
            (string)($log['asal_cabang_user'] ?? '')
        );
        $normalizedLogs[] = $log;
    }

    return ['logs' => $normalizedLogs];
}

function load_login_rate_data(): array
{
    $empty = default_login_rate_data();
    $decoded = read_json_file(login_rate_file_path(), $empty);
    if (!is_array($decoded) || !isset($decoded['records']) || !is_array($decoded['records'])) {
        return $empty;
    }
    return $decoded;
}

function save_login_rate_data(array $data): void
{
    if (!isset($data['records']) || !is_array($data['records'])) {
        $data = default_login_rate_data();
    }
    write_json_file_atomic(login_rate_file_path(), $data);
}

function flagging_candidate_key(string $bidang, string $kandidatNama, string $kandidatCabang): string
{
    $parts = [
        normalize_header_key($bidang),
        normalize_header_key($kandidatNama),
        normalize_header_key($kandidatCabang),
    ];

    return hash('sha256', implode('|', $parts));
}

function kesediaan_candidate_key(string $kandidatNama, string $kandidatCabang): string
{
    $parts = [
        'kesediaan',
        normalize_header_key($kandidatNama),
        normalize_header_key($kandidatCabang),
    ];

    return hash('sha256', implode('|', $parts));
}

function load_flagging_data(): array
{
    $empty = ['flags' => []];
    $decoded = read_json_file(flagging_file_path(), $empty);
    if (!is_array($decoded) || !isset($decoded['flags']) || !is_array($decoded['flags'])) {
        return $empty;
    }

    $normalized = [];
    foreach ($decoded['flags'] as $item) {
        if (!is_array($item)) {
            continue;
        }

        $bidang = trim((string)($item['bidang'] ?? ''));
        $kandidatNama = trim((string)($item['kandidat_nama'] ?? ''));
        $kandidatCabang = trim((string)($item['kandidat_cabang'] ?? ''));
        if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '') {
            continue;
        }

        $lanjutProses = !empty($item['lanjut_proses']);
        $lolosScreening = !empty($item['lolos_screening']) && $lanjutProses;
        $updatedAt = trim((string)($item['updated_at'] ?? ''));
        $updatedBy = trim((string)($item['updated_by'] ?? ''));
        $key = trim((string)($item['key'] ?? ''));
        if ($key === '') {
            $key = flagging_candidate_key($bidang, $kandidatNama, $kandidatCabang);
        }

        $normalized[] = [
            'key' => $key,
            'bidang' => $bidang,
            'kandidat_nama' => $kandidatNama,
            'kandidat_cabang' => $kandidatCabang,
            'lanjut_proses' => $lanjutProses,
            'lolos_screening' => $lolosScreening,
            'updated_at' => $updatedAt,
            'updated_by' => $updatedBy,
        ];
    }

    return ['flags' => $normalized];
}

function load_flagging_map(): array
{
    $data = load_flagging_data();
    $map = [];
    foreach ((array)($data['flags'] ?? []) as $item) {
        if (!is_array($item)) {
            continue;
        }

        $key = trim((string)($item['key'] ?? ''));
        if ($key === '') {
            continue;
        }
        $map[$key] = $item;
    }

    return $map;
}

function save_flagging_map(array $map): bool
{
    $flags = [];
    foreach ($map as $key => $item) {
        if (!is_string($key) || !is_array($item)) {
            continue;
        }

        $bidang = trim((string)($item['bidang'] ?? ''));
        $kandidatNama = trim((string)($item['kandidat_nama'] ?? ''));
        $kandidatCabang = trim((string)($item['kandidat_cabang'] ?? ''));
        if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '') {
            continue;
        }

        $lanjutProses = !empty($item['lanjut_proses']);
        $lolosScreening = !empty($item['lolos_screening']) && $lanjutProses;
        if (!$lanjutProses && !$lolosScreening) {
            continue;
        }

        $flags[] = [
            'key' => $key,
            'bidang' => $bidang,
            'kandidat_nama' => $kandidatNama,
            'kandidat_cabang' => $kandidatCabang,
            'lanjut_proses' => $lanjutProses,
            'lolos_screening' => $lolosScreening,
            'updated_at' => trim((string)($item['updated_at'] ?? '')),
            'updated_by' => trim((string)($item['updated_by'] ?? '')),
        ];
    }

    usort($flags, static function (array $a, array $b): int {
        $left = (string)($a['bidang'] ?? '') . '|' . (string)($a['kandidat_nama'] ?? '') . '|' . (string)($a['kandidat_cabang'] ?? '');
        $right = (string)($b['bidang'] ?? '') . '|' . (string)($b['kandidat_nama'] ?? '') . '|' . (string)($b['kandidat_cabang'] ?? '');
        return strnatcasecmp($left, $right);
    });

    return write_json_file_atomic(flagging_file_path(), ['flags' => $flags]);
}

function load_wawancara_assignment_data(): array
{
    $empty = ['assignments' => []];
    $decoded = read_json_file(wawancara_assignment_file_path(), $empty);
    if (!is_array($decoded) || !isset($decoded['assignments']) || !is_array($decoded['assignments'])) {
        return $empty;
    }

    $normalized = [];
    foreach ($decoded['assignments'] as $item) {
        if (!is_array($item)) {
            continue;
        }

        $bidang = trim((string)($item['bidang'] ?? ''));
        $kandidatNama = trim((string)($item['kandidat_nama'] ?? ''));
        $kandidatCabang = trim((string)($item['kandidat_cabang'] ?? ''));
        $interviewerLogin = normalize_login_username((string)($item['interviewer_login_username'] ?? ''));
        if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '' || $interviewerLogin === '') {
            continue;
        }

        $key = trim((string)($item['key'] ?? ''));
        if ($key === '') {
            $key = flagging_candidate_key($bidang, $kandidatNama, $kandidatCabang);
        }

        $normalized[] = [
            'key' => $key,
            'bidang' => $bidang,
            'kandidat_nama' => $kandidatNama,
            'kandidat_cabang' => $kandidatCabang,
            'interviewer_login_username' => $interviewerLogin,
            'interviewer_nama_lengkap' => normalize_username((string)($item['interviewer_nama_lengkap'] ?? '')),
            'interviewer_asal_cabang' => trim((string)($item['interviewer_asal_cabang'] ?? '')),
            'updated_at' => trim((string)($item['updated_at'] ?? '')),
            'updated_by' => normalize_username((string)($item['updated_by'] ?? '')),
        ];
    }

    return ['assignments' => $normalized];
}

function load_wawancara_assignment_map(): array
{
    $data = load_wawancara_assignment_data();
    $map = [];
    foreach ((array)($data['assignments'] ?? []) as $item) {
        if (!is_array($item)) {
            continue;
        }

        $key = trim((string)($item['key'] ?? ''));
        if ($key === '') {
            continue;
        }
        $map[$key] = $item;
    }

    return $map;
}

function save_wawancara_assignment_map(array $map): bool
{
    $assignments = [];
    foreach ($map as $key => $item) {
        if (!is_string($key) || !is_array($item)) {
            continue;
        }

        $bidang = trim((string)($item['bidang'] ?? ''));
        $kandidatNama = trim((string)($item['kandidat_nama'] ?? ''));
        $kandidatCabang = trim((string)($item['kandidat_cabang'] ?? ''));
        $interviewerLogin = normalize_login_username((string)($item['interviewer_login_username'] ?? ''));
        if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '' || $interviewerLogin === '') {
            continue;
        }

        $assignments[] = [
            'key' => $key,
            'bidang' => $bidang,
            'kandidat_nama' => $kandidatNama,
            'kandidat_cabang' => $kandidatCabang,
            'interviewer_login_username' => $interviewerLogin,
            'interviewer_nama_lengkap' => normalize_username((string)($item['interviewer_nama_lengkap'] ?? '')),
            'interviewer_asal_cabang' => trim((string)($item['interviewer_asal_cabang'] ?? '')),
            'updated_at' => trim((string)($item['updated_at'] ?? '')),
            'updated_by' => normalize_username((string)($item['updated_by'] ?? '')),
        ];
    }

    usort($assignments, static function (array $a, array $b): int {
        $left = (string)($a['bidang'] ?? '') . '|' . (string)($a['kandidat_nama'] ?? '') . '|' . (string)($a['kandidat_cabang'] ?? '');
        $right = (string)($b['bidang'] ?? '') . '|' . (string)($b['kandidat_nama'] ?? '') . '|' . (string)($b['kandidat_cabang'] ?? '');
        return strnatcasecmp($left, $right);
    });

    return write_json_file_atomic(wawancara_assignment_file_path(), ['assignments' => $assignments]);
}

function set_candidate_interviewer_assignment(
    string $bidang,
    string $kandidatNama,
    string $kandidatCabang,
    string $interviewerLoginUsername,
    string $interviewerNamaLengkap,
    string $interviewerAsalCabang,
    string $updatedBy
): array {
    $bidang = trim($bidang);
    $kandidatNama = trim($kandidatNama);
    $kandidatCabang = trim($kandidatCabang);
    $interviewerLoginUsername = normalize_login_username($interviewerLoginUsername);
    $interviewerNamaLengkap = normalize_username($interviewerNamaLengkap);
    $interviewerAsalCabang = trim($interviewerAsalCabang);
    $updatedBy = normalize_username($updatedBy);

    if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '') {
        return ['ok' => false, 'message' => 'Data kandidat tidak valid untuk assignment pewawancara.'];
    }

    $key = flagging_candidate_key($bidang, $kandidatNama, $kandidatCabang);
    $map = load_wawancara_assignment_map();

    if ($interviewerLoginUsername === '') {
        unset($map[$key]);
    } else {
        $map[$key] = [
            'key' => $key,
            'bidang' => $bidang,
            'kandidat_nama' => $kandidatNama,
            'kandidat_cabang' => $kandidatCabang,
            'interviewer_login_username' => $interviewerLoginUsername,
            'interviewer_nama_lengkap' => $interviewerNamaLengkap,
            'interviewer_asal_cabang' => $interviewerAsalCabang,
            'updated_at' => date('Y-m-d H:i:s', current_time()),
            'updated_by' => $updatedBy,
        ];
    }

    if (!save_wawancara_assignment_map($map)) {
        return ['ok' => false, 'message' => 'Gagal menyimpan assignment pewawancara.'];
    }

    return [
        'ok' => true,
        'message' => $interviewerLoginUsername === ''
            ? 'Assignment pewawancara berhasil dihapus.'
            : 'Assignment pewawancara berhasil diperbarui.',
    ];
}

function find_interviewer_user_by_login_username(array $users, string $loginUsername): ?array
{
    $targetLogin = normalize_login_username($loginUsername);
    if ($targetLogin === '') {
        return null;
    }

    foreach ($users as $user) {
        if (!is_array($user)) {
            continue;
        }
        if (!user_has_role($user, 'pewawancara')) {
            continue;
        }

        $login = normalize_login_username((string)($user['username'] ?? ''));
        if ($login === '' || !hash_equals($login, $targetLogin)) {
            continue;
        }

        return [
            'login_username' => $login,
            'nama_lengkap' => normalize_username((string)($user['nama_lengkap'] ?? $user['username'] ?? '')),
            'asal_cabang' => trim((string)($user['asal_cabang'] ?? '')),
        ];
    }

    return null;
}

function kesediaan_hubungan_options(): array
{
    return [
        'Diri Sendiri (Kandidat)',
        'Suami/Istri',
        'Ibu',
        'Ayah',
        'Anak',
        'Wali/Keluarga',
    ];
}

function kesediaan_single_submit_hubungan_options(): array
{
    return [
        'Diri Sendiri (Kandidat)',
        'Ibu',
        'Ayah',
    ];
}

function kesediaan_is_single_submit_hubungan(string $hubungan): bool
{
    $normalized = normalize_kesediaan_hubungan($hubungan);
    if ($normalized === '') {
        return false;
    }
    return in_array($normalized, kesediaan_single_submit_hubungan_options(), true);
}

function kesediaan_used_single_submit_hubungan(array $candidateForms): array
{
    $singleSet = array_fill_keys(kesediaan_single_submit_hubungan_options(), true);
    $used = [];
    foreach ($candidateForms as $item) {
        if (!is_array($item)) {
            continue;
        }
        $hubungan = normalize_kesediaan_hubungan((string)($item['hubungan'] ?? ''));
        if ($hubungan !== '' && isset($singleSet[$hubungan])) {
            $used[$hubungan] = true;
        }
    }
    return array_keys($used);
}

function normalize_kesediaan_hubungan(string $hubungan): string
{
    $raw = strtolower(trim(normalize_username($hubungan)));
    if ($raw === '') {
        return '';
    }

    $aliasMap = [
        'kandidat' => 'Diri Sendiri (Kandidat)',
        'diri sendiri' => 'Diri Sendiri (Kandidat)',
        'diri sendiri kandidat' => 'Diri Sendiri (Kandidat)',
        'diri sendiri (kandidat)' => 'Diri Sendiri (Kandidat)',
        'pribadi kandidat' => 'Diri Sendiri (Kandidat)',
        'suami' => 'Suami/Istri',
        'istri' => 'Suami/Istri',
        'suami/istri' => 'Suami/Istri',
        'istri/suami' => 'Suami/Istri',
        'ayah' => 'Ayah',
        'ibu' => 'Ibu',
        'anak' => 'Anak',
        'wali' => 'Wali/Keluarga',
        'keluarga' => 'Wali/Keluarga',
        'wali/keluarga' => 'Wali/Keluarga',
    ];

    if (isset($aliasMap[$raw])) {
        return $aliasMap[$raw];
    }

    foreach (kesediaan_hubungan_options() as $allowed) {
        if (strcasecmp($raw, strtolower($allowed)) === 0) {
            return $allowed;
        }
    }
    return '';
}

function normalize_kesediaan_status(string $status): string
{
    $status = strtolower(trim($status));
    return match ($status) {
        'bersedia' => 'bersedia',
        'tidak_bersedia' => 'tidak_bersedia',
        default => '',
    };
}

function normalize_kesediaan_alasan(string $alasan): string
{
    $alasan = str_replace(["\r\n", "\r"], "\n", $alasan);
    $alasan = preg_replace("/[ \t]+/", ' ', $alasan);
    $alasan = is_string($alasan) ? trim($alasan) : '';
    if ($alasan === '') {
        return '';
    }
    if (function_exists('mb_substr')) {
        return mb_substr($alasan, 0, 2000, 'UTF-8');
    }
    return substr($alasan, 0, 2000);
}

function kesediaan_upload_dir(): string
{
    $baseDir = secure_data_dir() . '/uploads';
    $targetDir = $baseDir . '/kesediaan';
    if (!ensure_directory_writable($baseDir)) {
        return '';
    }
    if (!ensure_directory_writable($targetDir)) {
        return '';
    }
    @chmod($baseDir, 0700);
    @chmod($targetDir, 0700);
    return $targetDir;
}

function kesediaan_uploaded_file_absolute_path(string $storedPath): string
{
    $storedPath = trim(str_replace('\\', '/', $storedPath));
    if ($storedPath === '') {
        return '';
    }

    if (strpos($storedPath, 'uploads/kesediaan/') !== 0) {
        return '';
    }

    return secure_data_dir() . '/' . $storedPath;
}

function kesediaan_file_extension(string $value): string
{
    $value = trim($value);
    if ($value === '') {
        return '';
    }
    $ext = strtolower((string)pathinfo($value, PATHINFO_EXTENSION));
    return trim($ext);
}

function kesediaan_is_image_extension(string $ext): bool
{
    return in_array($ext, ['jpg', 'jpeg', 'png', 'webp', 'gif', 'bmp', 'tif', 'tiff', 'heic', 'heif'], true);
}

function kesediaan_form_is_image_document(array $form): bool
{
    $mime = strtolower(trim((string)($form['file_mime'] ?? '')));
    if ($mime !== '' && strpos($mime, 'image/') === 0) {
        return true;
    }

    $originalExt = kesediaan_file_extension((string)($form['file_name_original'] ?? ''));
    if ($originalExt !== '' && kesediaan_is_image_extension($originalExt)) {
        return true;
    }

    $storedExt = kesediaan_file_extension((string)($form['file_path'] ?? ''));
    return $storedExt !== '' && kesediaan_is_image_extension($storedExt);
}

function kesediaan_form_is_pdf_document(array $form): bool
{
    $mime = strtolower(trim((string)($form['file_mime'] ?? '')));
    if ($mime === 'application/pdf') {
        return true;
    }

    $originalExt = kesediaan_file_extension((string)($form['file_name_original'] ?? ''));
    if ($originalExt === 'pdf') {
        return true;
    }

    $storedExt = kesediaan_file_extension((string)($form['file_path'] ?? ''));
    return $storedExt === 'pdf';
}

function kesediaan_form_public_id(array $form): string
{
    $formId = trim((string)($form['form_id'] ?? ''));
    if ($formId !== '') {
        return $formId;
    }

    $seed = trim((string)($form['key'] ?? ''))
        . '|'
        . trim((string)($form['file_path'] ?? ''))
        . '|'
        . trim((string)($form['updated_at'] ?? ''))
        . '|'
        . trim((string)($form['kandidat_nama'] ?? ''))
        . '|'
        . trim((string)($form['kandidat_cabang'] ?? ''));
    return 'legacy_' . sha1($seed);
}

function find_kesediaan_form_by_public_id(string $publicId): ?array
{
    $publicId = trim($publicId);
    if ($publicId === '') {
        return null;
    }

    $formsData = load_kesediaan_form_data();
    foreach ((array)($formsData['forms'] ?? []) as $item) {
        if (!is_array($item)) {
            continue;
        }
        if (!hash_equals(kesediaan_form_public_id($item), $publicId)) {
            continue;
        }
        return $item;
    }

    return null;
}

function kesediaan_form_view_url(array $form, bool $download = false): string
{
    $params = [
        'page' => 'kesediaan_file',
        'form_id' => kesediaan_form_public_id($form),
    ];
    if ($download) {
        $params['download'] = '1';
    }
    return app_index_url($params);
}

function sanitize_download_filename(string $name): string
{
    $name = trim($name);
    if ($name === '') {
        return 'bukti-foto-pertemuan';
    }

    $name = preg_replace('/[^\w.\- ]+/u', '-', $name);
    if (!is_string($name)) {
        return 'bukti-foto-pertemuan';
    }
    $name = trim($name, ".- \t\n\r\0\x0B");
    if ($name === '') {
        return 'bukti-foto-pertemuan';
    }
    return $name;
}

function save_kesediaan_uploaded_file(array $uploadedFile): array
{
    $uploadError = (int)($uploadedFile['error'] ?? UPLOAD_ERR_NO_FILE);
    if ($uploadError !== UPLOAD_ERR_OK) {
        $message = match ($uploadError) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'Ukuran file melebihi batas upload.',
            UPLOAD_ERR_PARTIAL => 'Upload file tidak selesai.',
            UPLOAD_ERR_NO_FILE => 'File bukti foto pertemuan belum dipilih.',
            UPLOAD_ERR_NO_TMP_DIR => 'Folder temporary upload tidak tersedia.',
            UPLOAD_ERR_CANT_WRITE => 'File upload gagal ditulis ke disk.',
            UPLOAD_ERR_EXTENSION => 'Upload file dibatalkan oleh ekstensi PHP.',
            default => 'Terjadi kesalahan saat upload file.',
        };
        return ['ok' => false, 'message' => $message];
    }

    $tmpPath = (string)($uploadedFile['tmp_name'] ?? '');
    if ($tmpPath === '' || !is_uploaded_file($tmpPath)) {
        return ['ok' => false, 'message' => 'File upload tidak valid.'];
    }

    $fileSize = (int)($uploadedFile['size'] ?? 0);
    if ($fileSize <= 0 || $fileSize > KESEDIAAN_UPLOAD_MAX_BYTES) {
        return ['ok' => false, 'message' => 'Ukuran file melebihi batas maksimal 8 MB.'];
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = '';
    if ($finfo !== false) {
        $detected = finfo_file($finfo, $tmpPath);
        finfo_close($finfo);
        if (is_string($detected)) {
            $mimeType = strtolower(trim($detected));
        }
    }

    $allowedMimeExtensions = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp',
        'image/gif' => 'gif',
        'image/bmp' => 'bmp',
        'image/tiff' => 'tif',
        'image/heic' => 'heic',
        'image/heif' => 'heif',
    ];

    if ($mimeType === '' || !isset($allowedMimeExtensions[$mimeType])) {
        return ['ok' => false, 'message' => 'Format file harus gambar (jpg/png/webp/gif/bmp/tiff/heic/heif).'];
    }

    $uploadDir = kesediaan_upload_dir();
    if ($uploadDir === '') {
        return ['ok' => false, 'message' => 'Folder penyimpanan upload tidak tersedia.'];
    }

    $ext = $allowedMimeExtensions[$mimeType];
    $storedFilename = 'foto-pertemuan-' . random_hex(12) . '.' . $ext;
    $targetPath = $uploadDir . '/' . $storedFilename;
    if (!@move_uploaded_file($tmpPath, $targetPath)) {
        return ['ok' => false, 'message' => 'Gagal menyimpan file upload.'];
    }
    @chmod($targetPath, 0600);

    return [
        'ok' => true,
        'stored_path' => 'uploads/kesediaan/' . $storedFilename,
        'stored_filename' => $storedFilename,
        'original_name' => trim((string)($uploadedFile['name'] ?? '')),
        'mime_type' => $mimeType,
        'size' => $fileSize,
    ];
}

function load_kesediaan_form_data(): array
{
    $empty = ['forms' => []];
    $decoded = read_json_file(kesediaan_form_file_path(), $empty);
    if (!is_array($decoded) || !isset($decoded['forms']) || !is_array($decoded['forms'])) {
        return $empty;
    }

    $normalized = [];
    foreach ($decoded['forms'] as $item) {
        if (!is_array($item)) {
            continue;
        }

        $bidang = trim((string)($item['bidang'] ?? ''));
        $kandidatNama = trim((string)($item['kandidat_nama'] ?? ''));
        $kandidatCabang = trim((string)($item['kandidat_cabang'] ?? ''));
        $hubungan = normalize_kesediaan_hubungan((string)($item['hubungan'] ?? ''));
        $namaPihak = normalize_username((string)($item['nama_pihak'] ?? ''));
        $status = normalize_kesediaan_status((string)($item['status_kesediaan'] ?? ''));
        $alasan = normalize_kesediaan_alasan((string)($item['alasan'] ?? ''));
        $filePath = trim((string)($item['file_path'] ?? ''));
        if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '' || $hubungan === '' || $status === '' || $filePath === '') {
            continue;
        }

        $key = kesediaan_candidate_key($kandidatNama, $kandidatCabang);

        $normalized[] = [
            'key' => $key,
            'form_id' => trim((string)($item['form_id'] ?? '')),
            'bidang' => $bidang,
            'kandidat_nama' => $kandidatNama,
            'kandidat_cabang' => $kandidatCabang,
            'hubungan' => $hubungan,
            'nama_pihak' => $namaPihak,
            'status_kesediaan' => $status,
            'alasan' => $alasan,
            'file_path' => $filePath,
            'file_name_original' => trim((string)($item['file_name_original'] ?? '')),
            'file_mime' => trim((string)($item['file_mime'] ?? '')),
            'file_size' => (int)($item['file_size'] ?? 0),
            'interviewer_login_username' => normalize_login_username((string)($item['interviewer_login_username'] ?? '')),
            'interviewer_nama_lengkap' => normalize_username((string)($item['interviewer_nama_lengkap'] ?? '')),
            'updated_at' => trim((string)($item['updated_at'] ?? '')),
            'updated_by' => normalize_username((string)($item['updated_by'] ?? '')),
        ];
    }

    return ['forms' => $normalized];
}

function load_kesediaan_form_map(): array
{
    $data = load_kesediaan_form_data();
    $map = [];
    foreach ((array)($data['forms'] ?? []) as $item) {
        if (!is_array($item)) {
            continue;
        }
        $key = trim((string)($item['key'] ?? ''));
        if ($key === '') {
            continue;
        }
        if (!isset($map[$key])) {
            $map[$key] = [];
        }
        $map[$key][] = $item;
    }

    foreach ($map as $key => $items) {
        if (!is_array($items)) {
            $map[$key] = [];
            continue;
        }
        usort($items, static function (array $a, array $b): int {
            return strcmp((string)($b['updated_at'] ?? ''), (string)($a['updated_at'] ?? ''));
        });
        $map[$key] = $items;
    }
    return $map;
}

function save_kesediaan_form_map(array $map): bool
{
    $forms = [];
    foreach ($map as $key => $items) {
        if (!is_string($key)) {
            continue;
        }

        if (is_array($items) && isset($items['bidang'])) {
            $items = [$items];
        }
        if (!is_array($items)) {
            continue;
        }

        foreach ($items as $item) {
            if (!is_array($item)) {
                continue;
            }

            $bidang = trim((string)($item['bidang'] ?? ''));
            $kandidatNama = trim((string)($item['kandidat_nama'] ?? ''));
            $kandidatCabang = trim((string)($item['kandidat_cabang'] ?? ''));
            $hubungan = normalize_kesediaan_hubungan((string)($item['hubungan'] ?? ''));
            $namaPihak = normalize_username((string)($item['nama_pihak'] ?? ''));
            $status = normalize_kesediaan_status((string)($item['status_kesediaan'] ?? ''));
            $alasan = normalize_kesediaan_alasan((string)($item['alasan'] ?? ''));
            $filePath = trim((string)($item['file_path'] ?? ''));
            if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '' || $hubungan === '' || $status === '' || $filePath === '') {
                continue;
            }

            $forms[] = [
                'key' => $key,
                'form_id' => trim((string)($item['form_id'] ?? '')),
                'bidang' => $bidang,
                'kandidat_nama' => $kandidatNama,
                'kandidat_cabang' => $kandidatCabang,
                'hubungan' => $hubungan,
                'nama_pihak' => $namaPihak,
                'status_kesediaan' => $status,
                'alasan' => $alasan,
                'file_path' => $filePath,
                'file_name_original' => trim((string)($item['file_name_original'] ?? '')),
                'file_mime' => trim((string)($item['file_mime'] ?? '')),
                'file_size' => (int)($item['file_size'] ?? 0),
                'interviewer_login_username' => normalize_login_username((string)($item['interviewer_login_username'] ?? '')),
                'interviewer_nama_lengkap' => normalize_username((string)($item['interviewer_nama_lengkap'] ?? '')),
                'updated_at' => trim((string)($item['updated_at'] ?? '')),
                'updated_by' => normalize_username((string)($item['updated_by'] ?? '')),
            ];
        }
    }

    usort($forms, static function (array $a, array $b): int {
        $left = (string)($a['bidang'] ?? '') . '|' . (string)($a['kandidat_nama'] ?? '') . '|' . (string)($a['kandidat_cabang'] ?? '');
        $right = (string)($b['bidang'] ?? '') . '|' . (string)($b['kandidat_nama'] ?? '') . '|' . (string)($b['kandidat_cabang'] ?? '');
        return strnatcasecmp($left, $right);
    });

    return write_json_file_atomic(kesediaan_form_file_path(), ['forms' => $forms]);
}

function save_kesediaan_form_submission(
    string $bidang,
    string $kandidatNama,
    string $kandidatCabang,
    string $hubungan,
    string $namaPihak,
    string $statusKesediaan,
    string $alasan,
    array $uploadedFile,
    string $interviewerLoginUsername,
    string $interviewerNamaLengkap,
    string $updatedBy
): array {
    $bidang = trim($bidang);
    $kandidatNama = trim($kandidatNama);
    $kandidatCabang = trim($kandidatCabang);
    $hubungan = normalize_kesediaan_hubungan($hubungan);
    $namaPihak = normalize_username($namaPihak);
    $statusKesediaan = normalize_kesediaan_status($statusKesediaan);
    $alasan = normalize_kesediaan_alasan($alasan);
    $interviewerLoginUsername = normalize_login_username($interviewerLoginUsername);
    $interviewerNamaLengkap = normalize_username($interviewerNamaLengkap);
    $updatedBy = normalize_username($updatedBy);

    if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '') {
        return ['ok' => false, 'message' => 'Data kandidat tidak valid untuk form kesediaan.'];
    }
    if ($hubungan === '') {
        return ['ok' => false, 'message' => 'Pihak yang menyatakan kesediaan wajib dipilih.'];
    }
    if ($hubungan === 'Diri Sendiri (Kandidat)') {
        $namaPihak = $kandidatNama;
    }
    if ($namaPihak === '') {
        return ['ok' => false, 'message' => 'Nama lengkap pihak yang menyatakan kesediaan wajib diisi.'];
    }
    if ($statusKesediaan === '') {
        return ['ok' => false, 'message' => 'Status kesediaan wajib dipilih.'];
    }

    $key = kesediaan_candidate_key($kandidatNama, $kandidatCabang);
    $map = load_kesediaan_form_map();
    if (!isset($map[$key]) || !is_array($map[$key])) {
        $map[$key] = [];
    }
    if (kesediaan_is_single_submit_hubungan($hubungan)) {
        foreach ((array)$map[$key] as $existingItem) {
            if (!is_array($existingItem)) {
                continue;
            }
            $existingHubungan = normalize_kesediaan_hubungan((string)($existingItem['hubungan'] ?? ''));
            if ($existingHubungan !== '' && hash_equals($existingHubungan, $hubungan)) {
                return ['ok' => false, 'message' => 'Pihak "' . $hubungan . '" sudah pernah mengisi form untuk kandidat ini.'];
            }
        }
    }

    $uploadResult = save_kesediaan_uploaded_file($uploadedFile);
    if (!($uploadResult['ok'] ?? false)) {
        return ['ok' => false, 'message' => (string)($uploadResult['message'] ?? 'Upload dokumen gagal.')];
    }

    $map[$key][] = [
        'key' => $key,
        'form_id' => generate_id('kesediaan_'),
        'bidang' => $bidang,
        'kandidat_nama' => $kandidatNama,
        'kandidat_cabang' => $kandidatCabang,
        'hubungan' => $hubungan,
        'nama_pihak' => $namaPihak,
        'status_kesediaan' => $statusKesediaan,
        'alasan' => $alasan,
        'file_path' => (string)($uploadResult['stored_path'] ?? ''),
        'file_name_original' => (string)($uploadResult['original_name'] ?? ''),
        'file_mime' => (string)($uploadResult['mime_type'] ?? ''),
        'file_size' => (int)($uploadResult['size'] ?? 0),
        'interviewer_login_username' => $interviewerLoginUsername,
        'interviewer_nama_lengkap' => $interviewerNamaLengkap,
        'updated_at' => date('Y-m-d H:i:s', current_time()),
        'updated_by' => $updatedBy,
    ];

    if (!save_kesediaan_form_map($map)) {
        $newPath = kesediaan_uploaded_file_absolute_path((string)($uploadResult['stored_path'] ?? ''));
        if ($newPath !== '' && is_file($newPath)) {
            @unlink($newPath);
        }
        return ['ok' => false, 'message' => 'Gagal menyimpan data form kesediaan.'];
    }

    return ['ok' => true, 'message' => 'Form kesediaan berhasil disimpan.'];
}

function kesediaan_status_label(string $status): string
{
    return match (normalize_kesediaan_status($status)) {
        'bersedia' => 'Bersedia',
        'tidak_bersedia' => 'Tidak Bersedia',
        default => '-',
    };
}

function kesediaan_interviewer_display_label(array $form): string
{
    $interviewerName = normalize_username((string)($form['interviewer_nama_lengkap'] ?? ''));
    $interviewerLogin = normalize_login_username((string)($form['interviewer_login_username'] ?? ''));
    if ($interviewerName !== '' && $interviewerLogin !== '') {
        return $interviewerName . ' (' . $interviewerLogin . ')';
    }
    if ($interviewerName !== '') {
        return $interviewerName;
    }
    if ($interviewerLogin !== '') {
        return $interviewerLogin;
    }

    $updatedBy = normalize_username((string)($form['updated_by'] ?? ''));
    return $updatedBy !== '' ? $updatedBy : '-';
}

function kesediaan_form_client_payload(array $form): array
{
    $fileName = trim((string)($form['file_name_original'] ?? ''));
    if ($fileName === '') {
        $fileName = trim((string)($form['file_path'] ?? '-'));
    }
    if ($fileName === '') {
        $fileName = '-';
    }

    $updatedAt = trim((string)($form['updated_at'] ?? ''));

    return [
        'hubungan' => (string)($form['hubungan'] ?? '-'),
        'nama_pihak' => (string)($form['nama_pihak'] ?? '-'),
        'status' => kesediaan_status_label((string)($form['status_kesediaan'] ?? '')),
        'alasan' => (string)($form['alasan'] ?? ''),
        'file' => $fileName,
        'file_url' => kesediaan_form_view_url($form),
        'file_download_url' => kesediaan_form_view_url($form, true),
        'file_is_image' => kesediaan_form_is_image_document($form),
        'file_is_pdf' => kesediaan_form_is_pdf_document($form),
        'interviewer_user' => kesediaan_interviewer_display_label($form),
        'updated_at' => $updatedAt !== '' ? $updatedAt : '-',
    ];
}

function build_kesediaan_recap_rows(array $formMap): array
{
    $rows = [];
    foreach ($formMap as $candidateForms) {
        if (!is_array($candidateForms)) {
            continue;
        }

        $validForms = [];
        foreach ($candidateForms as $form) {
            if (is_array($form)) {
                $validForms[] = $form;
            }
        }
        if ($validForms === []) {
            continue;
        }

        usort($validForms, static function (array $a, array $b): int {
            return strcmp((string)($b['updated_at'] ?? ''), (string)($a['updated_at'] ?? ''));
        });

        $firstForm = $validForms[0];
        $candidateName = trim((string)($firstForm['kandidat_nama'] ?? ''));
        if ($candidateName === '') {
            continue;
        }

        $candidateBranch = trim((string)($firstForm['kandidat_cabang'] ?? ''));
        $candidateLabel = display_name_text($candidateName);
        if ($candidateBranch !== '') {
            $candidateLabel .= ' (' . $candidateBranch . ')';
        }

        $bersediaCount = 0;
        $formItems = [];
        $interviewerSeen = [];
        $latestInterviewerUser = '-';
        foreach ($validForms as $index => $form) {
            $statusKey = normalize_kesediaan_status((string)($form['status_kesediaan'] ?? ''));
            if ($statusKey === 'bersedia') {
                $bersediaCount++;
            }

            $payload = kesediaan_form_client_payload($form);
            $formItems[] = $payload;

            $interviewerUser = trim((string)($payload['interviewer_user'] ?? '-'));
            if ($interviewerUser === '') {
                $interviewerUser = '-';
            }
            if ($index === 0) {
                $latestInterviewerUser = $interviewerUser;
            }

            $interviewerKey = normalize_header_key($interviewerUser);
            if ($interviewerKey === '') {
                $interviewerKey = $interviewerUser;
            }
            $interviewerSeen[$interviewerKey] = true;
        }

        $latestUpdatedAtRaw = trim((string)($firstForm['updated_at'] ?? ''));
        $rows[] = [
            'candidate_name' => $candidateName,
            'candidate_branch' => $candidateBranch !== '' ? $candidateBranch : '-',
            'candidate_label' => $candidateLabel,
            'bersedia_count' => $bersediaCount,
            'total_forms' => count($validForms),
            'consent_text' => $bersediaCount . '/' . count($validForms) . ' bersedia',
            'latest_interviewer_user' => $latestInterviewerUser,
            'additional_interviewer_count' => max(0, count($interviewerSeen) - 1),
            'latest_updated_at' => $latestUpdatedAtRaw !== '' ? $latestUpdatedAtRaw : '-',
            'latest_updated_at_sort' => $latestUpdatedAtRaw,
            'form_items' => $formItems,
        ];
    }

    usort($rows, static function (array $a, array $b): int {
        $leftComplete = ((int)($a['total_forms'] ?? 0)) > 0
            && ((int)($a['bersedia_count'] ?? 0)) >= ((int)($a['total_forms'] ?? 0));
        $rightComplete = ((int)($b['total_forms'] ?? 0)) > 0
            && ((int)($b['bersedia_count'] ?? 0)) >= ((int)($b['total_forms'] ?? 0));
        $completeCompare = ((int)$rightComplete) <=> ((int)$leftComplete);
        if ($completeCompare !== 0) {
            return $completeCompare;
        }

        $formCountCompare = ((int)($b['total_forms'] ?? 0)) <=> ((int)($a['total_forms'] ?? 0));
        if ($formCountCompare !== 0) {
            return $formCountCompare;
        }

        $timeCompare = strcmp((string)($b['latest_updated_at_sort'] ?? ''), (string)($a['latest_updated_at_sort'] ?? ''));
        if ($timeCompare !== 0) {
            return $timeCompare;
        }

        $nameCompare = strnatcasecmp((string)($a['candidate_name'] ?? ''), (string)($b['candidate_name'] ?? ''));
        if ($nameCompare !== 0) {
            return $nameCompare;
        }

        return strnatcasecmp((string)($a['candidate_branch'] ?? ''), (string)($b['candidate_branch'] ?? ''));
    });

    return $rows;
}

function scorecard_trim_text(string $value, int $maxLength = 2000): string
{
    $value = str_replace(["\r\n", "\r"], "\n", $value);
    $value = preg_replace("/[ \t]+/", ' ', $value);
    $value = is_string($value) ? trim($value) : '';
    if ($value === '') {
        return '';
    }
    if (function_exists('mb_substr')) {
        return mb_substr($value, 0, $maxLength, 'UTF-8');
    }
    return substr($value, 0, $maxLength);
}

function scorecard_normalize_indicator_list($rawValue): array
{
    $items = [];
    if (is_array($rawValue)) {
        $items = $rawValue;
    } elseif (is_string($rawValue) && trim($rawValue) !== '') {
        $items = preg_split('/\r\n|\r|\n/', $rawValue) ?: [];
    }

    $result = [];
    foreach ($items as $item) {
        $text = scorecard_trim_text((string)$item, 300);
        if ($text !== '') {
            $result[] = $text;
        }
    }

    return $result;
}

function scorecard_normalize_question_definition(array $question, int $index): ?array
{
    $id = strtoupper(trim((string)($question['id'] ?? 'Q' . ($index + 1))));
    $label = scorecard_trim_text((string)($question['label'] ?? ''), 180);
    if ($id === '' || $label === '') {
        return null;
    }

    $minScore = max(1, (int)($question['min_score'] ?? 1));
    $maxScore = max($minScore, (int)($question['max_score'] ?? 5));

    return [
        'id' => $id,
        'label' => $label,
        'low_indicator' => scorecard_normalize_indicator_list($question['low_indicator'] ?? []),
        'high_indicator' => scorecard_normalize_indicator_list($question['high_indicator'] ?? []),
        'min_score' => $minScore,
        'max_score' => $maxScore,
    ];
}

function scorecard_normalize_section_definition(array $section, int $index): ?array
{
    $id = strtoupper(trim((string)($section['id'] ?? chr(65 + $index))));
    $title = scorecard_trim_text((string)($section['title'] ?? ''), 180);
    if ($id === '' || $title === '') {
        return null;
    }

    $weight = (float)($section['weight'] ?? 0);
    if ($weight > 1) {
        $weight /= 100;
    }
    if ($weight <= 0) {
        return null;
    }

    $questions = [];
    foreach ((array)($section['questions'] ?? []) as $questionIndex => $question) {
        if (!is_array($question)) {
            continue;
        }
        $normalizedQuestion = scorecard_normalize_question_definition($question, (int)$questionIndex);
        if ($normalizedQuestion !== null) {
            $questions[] = $normalizedQuestion;
        }
    }
    if ($questions === []) {
        return null;
    }

    return [
        'id' => $id,
        'title' => $title,
        'focus' => scorecard_trim_text((string)($section['focus'] ?? ''), 400),
        'weight' => round($weight, 4),
        'note_label' => scorecard_trim_text((string)($section['note_label'] ?? ('Catatan Bagian ' . $id)), 120),
        'questions' => $questions,
    ];
}

function load_scorecard_template_data(): array
{
    $fallback = default_scorecard_templates_data();
    $decoded = read_json_file(scorecard_template_file_path(), $fallback);
    if (!is_array($decoded)) {
        $decoded = $fallback;
    }

    $templates = [];
    foreach ((array)($decoded['templates'] ?? []) as $templateIndex => $template) {
        if (!is_array($template)) {
            continue;
        }

        $templateKey = trim((string)($template['template_key'] ?? ''));
        if ($templateKey === '') {
            $templateKey = 'template_' . ($templateIndex + 1);
        }
        $templateKey = slugify_identifier($templateKey);
        if ($templateKey === '') {
            continue;
        }

        $title = scorecard_trim_text((string)($template['title'] ?? ''), 180);
        if ($title === '') {
            $title = 'Scorecard Wawancara';
        }

        $bidangTitles = [];
        foreach ((array)($template['bidang_titles'] ?? []) as $bidangTitle) {
            $text = scorecard_trim_text((string)$bidangTitle, 180);
            if ($text !== '') {
                $bidangTitles[] = $text;
            }
        }

        $sections = [];
        foreach ((array)($template['sections'] ?? []) as $sectionIndex => $section) {
            if (!is_array($section)) {
                continue;
            }
            $normalizedSection = scorecard_normalize_section_definition($section, (int)$sectionIndex);
            if ($normalizedSection !== null) {
                $sections[] = $normalizedSection;
            }
        }
        if ($sections === []) {
            continue;
        }

        $decisionOptions = [];
        foreach ((array)($template['decision_options'] ?? default_scorecard_decision_options()) as $decisionOption) {
            $text = scorecard_trim_text((string)$decisionOption, 120);
            if ($text !== '') {
                $decisionOptions[] = $text;
            }
        }
        if ($decisionOptions === []) {
            $decisionOptions = default_scorecard_decision_options();
        }

        $finalRanges = [];
        foreach ((array)($template['final_ranges'] ?? default_scorecard_final_ranges()) as $range) {
            if (!is_array($range)) {
                continue;
            }
            $min = (float)($range['min'] ?? 0);
            $max = (float)($range['max'] ?? 0);
            $label = scorecard_trim_text((string)($range['label'] ?? ''), 120);
            if ($label === '' || $max < $min) {
                continue;
            }
            $finalRanges[] = [
                'min' => round($min, 2),
                'max' => round($max, 2),
                'label' => $label,
            ];
        }
        if ($finalRanges === []) {
            $finalRanges = default_scorecard_final_ranges();
        }

        usort($finalRanges, static function (array $a, array $b): int {
            return ((float)($a['min'] ?? 0)) <=> ((float)($b['min'] ?? 0));
        });

        $templates[] = [
            'template_key' => $templateKey,
            'title' => $title,
            'version' => max(1, (int)($template['version'] ?? 1)),
            'bidang_titles' => $bidangTitles,
            'decision_options' => array_values(array_unique($decisionOptions)),
            'final_ranges' => $finalRanges,
            'sections' => $sections,
        ];
    }

    if ($templates === []) {
        $templates = (array)($fallback['templates'] ?? []);
    }

    $defaultTemplateKey = slugify_identifier((string)($decoded['default_template_key'] ?? ''));
    if ($defaultTemplateKey === '') {
        $defaultTemplateKey = slugify_identifier((string)($fallback['default_template_key'] ?? ''));
    }
    if ($defaultTemplateKey === '') {
        $defaultTemplateKey = (string)($templates[0]['template_key'] ?? '');
    }

    return [
        'default_template_key' => $defaultTemplateKey,
        'templates' => $templates,
    ];
}

function scorecard_bidang_lookup_keys(string $bidang): array
{
    $bidang = trim($bidang);
    if ($bidang === '') {
        return [];
    }

    $keys = [];
    $keys[] = normalize_header_key($bidang);
    $parts = bidang_title_parts($bidang);
    $mainTitle = trim((string)($parts['main'] ?? ''));
    if ($mainTitle !== '') {
        $keys[] = normalize_header_key($mainTitle);
    }
    if (is_ketua_pengurus_lokal_bidang($bidang)) {
        $keys[] = normalize_header_key('Ketua Pengurus Lokal');
    }

    $keys = array_values(array_filter(array_unique($keys), static fn($item): bool => is_string($item) && $item !== ''));
    return $keys;
}

function scorecard_template_matches_bidang(array $template, string $bidang): bool
{
    $lookupKeys = scorecard_bidang_lookup_keys($bidang);
    if ($lookupKeys === []) {
        return false;
    }

    foreach ((array)($template['bidang_titles'] ?? []) as $bidangTitle) {
        $templateKey = normalize_header_key((string)$bidangTitle);
        if ($templateKey !== '' && in_array($templateKey, $lookupKeys, true)) {
            return true;
        }
    }

    return false;
}

function find_scorecard_template_for_bidang(string $bidang): ?array
{
    $data = load_scorecard_template_data();
    $templates = (array)($data['templates'] ?? []);
    foreach ($templates as $template) {
        if (!is_array($template)) {
            continue;
        }
        if (scorecard_template_matches_bidang($template, $bidang)) {
            return $template;
        }
    }

    $defaultKey = trim((string)($data['default_template_key'] ?? ''));
    if ($defaultKey !== '') {
        foreach ($templates as $template) {
            if (!is_array($template)) {
                continue;
            }
            if (hash_equals((string)($template['template_key'] ?? ''), $defaultKey)) {
                return $template;
            }
        }
    }

    return isset($templates[0]) && is_array($templates[0]) ? $templates[0] : null;
}

function scorecard_recommendation_label(array $template, float $finalScore): string
{
    foreach ((array)($template['final_ranges'] ?? []) as $range) {
        if (!is_array($range)) {
            continue;
        }
        $min = (float)($range['min'] ?? 0);
        $max = (float)($range['max'] ?? 0);
        if ($finalScore + 0.00001 >= $min && $finalScore - 0.00001 <= $max) {
            return trim((string)($range['label'] ?? ''));
        }
    }
    return '';
}

function scorecard_calculate_results(array $template, array $answers): array
{
    $sectionResults = [];
    $finalScoreRaw = 0.0;

    foreach ((array)($template['sections'] ?? []) as $section) {
        if (!is_array($section)) {
            continue;
        }

        $sectionId = trim((string)($section['id'] ?? ''));
        if ($sectionId === '') {
            continue;
        }

        $questionCount = 0;
        $answeredCount = 0;
        $sectionTotal = 0.0;
        foreach ((array)($section['questions'] ?? []) as $question) {
            if (!is_array($question)) {
                continue;
            }
            $questionId = trim((string)($question['id'] ?? ''));
            if ($questionId === '') {
                continue;
            }
            $questionCount++;
            if (!array_key_exists($questionId, $answers)) {
                continue;
            }
            $score = (int)$answers[$questionId];
            $sectionTotal += $score;
            $answeredCount++;
        }

        $sectionAverage = $questionCount > 0 ? ($sectionTotal / $questionCount) : 0.0;
        $sectionWeight = (float)($section['weight'] ?? 0);
        $weightedScore = $sectionAverage * $sectionWeight;
        $finalScoreRaw += $weightedScore;

        $sectionResults[$sectionId] = [
            'question_count' => $questionCount,
            'answered_count' => $answeredCount,
            'total' => round($sectionTotal, 2),
            'average' => round($sectionAverage, 2),
            'weight' => round($sectionWeight, 4),
            'weighted_score' => round($weightedScore, 2),
        ];
    }

    $finalScore = round($finalScoreRaw, 2);

    return [
        'section_results' => $sectionResults,
        'final_score' => $finalScore,
        'auto_recommendation' => scorecard_recommendation_label($template, $finalScore),
    ];
}

function load_scorecard_submission_data(): array
{
    $empty = ['submissions' => []];
    $decoded = read_json_file(scorecard_submission_file_path(), $empty);
    if (!is_array($decoded) || !isset($decoded['submissions']) || !is_array($decoded['submissions'])) {
        return $empty;
    }

    $normalized = [];
    foreach ($decoded['submissions'] as $item) {
        if (!is_array($item)) {
            continue;
        }

        $bidang = trim((string)($item['bidang'] ?? ''));
        $kandidatNama = trim((string)($item['kandidat_nama'] ?? ''));
        $kandidatCabang = trim((string)($item['kandidat_cabang'] ?? ''));
        if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '') {
            continue;
        }

        $key = trim((string)($item['key'] ?? ''));
        if ($key === '') {
            $key = flagging_candidate_key($bidang, $kandidatNama, $kandidatCabang);
        }

        $answers = [];
        foreach ((array)($item['answers'] ?? []) as $questionId => $score) {
            $questionId = strtoupper(trim((string)$questionId));
            if ($questionId === '') {
                continue;
            }
            $answers[$questionId] = (int)$score;
        }

        $sectionNotes = [];
        foreach ((array)($item['section_notes'] ?? []) as $sectionId => $note) {
            $sectionId = strtoupper(trim((string)$sectionId));
            if ($sectionId === '') {
                continue;
            }
            $sectionNotes[$sectionId] = scorecard_trim_text((string)$note, 2000);
        }

        $sectionResults = [];
        foreach ((array)($item['section_results'] ?? []) as $sectionId => $resultItem) {
            $sectionId = strtoupper(trim((string)$sectionId));
            if ($sectionId === '' || !is_array($resultItem)) {
                continue;
            }
            $sectionResults[$sectionId] = [
                'question_count' => max(0, (int)($resultItem['question_count'] ?? 0)),
                'answered_count' => max(0, (int)($resultItem['answered_count'] ?? 0)),
                'total' => round((float)($resultItem['total'] ?? 0), 2),
                'average' => round((float)($resultItem['average'] ?? 0), 2),
                'weight' => round((float)($resultItem['weight'] ?? 0), 4),
                'weighted_score' => round((float)($resultItem['weighted_score'] ?? 0), 2),
            ];
        }

        $normalized[] = [
            'key' => $key,
            'submission_id' => trim((string)($item['submission_id'] ?? '')),
            'bidang' => $bidang,
            'kandidat_nama' => $kandidatNama,
            'kandidat_cabang' => $kandidatCabang,
            'template_key' => trim((string)($item['template_key'] ?? '')),
            'template_title' => scorecard_trim_text((string)($item['template_title'] ?? ''), 180),
            'template_version' => max(1, (int)($item['template_version'] ?? 1)),
            'interview_date' => trim((string)($item['interview_date'] ?? '')),
            'location' => scorecard_trim_text((string)($item['location'] ?? ''), 180),
            'answers' => $answers,
            'section_notes' => $sectionNotes,
            'section_results' => $sectionResults,
            'final_score' => round((float)($item['final_score'] ?? 0), 2),
            'auto_recommendation' => scorecard_trim_text((string)($item['auto_recommendation'] ?? ''), 120),
            'interviewer_decision' => scorecard_trim_text((string)($item['interviewer_decision'] ?? ''), 120),
            'decision_note' => scorecard_trim_text((string)($item['decision_note'] ?? ''), 2000),
            'is_submitted' => !empty($item['is_submitted']),
            'submitted_at' => trim((string)($item['submitted_at'] ?? '')),
            'submitted_by' => normalize_username((string)($item['submitted_by'] ?? '')),
            'submitted_by_login_username' => normalize_login_username((string)($item['submitted_by_login_username'] ?? '')),
            'submitted_by_name' => normalize_username((string)($item['submitted_by_name'] ?? '')),
            'updated_at' => trim((string)($item['updated_at'] ?? '')),
            'updated_by' => normalize_username((string)($item['updated_by'] ?? '')),
        ];
    }

    return ['submissions' => $normalized];
}

function load_scorecard_submission_map(): array
{
    $data = load_scorecard_submission_data();
    $map = [];
    foreach ((array)($data['submissions'] ?? []) as $item) {
        if (!is_array($item)) {
            continue;
        }
        $key = trim((string)($item['key'] ?? ''));
        if ($key === '') {
            continue;
        }
        $map[$key] = $item;
    }
    return $map;
}

function save_scorecard_submission_map(array $map): bool
{
    $submissions = [];
    foreach ($map as $key => $item) {
        if (!is_string($key) || !is_array($item)) {
            continue;
        }

        $bidang = trim((string)($item['bidang'] ?? ''));
        $kandidatNama = trim((string)($item['kandidat_nama'] ?? ''));
        $kandidatCabang = trim((string)($item['kandidat_cabang'] ?? ''));
        if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '') {
            continue;
        }

        $submissions[] = [
            'key' => $key,
            'submission_id' => trim((string)($item['submission_id'] ?? '')),
            'bidang' => $bidang,
            'kandidat_nama' => $kandidatNama,
            'kandidat_cabang' => $kandidatCabang,
            'template_key' => trim((string)($item['template_key'] ?? '')),
            'template_title' => scorecard_trim_text((string)($item['template_title'] ?? ''), 180),
            'template_version' => max(1, (int)($item['template_version'] ?? 1)),
            'interview_date' => trim((string)($item['interview_date'] ?? '')),
            'location' => scorecard_trim_text((string)($item['location'] ?? ''), 180),
            'answers' => (array)($item['answers'] ?? []),
            'section_notes' => (array)($item['section_notes'] ?? []),
            'section_results' => (array)($item['section_results'] ?? []),
            'final_score' => round((float)($item['final_score'] ?? 0), 2),
            'auto_recommendation' => scorecard_trim_text((string)($item['auto_recommendation'] ?? ''), 120),
            'interviewer_decision' => scorecard_trim_text((string)($item['interviewer_decision'] ?? ''), 120),
            'decision_note' => scorecard_trim_text((string)($item['decision_note'] ?? ''), 2000),
            'is_submitted' => !empty($item['is_submitted']),
            'submitted_at' => trim((string)($item['submitted_at'] ?? '')),
            'submitted_by' => normalize_username((string)($item['submitted_by'] ?? '')),
            'submitted_by_login_username' => normalize_login_username((string)($item['submitted_by_login_username'] ?? '')),
            'submitted_by_name' => normalize_username((string)($item['submitted_by_name'] ?? '')),
            'updated_at' => trim((string)($item['updated_at'] ?? '')),
            'updated_by' => normalize_username((string)($item['updated_by'] ?? '')),
        ];
    }

    usort($submissions, static function (array $a, array $b): int {
        $left = (string)($a['bidang'] ?? '') . '|' . (string)($a['kandidat_nama'] ?? '') . '|' . (string)($a['kandidat_cabang'] ?? '');
        $right = (string)($b['bidang'] ?? '') . '|' . (string)($b['kandidat_nama'] ?? '') . '|' . (string)($b['kandidat_cabang'] ?? '');
        return strnatcasecmp($left, $right);
    });

    return write_json_file_atomic(scorecard_submission_file_path(), ['submissions' => $submissions]);
}

function save_scorecard_submission(
    string $bidang,
    string $kandidatNama,
    string $kandidatCabang,
    string $interviewDate,
    string $location,
    array $rawAnswers,
    array $rawSectionNotes,
    string $interviewerDecision,
    string $decisionNote,
    string $submittedByLoginUsername,
    string $submittedByName,
    string $updatedBy
): array {
    $bidang = trim($bidang);
    $kandidatNama = trim($kandidatNama);
    $kandidatCabang = trim($kandidatCabang);
    $interviewDate = trim($interviewDate);
    $location = scorecard_trim_text($location, 180);
    $interviewerDecision = scorecard_trim_text($interviewerDecision, 120);
    $decisionNote = scorecard_trim_text($decisionNote, 2000);
    $submittedByLoginUsername = normalize_login_username($submittedByLoginUsername);
    $submittedByName = normalize_username($submittedByName);
    $updatedBy = normalize_username($updatedBy);

    if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '') {
        return ['ok' => false, 'message' => 'Data kandidat tidak valid untuk score card.'];
    }

    $template = find_scorecard_template_for_bidang($bidang);
    if ($template === null) {
        return ['ok' => false, 'message' => 'Template score card untuk bidang ini belum tersedia.'];
    }

    $dateObject = DateTime::createFromFormat('Y-m-d', $interviewDate);
    $dateErrors = DateTime::getLastErrors();
    $hasDateError = is_array($dateErrors) && ((int)($dateErrors['warning_count'] ?? 0) > 0 || (int)($dateErrors['error_count'] ?? 0) > 0);
    if ($interviewDate === '' || !($dateObject instanceof DateTime) || $hasDateError || $dateObject->format('Y-m-d') !== $interviewDate) {
        return ['ok' => false, 'message' => 'Tanggal wawancara wajib diisi dengan format yang valid.'];
    }

    if ($location === '') {
        return ['ok' => false, 'message' => 'Lokasi wawancara wajib diisi.'];
    }

    $answers = [];
    foreach ((array)($template['sections'] ?? []) as $section) {
        if (!is_array($section)) {
            continue;
        }
        foreach ((array)($section['questions'] ?? []) as $question) {
            if (!is_array($question)) {
                continue;
            }
            $questionId = trim((string)($question['id'] ?? ''));
            if ($questionId === '') {
                continue;
            }

            $rawScore = $rawAnswers[$questionId] ?? null;
            $scoreText = trim((string)$rawScore);
            if ($scoreText === '' || !preg_match('/^\d+$/', $scoreText)) {
                return ['ok' => false, 'message' => 'Semua skor pertanyaan wajib diisi.'];
            }

            $score = (int)$scoreText;
            $minScore = max(1, (int)($question['min_score'] ?? 1));
            $maxScore = max($minScore, (int)($question['max_score'] ?? 5));
            if ($score < $minScore || $score > $maxScore) {
                return ['ok' => false, 'message' => 'Nilai score card harus berada pada rentang yang diizinkan.'];
            }

            $answers[$questionId] = $score;
        }
    }

    $sectionNotes = [];
    foreach ((array)($template['sections'] ?? []) as $section) {
        if (!is_array($section)) {
            continue;
        }
        $sectionId = trim((string)($section['id'] ?? ''));
        if ($sectionId === '') {
            continue;
        }
        $sectionNotes[$sectionId] = scorecard_trim_text((string)($rawSectionNotes[$sectionId] ?? ''), 2000);
    }

    $decisionOptions = (array)($template['decision_options'] ?? []);
    if ($interviewerDecision === '' || !in_array($interviewerDecision, $decisionOptions, true)) {
        return ['ok' => false, 'message' => 'Keputusan pewawancara wajib dipilih.'];
    }
    if (stripos($interviewerDecision, 'catatan') !== false && $decisionNote === '') {
        return ['ok' => false, 'message' => 'Catatan keputusan wajib diisi untuk keputusan dengan catatan.'];
    }

    $calculation = scorecard_calculate_results($template, $answers);
    $key = flagging_candidate_key($bidang, $kandidatNama, $kandidatCabang);
    $map = load_scorecard_submission_map();
    $existing = (array)($map[$key] ?? []);

    if ($existing !== [] && !empty($existing['is_submitted'])) {
        return ['ok' => false, 'message' => 'Score card sudah disubmit dan tidak dapat diubah lagi.'];
    }

    $map[$key] = [
        'key' => $key,
        'submission_id' => trim((string)($existing['submission_id'] ?? '')) !== '' ? trim((string)$existing['submission_id']) : generate_id('scorecard_'),
        'bidang' => $bidang,
        'kandidat_nama' => $kandidatNama,
        'kandidat_cabang' => $kandidatCabang,
        'template_key' => trim((string)($template['template_key'] ?? '')),
        'template_title' => trim((string)($template['title'] ?? 'Scorecard Wawancara')),
        'template_version' => max(1, (int)($template['version'] ?? 1)),
        'interview_date' => $interviewDate,
        'location' => $location,
        'answers' => $answers,
        'section_notes' => $sectionNotes,
        'section_results' => (array)($calculation['section_results'] ?? []),
        'final_score' => round((float)($calculation['final_score'] ?? 0), 2),
        'auto_recommendation' => scorecard_trim_text((string)($calculation['auto_recommendation'] ?? ''), 120),
        'interviewer_decision' => $interviewerDecision,
        'decision_note' => $decisionNote,
        'is_submitted' => !empty($existing['is_submitted']),
        'submitted_at' => trim((string)($existing['submitted_at'] ?? '')),
        'submitted_by' => normalize_username((string)($existing['submitted_by'] ?? '')),
        'submitted_by_login_username' => trim((string)($existing['submitted_by_login_username'] ?? '')) !== ''
            ? normalize_login_username((string)$existing['submitted_by_login_username'])
            : $submittedByLoginUsername,
        'submitted_by_name' => trim((string)($existing['submitted_by_name'] ?? '')) !== ''
            ? normalize_username((string)$existing['submitted_by_name'])
            : $submittedByName,
        'updated_at' => date('Y-m-d H:i:s', current_time()),
        'updated_by' => $updatedBy,
    ];

    if (!save_scorecard_submission_map($map)) {
        return ['ok' => false, 'message' => 'Gagal menyimpan score card.'];
    }

    return [
        'ok' => true,
        'message' => $existing !== [] ? 'Score card berhasil diperbarui.' : 'Score card berhasil disimpan.',
        'submission' => $map[$key],
    ];
}

function submit_scorecard_submission(
    string $bidang,
    string $kandidatNama,
    string $kandidatCabang,
    string $submittedBy
): array {
    $bidang = trim($bidang);
    $kandidatNama = trim($kandidatNama);
    $kandidatCabang = trim($kandidatCabang);
    $submittedBy = normalize_username($submittedBy);

    if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '') {
        return ['ok' => false, 'message' => 'Data kandidat tidak valid untuk submit score card.'];
    }

    $key = flagging_candidate_key($bidang, $kandidatNama, $kandidatCabang);
    $map = load_scorecard_submission_map();
    $existing = (array)($map[$key] ?? []);
    if ($existing === []) {
        return ['ok' => false, 'message' => 'Score card belum diisi.'];
    }
    if (!empty($existing['is_submitted'])) {
        return ['ok' => false, 'message' => 'Score card sudah disubmit sebelumnya.'];
    }

    $existing['is_submitted'] = true;
    $existing['submitted_at'] = date('Y-m-d H:i:s', current_time());
    $existing['submitted_by'] = $submittedBy;
    $existing['updated_at'] = (string)$existing['submitted_at'];
    $existing['updated_by'] = $submittedBy;
    $map[$key] = $existing;

    if (!save_scorecard_submission_map($map)) {
        return ['ok' => false, 'message' => 'Gagal submit score card.'];
    }

    return [
        'ok' => true,
        'message' => 'Score card berhasil disubmit dan tidak dapat diubah lagi.',
        'submission' => $map[$key],
    ];
}

function cancel_submitted_scorecard_submission(
    string $bidang,
    string $kandidatNama,
    string $kandidatCabang,
    string $updatedBy
): array {
    $bidang = trim($bidang);
    $kandidatNama = trim($kandidatNama);
    $kandidatCabang = trim($kandidatCabang);
    $updatedBy = normalize_username($updatedBy);

    if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '') {
        return ['ok' => false, 'message' => 'Data kandidat tidak valid untuk batal submit score card.'];
    }

    $key = flagging_candidate_key($bidang, $kandidatNama, $kandidatCabang);
    $map = load_scorecard_submission_map();
    $existing = (array)($map[$key] ?? []);
    if ($existing === []) {
        return ['ok' => false, 'message' => 'Score card kandidat belum tersedia.'];
    }
    if (empty($existing['is_submitted'])) {
        return ['ok' => false, 'message' => 'Score card kandidat belum disubmit.'];
    }

    $existing['is_submitted'] = false;
    $existing['submitted_at'] = '';
    $existing['submitted_by'] = '';
    $existing['submitted_by_login_username'] = '';
    $existing['submitted_by_name'] = '';
    $existing['updated_at'] = date('Y-m-d H:i:s', current_time());
    $existing['updated_by'] = $updatedBy;
    $map[$key] = $existing;

    if (!save_scorecard_submission_map($map)) {
        return ['ok' => false, 'message' => 'Gagal membatalkan submit score card.'];
    }

    return [
        'ok' => true,
        'message' => 'Submit score card berhasil dibatalkan. Score card dapat diedit lagi.',
        'submission' => $map[$key],
    ];
}

function scorecard_template_client_payload(array $template): array
{
    return [
        'template_key' => (string)($template['template_key'] ?? ''),
        'title' => (string)($template['title'] ?? 'Scorecard Wawancara'),
        'version' => (int)($template['version'] ?? 1),
        'sections' => (array)($template['sections'] ?? []),
        'decision_options' => array_values((array)($template['decision_options'] ?? [])),
        'final_ranges' => array_values((array)($template['final_ranges'] ?? [])),
    ];
}

function scorecard_submission_client_payload(array $submission): array
{
    return [
        'submission_id' => (string)($submission['submission_id'] ?? ''),
        'template_key' => (string)($submission['template_key'] ?? ''),
        'template_title' => (string)($submission['template_title'] ?? ''),
        'template_version' => (int)($submission['template_version'] ?? 1),
        'interview_date' => (string)($submission['interview_date'] ?? ''),
        'location' => (string)($submission['location'] ?? ''),
        'answers' => (array)($submission['answers'] ?? []),
        'section_notes' => (array)($submission['section_notes'] ?? []),
        'section_results' => (array)($submission['section_results'] ?? []),
        'final_score' => round((float)($submission['final_score'] ?? 0), 2),
        'auto_recommendation' => (string)($submission['auto_recommendation'] ?? ''),
        'interviewer_decision' => (string)($submission['interviewer_decision'] ?? ''),
        'decision_note' => (string)($submission['decision_note'] ?? ''),
        'is_submitted' => !empty($submission['is_submitted']),
        'submitted_at' => (string)($submission['submitted_at'] ?? ''),
        'submitted_by_name' => (string)($submission['submitted_by_name'] ?? ''),
        'updated_at' => (string)($submission['updated_at'] ?? ''),
    ];
}

function is_candidate_in_top10_summary(array $bidangSummary, string $bidang, string $kandidatNama, string $kandidatCabang): bool
{
    if (!isset($bidangSummary[$bidang]) || !is_array($bidangSummary[$bidang])) {
        return false;
    }

    $topCandidates = (array)($bidangSummary[$bidang]['top_candidates'] ?? []);
    $targetName = normalize_header_key($kandidatNama);
    $targetCabang = normalize_header_key($kandidatCabang);
    foreach ($topCandidates as $candidate) {
        if (!is_array($candidate)) {
            continue;
        }

        $name = normalize_header_key((string)($candidate['nama'] ?? ''));
        $cabang = normalize_header_key((string)($candidate['cabang'] ?? ''));
        if ($name === $targetName && $cabang === $targetCabang) {
            return true;
        }
    }

    return false;
}

function toggle_candidate_flag_status(
    string $bidang,
    string $kandidatNama,
    string $kandidatCabang,
    string $flagType,
    string $updatedBy
): array {
    $bidang = trim($bidang);
    $kandidatNama = trim($kandidatNama);
    $kandidatCabang = trim($kandidatCabang);
    $flagType = trim(strtolower($flagType));
    $updatedBy = trim($updatedBy);

    if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '') {
        return ['ok' => false, 'message' => 'Data kandidat tidak valid untuk proses flagging.'];
    }
    if (!in_array($flagType, ['lanjut', 'screening'], true)) {
        return ['ok' => false, 'message' => 'Jenis flagging tidak valid.'];
    }

    $key = flagging_candidate_key($bidang, $kandidatNama, $kandidatCabang);
    $map = load_flagging_map();
    $record = (array)($map[$key] ?? []);
    $lanjutProses = !empty($record['lanjut_proses']);
    $lolosScreening = !empty($record['lolos_screening']) && $lanjutProses;

    if ($flagType === 'lanjut') {
        $lanjutProses = !$lanjutProses;
        if (!$lanjutProses) {
            $lolosScreening = false;
        }
    } else {
        if (!$lanjutProses) {
            return ['ok' => false, 'message' => 'Kandidat harus ditandai lanjut proses terlebih dahulu.'];
        }
        $lolosScreening = !$lolosScreening;
    }

    if (!$lanjutProses && !$lolosScreening) {
        unset($map[$key]);
    } else {
        $map[$key] = [
            'key' => $key,
            'bidang' => $bidang,
            'kandidat_nama' => $kandidatNama,
            'kandidat_cabang' => $kandidatCabang,
            'lanjut_proses' => $lanjutProses,
            'lolos_screening' => $lolosScreening,
            'updated_at' => date('Y-m-d H:i:s', current_time()),
            'updated_by' => $updatedBy,
        ];
    }

    if (!save_flagging_map($map)) {
        return ['ok' => false, 'message' => 'Gagal menyimpan data flagging.'];
    }

    return [
        'ok' => true,
        'message' => 'Status flagging berhasil diperbarui.',
        'lanjut_proses' => $lanjutProses,
        'lolos_screening' => $lolosScreening,
    ];
}

function mark_candidate_lanjut_proses(
    string $bidang,
    string $kandidatNama,
    string $kandidatCabang,
    string $updatedBy
): array {
    $bidang = trim($bidang);
    $kandidatNama = trim($kandidatNama);
    $kandidatCabang = trim($kandidatCabang);
    $updatedBy = trim($updatedBy);

    if ($bidang === '' || $kandidatNama === '' || $kandidatCabang === '') {
        return ['ok' => false, 'message' => 'Data kandidat tidak valid untuk lanjut proses.'];
    }
    $result = toggle_candidate_flag_status($bidang, $kandidatNama, $kandidatCabang, 'lanjut', $updatedBy);
    if (!($result['ok'] ?? false)) {
        return ['ok' => false, 'message' => (string)($result['message'] ?? 'Gagal menyimpan status lanjut proses.')];
    }

    $isLanjut = !empty($result['lanjut_proses']);
    $result['message'] = $isLanjut
        ? 'Kandidat berhasil ditandai lanjut proses.'
        : 'Status lanjut proses kandidat berhasil dibatalkan.';
    return $result;
}

function csrf_token(): string
{
    $token = $_SESSION['csrf_token'] ?? '';
    if (!is_string($token) || strlen($token) < 32) {
        $token = random_hex(32);
        $_SESSION['csrf_token'] = $token;
    }
    return $token;
}

function is_valid_csrf_token(string $token): bool
{
    if ($token === '') {
        return false;
    }
    $sessionToken = (string)($_SESSION['csrf_token'] ?? '');
    if ($sessionToken === '') {
        return false;
    }
    return hash_equals($sessionToken, $token);
}

function current_time(): int
{
    $override = getenv('MAJELIS_NOW_TS');
    if (is_string($override) && ctype_digit($override)) {
        return (int)$override;
    }
    return time();
}

function auth_fingerprint(): string
{
    $userAgent = trim((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    return hash('sha256', $userAgent);
}

function clear_auth_session(): void
{
    $_SESSION = [];

    if (session_status() === PHP_SESSION_ACTIVE) {
        session_unset();
        session_destroy();
    }

    start_secure_session();
    session_regenerate_id(true);
}

function current_authenticated_user(array $users): ?array
{
    if (!is_logged_in()) {
        return null;
    }

    $sessionNamaLengkap = normalize_username((string)($_SESSION['username'] ?? ''));
    $sessionLoginUsername = normalize_login_username((string)($_SESSION['login_username'] ?? ''));
    $sessionCabang = trim((string)($_SESSION['asal_cabang'] ?? ''));
    $sessionFingerprint = (string)($_SESSION['fingerprint'] ?? '');
    $sessionAuthKey = trim((string)($_SESSION['user_auth_key'] ?? ''));
    if (($sessionNamaLengkap === '' && $sessionLoginUsername === '') || $sessionCabang === '' || $sessionFingerprint === '') {
        return null;
    }
    if (!hash_equals($sessionFingerprint, auth_fingerprint())) {
        return null;
    }

    foreach ($users as $user) {
        if (!is_array($user)) {
            continue;
        }

        $namaLengkap = normalize_username((string)($user['nama_lengkap'] ?? $user['username'] ?? ''));
        $loginUsername = normalize_login_username((string)($user['username'] ?? ''));
        if ($loginUsername === '') {
            $loginUsername = short_username_from_fullname($namaLengkap);
        }
        $cabang = trim((string)($user['asal_cabang'] ?? ''));
        $password = normalize_password((string)($user['password'] ?? ''));
        if ($namaLengkap === '' || $cabang === '') {
            continue;
        }

        $matchedByLogin = $sessionLoginUsername !== '' && hash_equals($sessionLoginUsername, $loginUsername);
        $matchedByNama = hash_equals($sessionNamaLengkap, $namaLengkap);
        $matchedByAuthKey = false;
        if ($sessionAuthKey !== '' && $password !== '') {
            $matchedByAuthKey = hash_equals($sessionAuthKey, hash('sha256', $password));
        }
        $matchedSessionIdentity = false;
        if ($sessionLoginUsername !== '' && $sessionNamaLengkap !== '') {
            // Username login boleh duplikat, jadi wajib cocokkan juga nama lengkap dari sesi.
            $matchedSessionIdentity = $matchedByLogin && $matchedByNama;
        } elseif ($sessionLoginUsername !== '') {
            $matchedSessionIdentity = $matchedByLogin;
        } elseif ($sessionNamaLengkap !== '') {
            $matchedSessionIdentity = $matchedByNama;
        }

        if ($sessionAuthKey !== '' && !$matchedByAuthKey) {
            continue;
        }

        if ($matchedSessionIdentity && hash_equals($sessionCabang, $cabang)) {
            $roles = user_roles_from_record($user);
            return [
                'username' => $namaLengkap,
                'login_username' => $loginUsername,
                'asal_cabang' => $cabang,
                'role' => (string)($roles[0] ?? 'user'),
                'roles' => $roles,
            ];
        }
    }

    return null;
}

function login_rate_user_key(string $username, string $ipAddress): string
{
    return hash('sha256', strtolower(trim($username)) . '|' . trim($ipAddress));
}

function login_rate_ip_key(string $ipAddress): string
{
    return hash('sha256', 'ip|' . trim($ipAddress));
}

function normalize_login_rate_records(array $records, int $now): array
{
    $normalized = [];
    foreach ($records as $key => $record) {
        if (!is_string($key) || !is_array($record)) {
            continue;
        }

        $attempts = [];
        foreach ((array)($record['attempts'] ?? []) as $ts) {
            $ts = (int)$ts;
            if ($ts > 0 && ($now - $ts) <= LOGIN_WINDOW_SECONDS) {
                $attempts[] = $ts;
            }
        }

        $blockedUntil = max(0, (int)($record['blocked_until'] ?? 0));
        if ($blockedUntil > 0 && $blockedUntil <= $now) {
            $blockedUntil = 0;
        }

        if ($attempts !== [] || $blockedUntil > 0) {
            $normalized[$key] = [
                'attempts' => $attempts,
                'blocked_until' => $blockedUntil,
            ];
        }
    }

    return $normalized;
}

function login_rate_status(string $username, string $ipAddress): array
{
    $now = current_time();
    $data = load_login_rate_data();
    $records = normalize_login_rate_records((array)($data['records'] ?? []), $now);
    $data['records'] = $records;
    save_login_rate_data($data);

    $keys = [
        login_rate_user_key($username, $ipAddress),
        login_rate_ip_key($ipAddress),
    ];
    $blockedUntil = 0;
    foreach ($keys as $key) {
        $record = (array)($records[$key] ?? []);
        $candidateBlockedUntil = max(0, (int)($record['blocked_until'] ?? 0));
        if ($candidateBlockedUntil > $blockedUntil) {
            $blockedUntil = $candidateBlockedUntil;
        }
    }

    if ($blockedUntil > $now) {
        return [
            'allowed' => false,
            'retry_after_seconds' => $blockedUntil - $now,
        ];
    }

    return [
        'allowed' => true,
        'retry_after_seconds' => 0,
    ];
}

function register_failed_login(string $username, string $ipAddress): void
{
    $now = current_time();
    $data = load_login_rate_data();
    $records = normalize_login_rate_records((array)($data['records'] ?? []), $now);
    $targets = [
        [login_rate_user_key($username, $ipAddress), LOGIN_MAX_ATTEMPTS],
        [login_rate_ip_key($ipAddress), LOGIN_MAX_ATTEMPTS_PER_IP],
    ];

    foreach ($targets as [$key, $maxAttempts]) {
        $record = (array)($records[$key] ?? ['attempts' => [], 'blocked_until' => 0]);
        $attempts = [];
        foreach ((array)($record['attempts'] ?? []) as $ts) {
            $ts = (int)$ts;
            if ($ts > 0 && ($now - $ts) <= LOGIN_WINDOW_SECONDS) {
                $attempts[] = $ts;
            }
        }
        $attempts[] = $now;

        $blockedUntil = max(0, (int)($record['blocked_until'] ?? 0));
        if (count($attempts) >= (int)$maxAttempts) {
            $blockedUntil = $now + LOGIN_BLOCK_SECONDS;
            $attempts = [];
        }

        $records[$key] = [
            'attempts' => $attempts,
            'blocked_until' => $blockedUntil,
        ];
    }

    if (count($records) > 2000) {
        $records = array_slice($records, -2000, null, true);
    }

    $data['records'] = $records;
    save_login_rate_data($data);
}

function clear_login_rate_record(string $username, string $ipAddress): void
{
    $data = load_login_rate_data();
    $records = (array)($data['records'] ?? []);
    $changed = false;
    foreach ([login_rate_user_key($username, $ipAddress), login_rate_ip_key($ipAddress)] as $key) {
        if (isset($records[$key])) {
            unset($records[$key]);
            $changed = true;
        }
    }

    if ($changed) {
        $data['records'] = $records;
        save_login_rate_data($data);
    }
}

function write_locked_stream($handle, string $content): bool
{
    $length = strlen($content);
    $writtenTotal = 0;
    while ($writtenTotal < $length) {
        $chunk = fwrite($handle, substr($content, $writtenTotal));
        if ($chunk === false || $chunk === 0) {
            return false;
        }
        $writtenTotal += $chunk;
    }
    return true;
}

function client_ip_address(): string
{
    $candidates = [
        (string)($_SERVER['HTTP_CLIENT_IP'] ?? ''),
        (string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''),
        (string)($_SERVER['REMOTE_ADDR'] ?? ''),
    ];

    foreach ($candidates as $candidate) {
        $candidate = trim($candidate);
        if ($candidate === '') {
            continue;
        }

        if (strpos($candidate, ',') !== false) {
            $parts = explode(',', $candidate);
            $candidate = trim((string)($parts[0] ?? ''));
        }

        if ($candidate !== '') {
            return $candidate;
        }
    }

    return '-';
}

function append_vote_log(array $detail): void
{
    $path = vote_log_file_path();
    $handle = @fopen($path, 'c+');
    if ($handle === false) {
        return;
    }
    if (!flock($handle, LOCK_EX)) {
        fclose($handle);
        return;
    }

    rewind($handle);
    $raw = stream_get_contents($handle);
    $decoded = is_string($raw) ? json_decode($raw, true) : null;
    $data = (is_array($decoded) && isset($decoded['logs']) && is_array($decoded['logs']))
        ? $decoded
        : ['logs' => []];

    $kandidat = (array)($detail['kandidat'] ?? []);
    $userAgent = trim((string)($_SERVER['HTTP_USER_AGENT'] ?? '-'));
    if ($userAgent === '') {
        $userAgent = '-';
    }
    $userAgent = substr($userAgent, 0, 250);

    $data['logs'][] = [
        'log_id' => generate_id('log_'),
        'event' => 'vote_saved',
        'timestamp' => date('Y-m-d H:i:s', current_time()),
        'vote_id' => (string)($detail['id'] ?? ''),
        'username' => (string)($detail['username'] ?? ''),
        'asal_cabang_user' => (string)($detail['asal_cabang_user'] ?? ''),
        'bidang' => (string)($detail['bidang'] ?? ''),
        'kandidat_nama' => (string)($kandidat['nama_lengkap'] ?? ''),
        'kandidat_cabang' => (string)($kandidat['asal_cabang'] ?? ''),
        'ip_address' => client_ip_address(),
        'user_agent' => $userAgent,
    ];

    if (count($data['logs']) > 5000) {
        $data['logs'] = array_slice($data['logs'], -5000);
    }

    $encoded = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    if (!is_string($encoded)) {
        flock($handle, LOCK_UN);
        fclose($handle);
        return;
    }

    rewind($handle);
    ftruncate($handle, 0);
    write_locked_stream($handle, $encoded . PHP_EOL);
    fflush($handle);
    flock($handle, LOCK_UN);
    fclose($handle);
}

function save_pemilihan_detail(array $detail): bool
{
    $path = pemilihan_file_path();
    $handle = @fopen($path, 'c+');
    if ($handle === false) {
        return false;
    }
    if (!flock($handle, LOCK_EX)) {
        fclose($handle);
        return false;
    }

    rewind($handle);
    $raw = stream_get_contents($handle);
    $decoded = is_string($raw) ? json_decode($raw, true) : null;
    $data = (is_array($decoded) && isset($decoded['pemilihan']) && is_array($decoded['pemilihan']))
        ? $decoded
        : ['pemilihan' => []];

    $username = (string)($detail['username'] ?? '');
    $asalCabangUser = trim((string)($detail['asal_cabang_user'] ?? ''));
    $bidang = normalize_vote_bidang_title((string)($detail['bidang'] ?? ''), $asalCabangUser);
    $detail['bidang'] = $bidang;
    foreach (($data['pemilihan'] ?? []) as $item) {
        if (!is_array($item)) {
            continue;
        }

        $itemUser = (string)($item['username'] ?? '');
        $itemBidang = normalize_vote_bidang_title(
            (string)($item['bidang'] ?? ''),
            (string)($item['asal_cabang_user'] ?? '')
        );
        if ($itemUser === $username && $itemBidang === $bidang) {
            flock($handle, LOCK_UN);
            fclose($handle);
            return false;
        }
    }

    $data['pemilihan'][] = $detail;

    $encoded = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    if (!is_string($encoded)) {
        flock($handle, LOCK_UN);
        fclose($handle);
        return false;
    }

    rewind($handle);
    ftruncate($handle, 0);
    $saved = write_locked_stream($handle, $encoded . PHP_EOL);
    fflush($handle);
    flock($handle, LOCK_UN);
    fclose($handle);

    if ($saved) {
        append_vote_log($detail);
    }

    return $saved;
}

function latest_pemilihan_for(string $username, string $bidang): ?array
{
    $data = load_pemilihan_data();
    $items = $data['pemilihan'] ?? [];
    if (!is_array($items)) {
        return null;
    }

    for ($i = count($items) - 1; $i >= 0; $i--) {
        $item = $items[$i];
        if (!is_array($item)) {
            continue;
        }

        $itemUser = (string)($item['username'] ?? '');
        $itemBidang = normalize_vote_bidang_title(
            (string)($item['bidang'] ?? ''),
            (string)($item['asal_cabang_user'] ?? '')
        );
        if ($itemUser === $username && $itemBidang === $bidang) {
            return $item;
        }
    }

    return null;
}

function user_voted_bidang_map(string $username): array
{
    $data = load_pemilihan_data();
    $items = $data['pemilihan'] ?? [];
    if (!is_array($items)) {
        return [];
    }

    $result = [];
    foreach ($items as $item) {
        if (!is_array($item)) {
            continue;
        }

        $itemUser = (string)($item['username'] ?? '');
        $itemBidang = trim(normalize_vote_bidang_title(
            (string)($item['bidang'] ?? ''),
            (string)($item['asal_cabang_user'] ?? '')
        ));
        if ($itemUser === $username && $itemBidang !== '') {
            $result[$itemBidang] = true;
        }
    }

    return $result;
}

function user_vote_detail_map(string $username): array
{
    $data = load_pemilihan_data();
    $items = $data['pemilihan'] ?? [];
    if (!is_array($items)) {
        return [];
    }

    $result = [];
    foreach ($items as $item) {
        if (!is_array($item)) {
            continue;
        }

        $itemUser = (string)($item['username'] ?? '');
        $itemBidang = trim(normalize_vote_bidang_title(
            (string)($item['bidang'] ?? ''),
            (string)($item['asal_cabang_user'] ?? '')
        ));
        if ($itemUser === $username && $itemBidang !== '') {
            $item['bidang'] = $itemBidang;
            $result[$itemBidang] = $item;
        }
    }

    return $result;
}

function has_user_completed_all_votes(string $username, string $asalCabang): bool
{
    if ($username === '' || $asalCabang === '') {
        return false;
    }

    $bidangList = personalize_bidang_list_for_cabang(load_bidang_data(), $asalCabang);
    $totalBidang = count($bidangList);
    if ($totalBidang === 0) {
        return false;
    }

    $votedMap = user_voted_bidang_map($username);
    $votedCount = count($votedMap);

    return $votedCount >= $totalBidang;
}

$page = route_page();
$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$error = '';
$electionClosed = is_election_closed();
$usersForLogin = load_user_data();
$loginSelectedUsername = substr(normalize_login_username((string)($_POST['username'] ?? '')), 0, 120);
$csrfFormToken = csrf_token();
$clientIp = client_ip_address();

if ($page === '') {
    redirect_to_page('login');
}

if ($page === 'logout') {
    if ($method !== 'POST') {
        http_response_code(405);
        exit('405 - Method tidak diizinkan.');
    }

    $logoutToken = trim((string)($_POST['csrf_token'] ?? ''));
    if (!is_valid_csrf_token($logoutToken)) {
        http_response_code(400);
        exit('400 - Permintaan tidak valid.');
    }
    clear_auth_session();
    redirect_to_page('login');
}

if ($page === 'login' && $method === 'POST') {
    $postedCsrfToken = trim((string)($_POST['csrf_token'] ?? ''));
    $password = substr(normalize_password((string)($_POST['password'] ?? '')), 0, 255);

    if (!is_valid_csrf_token($postedCsrfToken)) {
        $error = 'Sesi tidak valid. Muat ulang halaman lalu coba login kembali.';
    } else {
        $rateStatus = login_rate_status($loginSelectedUsername, $clientIp);
        if (!$rateStatus['allowed']) {
            $retryMinutes = (int)ceil(((int)$rateStatus['retry_after_seconds']) / 60);
            $retryMinutes = max(1, $retryMinutes);
            $error = 'Terlalu banyak percobaan login. Coba lagi dalam ' . $retryMinutes . ' menit.';
        } elseif ($loginSelectedUsername === '' || $password === '') {
            $error = 'Silakan isi username dan password terlebih dahulu.';
        } else {
            $foundUser = find_user_for_login($usersForLogin, $loginSelectedUsername, $password);

            if ($foundUser === null) {
                register_failed_login($loginSelectedUsername, $clientIp);
                $error = 'Username atau password salah.';
            } else {
                $foundRole = primary_role_from_record($foundUser);

                if ($electionClosed && !in_array($foundRole, ['admin', 'pewawancara', 'gembala_lokal'], true)) {
                    register_failed_login($loginSelectedUsername, $clientIp);
                    $error = 'Masa pemilihan sudah berakhir pada ' . ELECTION_DEADLINE_LABEL . '.';
                } elseif ($foundRole === 'user') {
                    // Cek apakah user biasa sudah menyelesaikan vote semua bidang.
                    $foundNamaLengkap = normalize_username((string)($foundUser['nama_lengkap'] ?? $foundUser['username'] ?? ''));
                    $foundCabang = trim((string)($foundUser['asal_cabang'] ?? ''));
                    if (has_user_completed_all_votes($foundNamaLengkap, $foundCabang)) {
                        $error = 'Anda sudah menyelesaikan seluruh proses pemilihan. Terima kasih atas partisipasi Anda!';
                    } else {
                        clear_login_rate_record($loginSelectedUsername, $clientIp);
                        session_regenerate_id(true);
                        $_SESSION['logged_in'] = true;
                        $_SESSION['username'] = $foundNamaLengkap;
                        $_SESSION['login_username'] = normalize_login_username((string)($foundUser['username'] ?? ''));
                        $_SESSION['asal_cabang'] = $foundCabang;
                        sync_session_roles($foundUser);
                        $_SESSION['user_auth_key'] = hash('sha256', normalize_password((string)($foundUser['password'] ?? '')));
                        $_SESSION['fingerprint'] = auth_fingerprint();
                        $_SESSION['csrf_token'] = random_hex(32);
                        redirect_to_page('bidang');
                    }
                } else {
                    clear_login_rate_record($loginSelectedUsername, $clientIp);
                    session_regenerate_id(true);
                    $_SESSION['logged_in'] = true;
                    $_SESSION['username'] = normalize_username((string)($foundUser['nama_lengkap'] ?? $foundUser['username'] ?? ''));
                    $_SESSION['login_username'] = normalize_login_username((string)($foundUser['username'] ?? ''));
                    $_SESSION['asal_cabang'] = trim((string)$foundUser['asal_cabang']);
                    sync_session_roles($foundUser);
                    $_SESSION['user_auth_key'] = hash('sha256', normalize_password((string)($foundUser['password'] ?? '')));
                    $_SESSION['fingerprint'] = auth_fingerprint();
                    $_SESSION['csrf_token'] = random_hex(32);
                    redirect_to_page('bidang');
                }
            }
        }
    }
}

if ($page === 'kesediaan_file') {
    $authUser = current_authenticated_user($usersForLogin);
    if ($authUser === null) {
        http_response_code(403);
        exit('403 - Akses ditolak.');
    }
    if (!can_access_wawancara_user($authUser)) {
        http_response_code(403);
        exit('403 - Akses ditolak.');
    }

    $formPublicId = trim((string)($_GET['form_id'] ?? ''));
    if ($formPublicId === '') {
        http_response_code(400);
        exit('400 - Permintaan tidak valid.');
    }

    $formRecord = find_kesediaan_form_by_public_id($formPublicId);
    if ($formRecord === null) {
        http_response_code(404);
        exit('404 - File tidak ditemukan.');
    }

    $storedPath = trim((string)($formRecord['file_path'] ?? ''));
    $absolutePath = kesediaan_uploaded_file_absolute_path($storedPath);
    if ($absolutePath === '' || !is_file($absolutePath)) {
        http_response_code(404);
        exit('404 - File tidak ditemukan.');
    }

    $mimeType = strtolower(trim((string)($formRecord['file_mime'] ?? '')));
    if ($mimeType === '') {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo !== false) {
            $detected = finfo_file($finfo, $absolutePath);
            finfo_close($finfo);
            if (is_string($detected)) {
                $mimeType = strtolower(trim($detected));
            }
        }
    }
    $originalName = trim((string)($formRecord['file_name_original'] ?? ''));
    $originalExt = kesediaan_file_extension($originalName);
    $storedExt = kesediaan_file_extension($storedPath);
    if (($mimeType === '' || $mimeType === 'application/octet-stream') && ($originalExt === 'pdf' || $storedExt === 'pdf')) {
        $mimeType = 'application/pdf';
    }
    if ($mimeType === '') {
        $mimeType = 'application/octet-stream';
    }

    $fileSize = @filesize($absolutePath);
    $downloadRequested = trim((string)($_GET['download'] ?? '')) === '1';
    $isInlineAllowed = strpos($mimeType, 'image/') === 0 || $mimeType === 'application/pdf';
    $disposition = (!$downloadRequested && $isInlineAllowed) ? 'inline' : 'attachment';
    $fileName = sanitize_download_filename($originalName);
    if ($fileName === 'bukti-foto-pertemuan') {
        $ext = kesediaan_file_extension($storedPath);
        if ($ext !== '') {
            $fileName .= '.' . $ext;
        }
    }

    // Endpoint ini perlu bisa tampil di iframe modal (same-origin) untuk preview PDF.
    header_remove('X-Frame-Options');
    header_remove('Content-Security-Policy');
    header('X-Frame-Options: SAMEORIGIN');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'self';");

    header('Content-Type: ' . $mimeType);
    if (is_int($fileSize) && $fileSize > 0) {
        header('Content-Length: ' . (string)$fileSize);
    }
    header('Content-Disposition: ' . $disposition . '; filename="' . addcslashes($fileName, "\"\\") . '"');
    header('X-Content-Type-Options: nosniff');

    $handle = @fopen($absolutePath, 'rb');
    if ($handle === false) {
        http_response_code(500);
        exit('500 - Gagal membaca file.');
    }
    fpassthru($handle);
    fclose($handle);
    exit;
}

if ($page === 'bidang') {
    $authUser = current_authenticated_user($usersForLogin);
    if ($authUser === null) {
        clear_auth_session();
        redirect_to_page('login');
    }

    $username = (string)$authUser['username'];
    $asalCabang = (string)$authUser['asal_cabang'];
    $isAdmin = user_has_role($authUser, 'admin');
    $canAccessWawancara = can_access_wawancara_user($authUser);
    $canAccessGembalaLokal = can_access_gembala_lokal_user($authUser);
    sync_session_roles($authUser);

    if ($asalCabang === '') {
        $asalCabang = '-';
    }

    $bidangList = personalize_bidang_list_for_cabang(load_bidang_data(), $asalCabang);
    $votedDetailMap = user_vote_detail_map($username);
    $votedBidangMap = array_fill_keys(array_keys($votedDetailMap), true);
    $votingOpen = !$electionClosed;
    $logoutToken = csrf_token();

    $infoMessage = '';
    $infoMessageKey = '';
    $infoMessageVars = [];
    $info = trim((string)($_GET['info'] ?? ''));
    $infoBidang = trim((string)($_GET['bidang'] ?? ''));
    if ($info === 'sudah-vote' && $infoBidang !== '' && isset($votedBidangMap[$infoBidang])) {
        $infoMessage = 'Anda sudah melakukan vote pada ' . $infoBidang . '. Silakan pilih bidang lainnya.';
        $infoMessageKey = 'info_already_voted';
        $infoMessageVars = [
            'bidang' => $infoBidang,
            'bidang_en' => bidang_display_title($infoBidang, 'en'),
        ];
    } elseif ($info === 'vote-berhasil' && $infoBidang !== '' && isset($votedBidangMap[$infoBidang])) {
        $infoMessage = 'Vote untuk ' . $infoBidang . ' berhasil disimpan.';
        $infoMessageKey = 'info_vote_saved';
        $infoMessageVars = [
            'bidang' => $infoBidang,
            'bidang_en' => bidang_display_title($infoBidang, 'en'),
        ];
    } elseif ($info === 'admin-only') {
        $infoMessage = 'Halaman ini hanya dapat diakses oleh admin.';
        $infoMessageKey = 'info_admin_only';
    } elseif ($info === 'wawancara-only') {
        $infoMessage = 'Halaman wawancara hanya dapat diakses oleh admin atau pewawancara.';
        $infoMessageKey = 'info_interview_only';
    } elseif ($info === 'gembala-local-only') {
        $infoMessage = 'Halaman pantauan cabang hanya dapat diakses oleh gembala lokal.';
        $infoMessageKey = 'info_branch_only';
    } elseif ($info === 'masa-berakhir') {
        $infoMessage = 'Masa pemilihan sudah berakhir pada ' . ELECTION_DEADLINE_LABEL . '.';
        $infoMessageKey = 'info_voting_ended';
        $infoMessageVars = ['date' => ELECTION_DEADLINE_LABEL];
    }
    ?>
    <!doctype html>
    <html lang="id">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>PeMa REC Indonesia</title>
        <link rel="icon" type="image/png" href="logo.png">
        <style>
            * { box-sizing: border-box; }
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%);
                color: #111827;
                min-height: 100vh;
                padding: 24px 16px;
            }
            .card {
                width: 100%;
                max-width: 980px;
                background: #fff;
                border-radius: 16px;
                padding: 28px;
                border: 1px solid #e5e7eb;
                box-shadow: 0 16px 40px rgba(15, 23, 42, 0.08);
                margin: 0 auto;
            }
            h1 {
                margin: 0;
                font-size: 28px;
            }
            p {
                margin: 0 0 16px;
                line-height: 1.5;
                color: #4b5563;
            }
            .topbar {
                display: flex;
                gap: 16px;
                flex-wrap: wrap;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 22px;
            }
            .topbar-copy {
                flex: 1 1 320px;
                min-width: 0;
            }
            .top-actions {
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
                align-items: center;
                justify-content: flex-end;
                flex: 0 1 auto;
            }
            .btn {
                display: inline-block;
                text-decoration: none;
                background: #111827;
                color: #fff;
                padding: 8px 12px;
                border-radius: 7px;
                font-size: 13px;
                line-height: 1.2;
                font-weight: 600;
                border: 0;
                cursor: pointer;
                white-space: nowrap;
            }
            .btn:focus-visible {
                outline: 3px solid #93c5fd;
                outline-offset: 2px;
            }
            .logout-form {
                margin: 0;
                display: flex;
            }
            .logout-form .btn {
                width: 100%;
            }
            @media (max-width: 760px) {
                .topbar {
                    align-items: flex-start;
                }
                .top-actions {
                    width: 100%;
                    justify-content: flex-start;
                }
            }
            .btn-dashboard {
                background: #2563eb;
            }
            .btn-dashboard:hover {
                background: #1d4ed8;
            }
            .btn-kandidat {
                background: #475569;
            }
            .btn-kandidat:hover {
                background: #334155;
            }
            .btn-wawancara {
                background: #0f766e;
            }
            .btn-wawancara:hover {
                background: #0d9488;
            }
            .btn-gembala {
                background: #1d4ed8;
            }
            .btn-gembala:hover {
                background: #1e40af;
            }
            .btn-consent-recap {
                background: #b45309;
            }
            .btn-consent-recap:hover {
                background: #92400e;
            }
            .grid {
                display: grid;
                gap: 16px;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                grid-auto-rows: 1fr;
            }
            .bidang-item {
                border: 1px solid #e5e7eb;
                border-radius: 12px;
                padding: 16px;
                background: #f9fafb;
                display: flex;
                flex-direction: column;
                gap: 12px;
                justify-content: space-between;
                height: 100%;
                transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease, background 0.15s ease, opacity 0.15s ease;
            }
            .bidang-item.active {
                background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
                border-color: #94a3b8;
                box-shadow: 0 8px 20px rgba(15, 23, 42, 0.1);
            }
            .bidang-item.active:hover {
                transform: translateY(-2px);
                box-shadow: 0 14px 28px rgba(15, 23, 42, 0.15);
            }
            .bidang-item.inactive {
                background: #f0fdf4;
                border-color: #86efac;
                box-shadow: none;
                opacity: 0.94;
            }
            .bidang-item.inactive .bidang-title {
                color: #166534;
            }
            .bidang-item.inactive .bidang-cabang {
                color: #166534;
            }
            .bidang-item.inactive .picked-candidate {
                background: #dcfce7;
                border-color: #4ade80;
                color: #14532d;
            }
            .bidang-title {
                margin: 0;
                font-size: 18px;
                font-weight: 700;
                color: #111827;
                text-align: center;
            }
            .bidang-cabang {
                margin: -6px 0 0;
                font-size: 13px;
                font-weight: 700;
                color: #475569;
                text-align: center;
            }
            .picked-candidate {
                margin: 0;
                padding: 8px 10px;
                border-radius: 8px;
                background: #ecfdf5;
                border: 1px solid #86efac;
                color: #14532d;
                font-size: 13px;
                line-height: 1.45;
                text-align: center;
                min-height: 52px;
            }
            .picked-label {
                display: block;
                margin-bottom: 4px;
                font-weight: 600;
            }
            .picked-name {
                display: block;
                font-weight: 700;
            }
            .picked-candidate.empty {
                background: #f3f4f6;
                border: 1px dashed #d1d5db;
                color: #6b7280;
            }
            .btn-pilih {
                display: inline-block;
                text-decoration: none;
                text-align: center;
                background: #4b5563;
                color: #fff;
                padding: 10px 12px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                border: 0;
                cursor: pointer;
                box-shadow: 0 6px 14px rgba(75, 85, 99, 0.28);
                transition: transform 0.15s ease, box-shadow 0.15s ease, background 0.15s ease, opacity 0.15s ease;
            }
            .btn-pilih:hover {
                background: #374151;
                transform: translateY(-1px);
                box-shadow: 0 10px 18px rgba(55, 65, 81, 0.34);
            }
            .btn-pilih:active {
                transform: translateY(0);
            }
            .btn-pilih:focus-visible {
                outline: 3px solid #9ca3af;
                outline-offset: 2px;
            }
            .btn-pilih.voted {
                background: #bbf7d0;
                color: #14532d;
                border: 1px solid #4ade80;
                cursor: not-allowed;
                box-shadow: none;
                opacity: 0.88;
                transform: none;
                pointer-events: none;
            }
            .btn-pilih.voted:hover {
                background: #bbf7d0;
                box-shadow: none;
            }
            .btn-pilih.closed {
                background: #e5e7eb;
                color: #475569;
                border: 1px solid #cbd5e1;
                cursor: not-allowed;
                box-shadow: none;
                opacity: 0.95;
                pointer-events: none;
            }
            .alert-info {
                margin-bottom: 16px;
                padding: 10px 12px;
                border-radius: 8px;
                background: #e0f2fe;
                color: #0c4a6e;
                font-size: 14px;
            }
            @media (max-width: 900px) {
                .grid {
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                }
            }
            @media (max-width: 640px) {
                .card {
                    padding: 18px;
                }
                h1 {
                    font-size: 22px;
                }
                .top-actions {
                    display: grid;
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                    width: 100%;
                }
                .top-actions .btn,
                .top-actions .logout-form {
                    width: 100%;
                }
                .top-actions .btn {
                    text-align: center;
                }
                .grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
        <?php render_language_switcher_head(); ?>
    </head>
    <body>
        <section class="card">
            <div class="topbar">
                <div class="topbar-copy">
                    <h1 data-i18n="bidang_title">Halaman Pemilihan</h1>
                    <p data-i18n-html="bidang_intro" data-i18n-vars="<?= h((string)json_encode(['username' => h_name($username), 'branch' => h($asalCabang)], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>">Pilih bidang yang diinginkan. Login sebagai <strong><?= h_name($username) ?></strong> (<?= h($asalCabang) ?>).</p>
                </div>
                <div class="top-actions">
                    <?php if ($isAdmin): ?>
                        <a class="btn btn-dashboard" href="<?= h(app_index_url(['page' => 'dashboard'])) ?>" data-i18n="nav_dashboard">Dashboard</a>
                        <a class="btn btn-kandidat" href="<?= h(app_index_url(['page' => 'kandidat'])) ?>" data-i18n="nav_candidate">Kandidat</a>
                        <a class="btn btn-consent-recap" href="<?= h(app_index_url(['page' => 'rekap_kesediaan'])) ?>" data-i18n="nav_consent_recap">Rekap Kesediaan</a>
                    <?php endif; ?>
                    <?php if ($canAccessWawancara): ?>
                        <a class="btn btn-wawancara" href="<?= h(app_index_url(['page' => 'wawancara'])) ?>" data-i18n="nav_interview">Wawancara</a>
                    <?php endif; ?>
                    <?php if ($canAccessGembalaLokal): ?>
                        <a class="btn btn-gembala" href="<?= h(app_index_url(['page' => 'gembala_lokal'])) ?>" data-i18n="nav_branch_monitor">Pantauan Cabang</a>
                    <?php endif; ?>
                    <form class="logout-form" method="post" action="<?= h(app_index_url(['page' => 'logout'])) ?>">
                        <input type="hidden" name="csrf_token" value="<?= h($logoutToken) ?>">
                        <button class="btn" type="submit" data-i18n="nav_logout">Logout</button>
                    </form>
                </div>
            </div>

            <?php if ($infoMessage !== ''): ?>
                <div
                    class="alert-info"
                    <?= $infoMessageKey !== '' ? 'data-i18n="' . h($infoMessageKey) . '"' : '' ?>
                    <?= $infoMessageVars !== [] ? 'data-i18n-vars="' . h((string)json_encode($infoMessageVars, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '"' : '' ?>
                ><?= h($infoMessage) ?></div>
            <?php endif; ?>

            <div class="grid">
                <?php foreach ($bidangList as $bidangItem): ?>
                    <?php
                    $bidangTitle = (string)$bidangItem['title'];
                    $bidangParts = bidang_title_parts($bidangTitle);
                    $bidangMainTitle = (string)($bidangParts['main'] ?? $bidangTitle);
                    if ($bidangMainTitle === '') {
                        $bidangMainTitle = $bidangTitle;
                    }
                    $bidangCabangTitle = (string)($bidangParts['cabang'] ?? '');
                    $isVoted = isset($votedBidangMap[$bidangTitle]);
                    $pickedName = 'Belum dipilih';
                    if ($isVoted) {
                        $voteDetail = $votedDetailMap[$bidangTitle] ?? [];
                        $pickedName = trim((string)($voteDetail['kandidat']['nama_lengkap'] ?? ''));
                        if ($pickedName === '') {
                            $pickedName = '-';
                        }
                    }
                    ?>
                    <article class="bidang-item<?= $isVoted ? ' inactive' : ' active' ?>">
                        <h2 class="bidang-title" data-lang-text-id="<?= h($bidangMainTitle) ?>" data-lang-text-en="<?= h(bidang_translate_main_title($bidangMainTitle, 'en')) ?>"><?= h($bidangMainTitle) ?></h2>
                        <?php if ($bidangCabangTitle !== ''): ?>
                            <p class="bidang-cabang"><?= h($bidangCabangTitle) ?></p>
                        <?php endif; ?>
                        <p class="picked-candidate<?= $isVoted ? '' : ' empty' ?>">
                            <span class="picked-label" data-i18n="picked_candidate_label">Kandidat terpilih:</span>
                            <span
                                class="picked-name"
                                data-lang-text-id="<?= h($isVoted ? display_name_text($pickedName) : $pickedName) ?>"
                                data-lang-text-en="<?= h($isVoted ? display_name_text($pickedName) : 'Not selected yet') ?>"
                            ><?= h($isVoted ? display_name_text($pickedName) : $pickedName) ?></span>
                        </p>
                        <?php if ($isVoted): ?>
                            <button class="btn-pilih voted" type="button" disabled data-i18n="bidang_status_voted">Sudah Vote</button>
                        <?php elseif (!$votingOpen): ?>
                            <button class="btn-pilih closed" type="button" disabled data-i18n="bidang_status_closed">Pemilihan Ditutup</button>
                        <?php else: ?>
                            <a class="btn-pilih" href="<?= h(app_index_url(['page' => 'pemilihan', 'bidang' => $bidangTitle])) ?>" data-i18n="bidang_choose_now">Pilih Sekarang</a>
                        <?php endif; ?>
                    </article>
                <?php endforeach; ?>
            </div>
        </section>
        <?php render_language_switcher(); ?>
        <?php render_language_script([
            'bidang_title' => ['id' => 'Halaman Pemilihan', 'en' => 'Voting Page'],
            'bidang_intro' => ['id' => 'Pilih bidang yang diinginkan. Login sebagai <strong>{username}</strong> ({branch}).', 'en' => 'Choose the position you want. Signed in as <strong>{username}</strong> ({branch}).'],
            'nav_dashboard' => ['id' => 'Dashboard', 'en' => 'Dashboard'],
            'nav_candidate' => ['id' => 'Kandidat', 'en' => 'Candidates'],
            'nav_consent_recap' => ['id' => 'Rekap Kesediaan', 'en' => 'Consent Recap'],
            'nav_interview' => ['id' => 'Wawancara', 'en' => 'Interviews'],
            'nav_branch_monitor' => ['id' => 'Pantauan Cabang', 'en' => 'Branch Monitor'],
            'nav_logout' => ['id' => 'Logout', 'en' => 'Logout'],
            'picked_candidate_label' => ['id' => 'Kandidat terpilih:', 'en' => 'Selected candidate:'],
            'bidang_status_voted' => ['id' => 'Sudah Vote', 'en' => 'Already Voted'],
            'bidang_status_closed' => ['id' => 'Pemilihan Ditutup', 'en' => 'Voting Closed'],
            'bidang_choose_now' => ['id' => 'Pilih Sekarang', 'en' => 'Choose Now'],
            'info_already_voted' => ['id' => 'Anda sudah melakukan vote pada {bidang}. Silakan pilih bidang lainnya.', 'en' => 'You have already voted for {bidang_en}. Please choose another position.'],
            'info_vote_saved' => ['id' => 'Vote untuk {bidang} berhasil disimpan.', 'en' => 'Your vote for {bidang_en} was saved successfully.'],
            'info_admin_only' => ['id' => 'Halaman ini hanya dapat diakses oleh admin.', 'en' => 'This page can only be accessed by admins.'],
            'info_interview_only' => ['id' => 'Halaman wawancara hanya dapat diakses oleh admin atau pewawancara.', 'en' => 'The interview page can only be accessed by admins or interviewers.'],
            'info_branch_only' => ['id' => 'Halaman pantauan cabang hanya dapat diakses oleh gembala lokal.', 'en' => 'The branch monitoring page can only be accessed by local pastors.'],
            'info_voting_ended' => ['id' => 'Masa pemilihan sudah berakhir pada {date}.', 'en' => 'The voting period ended on {date}.'],
        ]); ?>
    </body>
    </html>
    <?php
    exit;
}

if ($page === 'gembala_lokal') {
    $authUser = current_authenticated_user($usersForLogin);
    if ($authUser === null) {
        clear_auth_session();
        redirect_to_page('login');
    }
    if (!can_access_gembala_lokal_user($authUser)) {
        redirect_to_page('bidang', ['info' => 'gembala-local-only']);
    }

    $username = (string)$authUser['username'];
    $asalCabang = trim((string)$authUser['asal_cabang']);
    sync_session_roles($authUser);
    if ($asalCabang === '') {
        $asalCabang = '-';
    }

    $logoutToken = csrf_token();
    $allUsers = load_user_data();
    $allBidang = load_bidang_data();
    $cabangKey = normalize_header_key($asalCabang);
    $bidangCabangList = personalize_bidang_list_for_cabang($allBidang, $asalCabang);
    $bidangCabangMap = [];
    foreach ($bidangCabangList as $bidangItem) {
        if (!is_array($bidangItem)) {
            continue;
        }
        $bidangTitle = trim((string)($bidangItem['title'] ?? ''));
        if ($bidangTitle !== '') {
            $bidangCabangMap[$bidangTitle] = true;
        }
    }
    $totalBidangCabang = count($bidangCabangMap);

    $voteItems = (array)(load_pemilihan_data()['pemilihan'] ?? []);
    $voteCountByUser = [];
    foreach ($voteItems as $voteItem) {
        if (!is_array($voteItem)) {
            continue;
        }

        $voteCabang = trim((string)($voteItem['asal_cabang_user'] ?? ''));
        if ($voteCabang === '' || normalize_header_key($voteCabang) !== $cabangKey) {
            continue;
        }

        $voteUser = normalize_username((string)($voteItem['username'] ?? ''));
        if ($voteUser === '') {
            continue;
        }

        $voteBidang = normalize_vote_bidang_title((string)($voteItem['bidang'] ?? ''), $voteCabang);
        if ($voteBidang === '' || !isset($bidangCabangMap[$voteBidang])) {
            continue;
        }

        if (!isset($voteCountByUser[$voteUser])) {
            $voteCountByUser[$voteUser] = [];
        }
        $voteCountByUser[$voteUser][$voteBidang] = true;
    }

    $branchUsers = [];
    foreach ($allUsers as $userItem) {
        if (!is_array($userItem)) {
            continue;
        }

        $userCabang = trim((string)($userItem['asal_cabang'] ?? ''));
        if ($userCabang === '' || normalize_header_key($userCabang) !== $cabangKey) {
            continue;
        }
        if (user_has_role($userItem, 'admin')) {
            continue;
        }

        $namaLengkap = normalize_username((string)($userItem['nama_lengkap'] ?? $userItem['username'] ?? ''));
        $loginUsername = normalize_login_username((string)($userItem['username'] ?? ''));
        if ($namaLengkap === '' || $loginUsername === '') {
            continue;
        }

        $filledBidang = isset($voteCountByUser[$namaLengkap]) ? count((array)$voteCountByUser[$namaLengkap]) : 0;
        $remainingBidang = max(0, $totalBidangCabang - $filledBidang);
        $statusKey = $remainingBidang <= 0
            ? 'selesai'
            : ($filledBidang > 0 ? 'belum_lengkap' : 'belum_vote');
        $statusLabel = match ($statusKey) {
            'selesai' => 'Selesai',
            'belum_lengkap' => 'Belum Lengkap',
            default => 'Belum Vote',
        };

        $branchUsers[] = [
            'nama_lengkap' => $namaLengkap,
            'login_username' => $loginUsername,
            'filled_bidang' => $filledBidang,
            'remaining_bidang' => $remainingBidang,
            'total_bidang' => $totalBidangCabang,
            'status_key' => $statusKey,
            'status_label' => $statusLabel,
        ];
    }

    usort($branchUsers, static function (array $a, array $b): int {
        $priority = [
            'belum_vote' => 0,
            'belum_lengkap' => 1,
            'selesai' => 2,
        ];
        $statusCompare = ($priority[(string)($a['status_key'] ?? '')] ?? 99)
            <=> ($priority[(string)($b['status_key'] ?? '')] ?? 99);
        if ($statusCompare !== 0) {
            return $statusCompare;
        }
        return strnatcasecmp((string)($a['nama_lengkap'] ?? ''), (string)($b['nama_lengkap'] ?? ''));
    });

    $pendingUsers = [];
    $belumVoteCount = 0;
    $belumLengkapCount = 0;
    $selesaiCount = 0;
    foreach ($branchUsers as $branchUser) {
        $statusKey = (string)($branchUser['status_key'] ?? '');
        if ($statusKey === 'belum_vote') {
            $belumVoteCount++;
            $pendingUsers[] = $branchUser;
        } elseif ($statusKey === 'belum_lengkap') {
            $belumLengkapCount++;
            $pendingUsers[] = $branchUser;
        } else {
            $selesaiCount++;
        }
    }
    $totalUserCabang = count($branchUsers);
    ?>
    <!doctype html>
    <html lang="id">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>PeMa REC Indonesia</title>
        <link rel="icon" type="image/png" href="logo.png">
        <style>
            * { box-sizing: border-box; }
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%);
                color: #111827;
                min-height: 100vh;
                padding: 24px 16px;
            }
            .wrap {
                width: 100%;
                max-width: 1080px;
                margin: 0 auto;
            }
            .panel {
                background: #fff;
                border: 1px solid #e5e7eb;
                border-radius: 18px;
                padding: 28px;
                box-shadow: 0 16px 40px rgba(15, 23, 42, 0.08);
            }
            .topbar {
                display: flex;
                gap: 16px;
                justify-content: space-between;
                align-items: flex-start;
                flex-wrap: wrap;
                margin-bottom: 20px;
            }
            .topbar-copy {
                flex: 1 1 320px;
                min-width: 0;
            }
            h1 {
                margin: 0 0 10px;
                font-size: 30px;
                color: #111827;
            }
            p {
                margin: 0;
                color: #475569;
                line-height: 1.6;
            }
            .top-actions {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                justify-content: flex-end;
            }
            .btn-back {
                display: inline-block;
                text-decoration: none;
                background: #111827;
                color: #fff;
                padding: 10px 16px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                border: 0;
            }
            .btn-back:hover {
                background: #0f172a;
            }
            .btn-back:focus-visible {
                outline: 3px solid #93c5fd;
                outline-offset: 2px;
            }
            .summary-grid {
                display: grid;
                gap: 14px;
                grid-template-columns: repeat(4, minmax(0, 1fr));
                margin-bottom: 18px;
            }
            .summary-card {
                background: #f8fafc;
                border: 1px solid #dbeafe;
                border-radius: 14px;
                padding: 16px;
            }
            .summary-label {
                display: block;
                font-size: 13px;
                font-weight: 700;
                color: #2563eb;
                margin-bottom: 8px;
                text-transform: uppercase;
                letter-spacing: 0.04em;
            }
            .summary-value {
                display: block;
                font-size: 28px;
                font-weight: 800;
                color: #111827;
                line-height: 1.1;
            }
            .summary-note {
                margin-top: 6px;
                font-size: 13px;
                color: #64748b;
            }
            .info-box,
            .empty-box {
                border-radius: 14px;
                padding: 14px 16px;
                margin-bottom: 18px;
                border: 1px solid #bae6fd;
                background: #e0f2fe;
                color: #0c4a6e;
            }
            .empty-box {
                border-color: #86efac;
                background: #f0fdf4;
                color: #166534;
            }
            .table-wrap {
                overflow-x: auto;
                border: 1px solid #e5e7eb;
                border-radius: 16px;
                background: #fff;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                min-width: 720px;
            }
            th,
            td {
                padding: 14px 16px;
                border-bottom: 1px solid #e5e7eb;
                text-align: left;
                vertical-align: top;
                font-size: 14px;
            }
            th {
                background: #f8fafc;
                color: #475569;
                font-size: 13px;
                text-transform: uppercase;
                letter-spacing: 0.04em;
            }
            tr:last-child td {
                border-bottom: 0;
            }
            .status-badge {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                min-width: 116px;
                padding: 7px 10px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: 700;
            }
            .status-badge.belum-vote {
                background: #fee2e2;
                color: #991b1b;
            }
            .status-badge.belum-lengkap {
                background: #fef3c7;
                color: #92400e;
            }
            .progress-text {
                font-weight: 700;
                color: #111827;
            }
            .section-title {
                margin: 0 0 12px;
                font-size: 20px;
                color: #111827;
            }
            @media (max-width: 900px) {
                .summary-grid {
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                }
            }
            @media (max-width: 640px) {
                body {
                    padding: 14px;
                }
                .panel {
                    padding: 18px;
                }
                h1 {
                    font-size: 24px;
                }
                .summary-grid {
                    grid-template-columns: 1fr;
                }
                .top-actions {
                    width: 100%;
                    justify-content: flex-start;
                }
                .top-actions .btn-back {
                    width: 100%;
                }
            }
        </style>
        <?php render_language_switcher_head(); ?>
    </head>
    <body>
        <div class="wrap">
            <section class="panel">
                <div class="topbar">
                    <div class="topbar-copy">
                        <h1 data-i18n="gembala_title">Pantauan Vote Cabang</h1>
                    </div>
                    <div class="top-actions">
                        <a class="btn-back" href="<?= h(app_index_url(['page' => 'bidang'])) ?>" data-i18n="gembala_back">Kembali ke Halaman Bidang</a>
                    </div>
                </div>

                <div class="summary-grid">
                    <div class="summary-card">
                        <span class="summary-label" data-i18n="gembala_summary_users">User Cabang</span>
                        <strong class="summary-value"><?= (int)$totalUserCabang ?></strong>
                        <p class="summary-note" data-i18n="gembala_summary_users_note">Total user non-admin pada cabang ini.</p>
                    </div>
                    <div class="summary-card">
                        <span class="summary-label" data-i18n="gembala_summary_not_voted">Belum Vote</span>
                        <strong class="summary-value"><?= (int)$belumVoteCount ?></strong>
                        <p class="summary-note" data-i18n="gembala_summary_not_voted_note">Belum mengisi vote sama sekali.</p>
                    </div>
                    <div class="summary-card">
                        <span class="summary-label" data-i18n="gembala_summary_incomplete">Belum Lengkap</span>
                        <strong class="summary-value"><?= (int)$belumLengkapCount ?></strong>
                        <p class="summary-note" data-i18n="gembala_summary_incomplete_note">Sudah mulai vote, tetapi belum selesai.</p>
                    </div>
                    <div class="summary-card">
                        <span class="summary-label" data-i18n="gembala_summary_done">Selesai</span>
                        <strong class="summary-value"><?= (int)$selesaiCount ?></strong>
                        <p class="summary-note" data-i18n="gembala_summary_done_note" data-i18n-vars="<?= h((string)json_encode(['count' => (int)$totalBidangCabang], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>">Sudah mengisi seluruh <?= (int)$totalBidangCabang ?> bidang cabang ini.</p>
                    </div>
                </div>

                <?php if ($pendingUsers === []): ?>
                    <div class="empty-box" data-i18n="gembala_empty">Semua user cabang ini sudah menyelesaikan vote.</div>
                <?php else: ?>
                    <h2 class="section-title" data-i18n="gembala_section_pending">User Yang Belum Menyelesaikan Vote</h2>
                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th data-i18n="gembala_table_name">Nama Lengkap</th>
                                    <th data-i18n="gembala_table_username">Username</th>
                                    <th data-i18n="gembala_table_progress">Progress Vote</th>
                                    <th data-i18n="gembala_table_remaining">Sisa Bidang</th>
                                    <th data-i18n="gembala_table_status">Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($pendingUsers as $pendingUser): ?>
                                    <?php
                                    $statusKey = (string)($pendingUser['status_key'] ?? '');
                                    $statusClass = $statusKey === 'belum_lengkap' ? 'belum-lengkap' : 'belum-vote';
                                    ?>
                                    <tr>
                                        <td><?= h_name((string)($pendingUser['nama_lengkap'] ?? '-')) ?></td>
                                        <td><?= h((string)($pendingUser['login_username'] ?? '-')) ?></td>
                                        <td>
                                            <span class="progress-text">
                                                <?= (int)($pendingUser['filled_bidang'] ?? 0) ?>/<?= (int)($pendingUser['total_bidang'] ?? 0) ?>
                                            </span>
                                        </td>
                                        <td><?= (int)($pendingUser['remaining_bidang'] ?? 0) ?></td>
                                        <td>
                                            <span class="status-badge <?= h($statusClass) ?>">
                                                <?= h((string)($pendingUser['status_label'] ?? '-')) ?>
                                            </span>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </section>
        </div>
        <?php render_language_switcher(); ?>
        <?php render_language_script([
            'gembala_title' => ['id' => 'Pantauan Vote Cabang', 'en' => 'Branch Voting Monitor'],
            'gembala_back' => ['id' => 'Kembali ke Halaman Bidang', 'en' => 'Back to Positions'],
            'gembala_summary_users' => ['id' => 'User Cabang', 'en' => 'Branch Users'],
            'gembala_summary_users_note' => ['id' => 'Total user non-admin pada cabang ini.', 'en' => 'Total non-admin users in this branch.'],
            'gembala_summary_not_voted' => ['id' => 'Belum Vote', 'en' => 'Not Yet Voted'],
            'gembala_summary_not_voted_note' => ['id' => 'Belum mengisi vote sama sekali.', 'en' => 'Have not submitted any votes yet.'],
            'gembala_summary_incomplete' => ['id' => 'Belum Lengkap', 'en' => 'Incomplete'],
            'gembala_summary_incomplete_note' => ['id' => 'Sudah mulai vote, tetapi belum selesai.', 'en' => 'Started voting, but not finished yet.'],
            'gembala_summary_done' => ['id' => 'Selesai', 'en' => 'Completed'],
            'gembala_summary_done_note' => ['id' => 'Sudah mengisi seluruh {count} bidang cabang ini.', 'en' => 'Completed all {count} positions for this branch.'],
            'gembala_empty' => ['id' => 'Semua user cabang ini sudah menyelesaikan vote.', 'en' => 'All users in this branch have completed voting.'],
            'gembala_section_pending' => ['id' => 'User Yang Belum Menyelesaikan Vote', 'en' => 'Users Who Have Not Finished Voting'],
            'gembala_table_name' => ['id' => 'Nama Lengkap', 'en' => 'Full Name'],
            'gembala_table_username' => ['id' => 'Username', 'en' => 'Username'],
            'gembala_table_progress' => ['id' => 'Progress Vote', 'en' => 'Voting Progress'],
            'gembala_table_remaining' => ['id' => 'Sisa Bidang', 'en' => 'Remaining Positions'],
            'gembala_table_status' => ['id' => 'Status', 'en' => 'Status'],
        ]); ?>
    </body>
    </html>
    <?php
    exit;
}

if ($page === 'dashboard' || $page === 'kandidat') {
    $authUser = current_authenticated_user($usersForLogin);
    if ($authUser === null) {
        clear_auth_session();
        redirect_to_page('login');
    }
    if (!user_has_role($authUser, 'admin')) {
        redirect_to_page('bidang', ['info' => 'admin-only']);
    }

    $username = (string)$authUser['username'];
    $asalCabang = trim((string)$authUser['asal_cabang']);
    $isDashboardPage = $page === 'dashboard';
    $isKandidatPage = $page === 'kandidat';
    $kandidatAllowedProcessFilters = ['all', 'belum_lanjut', 'lanjut', 'screening', 'scorecard_submitted'];
    $kandidatProcessFilter = normalize_query_choice((string)($_GET['kandidat_filter'] ?? ''), $kandidatAllowedProcessFilters, 'all');
    $kandidatPageParams = ['page' => 'kandidat'];
    if ($kandidatProcessFilter !== 'all') {
        $kandidatPageParams['kandidat_filter'] = $kandidatProcessFilter;
    }
    sync_session_roles($authUser);
    if ($asalCabang === '') {
        $asalCabang = '-';
    }
    $dashboardElectionClosed = $electionClosed;
    $dashboardLogoutToken = csrf_token();
    $dashboardAction = trim((string)($_POST['dashboard_action'] ?? ''));
    $importSuccessMessage = '';
    $importErrors = [];
    $importWarnings = [];
    $flaggingSuccessMessage = '';
    $flaggingErrorMessage = '';

    if ($method === 'POST' && $dashboardAction === 'import_excel') {
        $postedCsrfToken = trim((string)($_POST['csrf_token'] ?? ''));
        if (!is_valid_csrf_token($postedCsrfToken)) {
            $importErrors[] = 'Sesi tidak valid. Muat ulang halaman dashboard lalu coba lagi.';
        } elseif (!isset($_FILES['excel_file']) || !is_array($_FILES['excel_file'])) {
            $importErrors[] = 'File Excel tidak ditemukan.';
        } else {
            $uploadedFile = $_FILES['excel_file'];
            $uploadError = (int)($uploadedFile['error'] ?? UPLOAD_ERR_NO_FILE);
            if ($uploadError !== UPLOAD_ERR_OK) {
                $importErrors[] = upload_error_message($uploadError);
            } else {
                $originalName = trim((string)($uploadedFile['name'] ?? ''));
                $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
                $fileSize = (int)($uploadedFile['size'] ?? 0);
                $tmpPath = (string)($uploadedFile['tmp_name'] ?? '');

                if ($extension !== 'xlsx') {
                    $importErrors[] = 'Format file harus .xlsx sesuai template.';
                } elseif ($fileSize <= 0 || $fileSize > IMPORT_MAX_BYTES) {
                    $importErrors[] = 'Ukuran file harus lebih kecil dari ' . (int)(IMPORT_MAX_BYTES / (1024 * 1024)) . ' MB.';
                } elseif ($tmpPath === '' || !is_uploaded_file($tmpPath)) {
                    $importErrors[] = 'File upload tidak valid.';
                } else {
                    $importResult = import_users_and_kandidat_from_xlsx($tmpPath);
                    $importWarnings = (array)($importResult['warnings'] ?? []);

                    if (!(bool)($importResult['ok'] ?? false)) {
                        $importErrors = array_merge($importErrors, (array)($importResult['errors'] ?? ['Import gagal diproses.']));
                    } else {
                        $summary = (array)($importResult['summary'] ?? []);
                        $importSuccessMessage = 'Import selesai. '
                            . 'User baru: ' . (int)($summary['users_inserted'] ?? 0) . ', '
                            . 'user diperbarui: ' . (int)($summary['users_updated'] ?? 0) . ', '
                            . 'kandidat baru: ' . (int)($summary['kandidat_inserted'] ?? 0) . ', '
                            . 'kandidat diperbarui: ' . (int)($summary['kandidat_updated'] ?? 0) . '.';
                    }
                }
            }
        }
    }

    $rawVotes = load_pemilihan_data();
    $voteItems = $rawVotes['pemilihan'] ?? [];
    if (!is_array($voteItems)) {
        $voteItems = [];
    }

    $totalVotes = 0;
    $uniqueVoterMap = [];
    $uniqueVotePairMap = [];
    $userBidangMap = [];
    $bidangSummary = [];
    foreach ($voteItems as $vote) {
        if (!is_array($vote)) {
            continue;
        }

        $totalVotes++;
        $voter = trim((string)($vote['username'] ?? ''));
        if ($voter !== '') {
            $uniqueVoterMap[$voter] = true;
        }

        $bidang = trim((string)($vote['bidang'] ?? '-'));
        if ($bidang === '') {
            $bidang = '-';
        }

        $normalizedVoter = normalize_username($voter);
        if ($normalizedVoter !== '' && $bidang !== '-') {
            $pairKey = $normalizedVoter . '||' . $bidang;
            $uniqueVotePairMap[$pairKey] = true;

            if (!isset($userBidangMap[$normalizedVoter])) {
                $userBidangMap[$normalizedVoter] = [];
            }
            $userBidangMap[$normalizedVoter][$bidang] = true;
        }

        $candidateName = trim((string)($vote['kandidat']['nama_lengkap'] ?? '-'));
        if ($candidateName === '') {
            $candidateName = '-';
        }
        $candidateCabang = trim((string)($vote['kandidat']['asal_cabang'] ?? '-'));
        if ($candidateCabang === '') {
            $candidateCabang = '-';
        }

        if (!isset($bidangSummary[$bidang])) {
            $bidangSummary[$bidang] = [
                'total' => 0,
                'candidates' => [],
            ];
        }

        $bidangSummary[$bidang]['total']++;

        $candidateKey = $candidateName . '||' . $candidateCabang;
        if (!isset($bidangSummary[$bidang]['candidates'][$candidateKey])) {
            $bidangSummary[$bidang]['candidates'][$candidateKey] = [
                'nama' => $candidateName,
                'cabang' => $candidateCabang,
                'count' => 0,
            ];
        }
        $bidangSummary[$bidang]['candidates'][$candidateKey]['count']++;
    }

    foreach ($bidangSummary as $bidang => $summary) {
        uasort($summary['candidates'], static function (array $a, array $b): int {
            $countCompare = $b['count'] <=> $a['count'];
            if ($countCompare !== 0) {
                return $countCompare;
            }
            return strcmp((string)$a['nama'], (string)$b['nama']);
        });
        $sortedCandidates = array_values($summary['candidates']);
        $bidangSummary[$bidang]['candidates'] = $sortedCandidates;
        $bidangSummary[$bidang]['candidate_total'] = count($sortedCandidates);
        $bidangSummary[$bidang]['top_candidates'] = array_slice($sortedCandidates, 0, 10);
    }

    $orderedBidangSummary = [];
    $orderedAssigned = [];
    $allBidang = load_bidang_data();
    $cabangOrderMap = [];
    foreach (known_cabang_values() as $idx => $cabangItem) {
        $cabangKey = normalize_header_key((string)$cabangItem);
        if ($cabangKey !== '' && !isset($cabangOrderMap[$cabangKey])) {
            $cabangOrderMap[$cabangKey] = (int)$idx;
        }
    }

    foreach ($allBidang as $bidangItem) {
        if (!is_array($bidangItem)) {
            continue;
        }

        $orderTitle = trim((string)($bidangItem['title'] ?? ''));
        if ($orderTitle === '') {
            continue;
        }

        if (is_ketua_pengurus_lokal_bidang($orderTitle)) {
            $kplTitles = [];
            foreach ($bidangSummary as $summaryTitle => $_summaryValue) {
                if (isset($orderedAssigned[$summaryTitle])) {
                    continue;
                }
                if (is_ketua_pengurus_lokal_bidang((string)$summaryTitle)) {
                    $kplTitles[] = (string)$summaryTitle;
                }
            }

            usort($kplTitles, static function (string $a, string $b) use ($cabangOrderMap): int {
                $cabangA = normalize_header_key(extract_ketua_pengurus_lokal_cabang($a));
                $cabangB = normalize_header_key(extract_ketua_pengurus_lokal_cabang($b));
                $idxA = $cabangOrderMap[$cabangA] ?? PHP_INT_MAX;
                $idxB = $cabangOrderMap[$cabangB] ?? PHP_INT_MAX;
                if ($idxA !== $idxB) {
                    return $idxA <=> $idxB;
                }
                return strnatcasecmp($a, $b);
            });

            foreach ($kplTitles as $kplTitle) {
                $orderedBidangSummary[$kplTitle] = $bidangSummary[$kplTitle];
                $orderedAssigned[$kplTitle] = true;
            }
            continue;
        }

        if (!isset($orderedAssigned[$orderTitle]) && isset($bidangSummary[$orderTitle])) {
            $orderedBidangSummary[$orderTitle] = $bidangSummary[$orderTitle];
            $orderedAssigned[$orderTitle] = true;
        }
    }

    $remainingTitles = [];
    foreach ($bidangSummary as $summaryTitle => $_summaryValue) {
        if (!isset($orderedAssigned[$summaryTitle])) {
            $remainingTitles[] = (string)$summaryTitle;
        }
    }
    natcasesort($remainingTitles);
    foreach ($remainingTitles as $remainingTitle) {
        $orderedBidangSummary[$remainingTitle] = $bidangSummary[$remainingTitle];
    }
    $bidangSummary = $orderedBidangSummary;

    $allUsers = load_user_data();
    $interviewerUsers = [];
    $interviewerMapByLogin = [];
    foreach ($allUsers as $userItem) {
        if (!is_array($userItem)) {
            continue;
        }
        if (!user_has_role($userItem, 'pewawancara')) {
            continue;
        }

        $loginUsername = normalize_login_username((string)($userItem['username'] ?? ''));
        $namaLengkap = normalize_username((string)($userItem['nama_lengkap'] ?? $userItem['username'] ?? ''));
        $asalCabangPewawancara = trim((string)($userItem['asal_cabang'] ?? ''));
        if ($loginUsername === '' || $namaLengkap === '') {
            continue;
        }
        if (isset($interviewerMapByLogin[$loginUsername])) {
            continue;
        }

        $record = [
            'login_username' => $loginUsername,
            'nama_lengkap' => $namaLengkap,
            'asal_cabang' => $asalCabangPewawancara,
        ];
        $interviewerUsers[] = $record;
        $interviewerMapByLogin[$loginUsername] = $record;
    }
    usort($interviewerUsers, static function (array $a, array $b): int {
        $nameCompare = strnatcasecmp((string)($a['nama_lengkap'] ?? ''), (string)($b['nama_lengkap'] ?? ''));
        if ($nameCompare !== 0) {
            return $nameCompare;
        }
        return strnatcasecmp((string)($a['login_username'] ?? ''), (string)($b['login_username'] ?? ''));
    });

    if ($method === 'POST' && $dashboardAction === 'toggle_candidate_flag') {
        $postedCsrfToken = trim((string)($_POST['csrf_token'] ?? ''));
        $targetBidang = trim((string)($_POST['target_bidang'] ?? ''));
        $targetKandidatNama = trim((string)($_POST['target_kandidat_nama'] ?? ''));
        $targetKandidatCabang = trim((string)($_POST['target_kandidat_cabang'] ?? ''));
        $flagType = trim((string)($_POST['flag_type'] ?? ''));

        if (!is_valid_csrf_token($postedCsrfToken)) {
            $flaggingErrorMessage = 'Sesi tidak valid. Muat ulang halaman kandidat lalu coba lagi.';
        } elseif ($targetBidang === '' || $targetKandidatNama === '' || $targetKandidatCabang === '') {
            $flaggingErrorMessage = 'Data kandidat untuk flagging tidak lengkap.';
        } elseif (!is_candidate_in_top10_summary($bidangSummary, $targetBidang, $targetKandidatNama, $targetKandidatCabang)) {
            $flaggingErrorMessage = 'Flagging hanya dapat dilakukan pada kandidat Top 10 di bidang terkait.';
        } elseif (strtolower($flagType) === 'lanjut') {
            if (!$isKandidatPage) {
                $flaggingErrorMessage = 'Perubahan status lanjut proses hanya dapat dilakukan dari halaman kandidat admin.';
            } else {
                $candidateKey = flagging_candidate_key($targetBidang, $targetKandidatNama, $targetKandidatCabang);
                $candidateFlagMap = load_flagging_map();
                $candidateFlag = (array)($candidateFlagMap[$candidateKey] ?? []);
                $isCurrentlyLanjut = !empty($candidateFlag['lanjut_proses']);
                $candidateKesediaanMap = load_kesediaan_form_map();
                $candidateKesediaanKey = kesediaan_candidate_key($targetKandidatNama, $targetKandidatCabang);
                $candidateForms = (array)($candidateKesediaanMap[$candidateKesediaanKey] ?? []);
                $candidateFormCount = 0;
                foreach ($candidateForms as $candidateFormItem) {
                    if (!is_array($candidateFormItem)) {
                        continue;
                    }
                    $candidateFormStatus = normalize_kesediaan_status((string)($candidateFormItem['status_kesediaan'] ?? ''));
                    if ($candidateFormStatus === '') {
                        continue;
                    }
                    $candidateFormCount++;
                }

                if (!$isCurrentlyLanjut && $candidateFormCount <= 0) {
                    $flaggingErrorMessage = 'Lanjut proses hanya dapat ditandai jika kandidat sudah memiliki form kesediaan.';
                } else {
                    $flagResult = mark_candidate_lanjut_proses(
                        $targetBidang,
                        $targetKandidatNama,
                        $targetKandidatCabang,
                        $username
                    );

                    if (!($flagResult['ok'] ?? false)) {
                        $flaggingErrorMessage = (string)($flagResult['message'] ?? 'Gagal menandai lanjut proses.');
                    } else {
                        $flaggingSuccessMessage = (string)($flagResult['message'] ?? 'Status lanjut proses berhasil diperbarui.');
                    }
                }
            }
        } elseif (strtolower($flagType) === 'scorecard_submit') {
            $flagResult = cancel_submitted_scorecard_submission(
                $targetBidang,
                $targetKandidatNama,
                $targetKandidatCabang,
                $username
            );

            if (!($flagResult['ok'] ?? false)) {
                $flaggingErrorMessage = (string)($flagResult['message'] ?? 'Batal submit score card gagal diproses.');
            } else {
                $flaggingSuccessMessage = (string)($flagResult['message'] ?? 'Submit score card berhasil dibatalkan.');
            }
        } else {
            $flagResult = toggle_candidate_flag_status(
                $targetBidang,
                $targetKandidatNama,
                $targetKandidatCabang,
                $flagType,
                $username
            );

            if (!($flagResult['ok'] ?? false)) {
                $flaggingErrorMessage = (string)($flagResult['message'] ?? 'Proses flagging gagal disimpan.');
            } else {
                $flaggingSuccessMessage = (string)($flagResult['message'] ?? 'Status flagging berhasil diperbarui.');
            }
        }
    }

    $flaggingMap = load_flagging_map();
    $scorecardSubmissionMap = load_scorecard_submission_map();
    $kesediaanFormMap = load_kesediaan_form_map();

    $totalPemilih = count($uniqueVoterMap);
    $totalBidangTerisi = count($bidangSummary);
    $totalUsers = count($allUsers);
    $totalBidang = count($allBidang);
    $targetVotes = $totalUsers * $totalBidang;
    $completedVotes = count($uniqueVotePairMap);
    $progressPercent = $targetVotes > 0 ? ($completedVotes / $targetVotes) * 100 : 0;
    $progressPercent = min(100, max(0, $progressPercent));
    $progressPercentText = number_format($progressPercent, 1);
    $progressWidth = number_format($progressPercent, 2, '.', '');

    $usersStarted = count($userBidangMap);
    $usersCompletedAll = 0;
    if ($totalBidang > 0) {
        foreach ($allUsers as $userItem) {
            if (!is_array($userItem)) {
                continue;
            }
            $userName = normalize_username((string)($userItem['username'] ?? ''));
            if ($userName === '') {
                continue;
            }
            $filledBidang = isset($userBidangMap[$userName]) ? count($userBidangMap[$userName]) : 0;
            if ($filledBidang >= $totalBidang) {
                $usersCompletedAll++;
            }
        }
    }

    $voteLogData = load_vote_log_data();
    $voteLogs = $voteLogData['logs'] ?? [];
    if (!is_array($voteLogs)) {
        $voteLogs = [];
    }
    $voteLogs = array_values(array_filter($voteLogs, static fn($item): bool => is_array($item)));
    usort($voteLogs, static function (array $a, array $b): int {
        return strcmp((string)($b['timestamp'] ?? ''), (string)($a['timestamp'] ?? ''));
    });
    ?>
    <!doctype html>
    <html lang="id">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>PeMa REC Indonesia</title>
        <link rel="icon" type="image/png" href="logo.png">
        <style>
            * { box-sizing: border-box; }
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: linear-gradient(180deg, #f8fafc 0%, #e2e8f0 100%);
                color: #0f172a;
                min-height: 100vh;
                padding: 24px 16px;
            }
            .wrap {
                width: 100%;
                max-width: 1060px;
                margin: 0 auto;
            }
            .panel {
                background: #fff;
                border: 1px solid #e2e8f0;
                border-radius: 14px;
                padding: 20px;
                box-shadow: 0 14px 36px rgba(15, 23, 42, 0.08);
            }
            .topbar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 12px;
                flex-wrap: wrap;
                margin-bottom: 18px;
            }
            .title {
                margin: 0;
                font-size: 28px;
            }
            .actions {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
            }
            .btn {
                display: inline-block;
                text-decoration: none;
                padding: 10px 14px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                color: #fff;
                background: #111827;
                border: 0;
                cursor: pointer;
            }
            .btn-back {
                display: inline-block;
                text-decoration: none;
                background: #111827;
                color: #fff;
                padding: 10px 16px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                border: 0;
            }
            .btn-back:hover {
                background: #0f172a;
            }
            .btn-back:focus-visible {
                outline: 3px solid #93c5fd;
                outline-offset: 2px;
            }
            .btn-back:focus-visible {
                outline: 3px solid #93c5fd;
                outline-offset: 2px;
            }
            .stats {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 12px;
                margin-bottom: 16px;
            }
            .deadline-box {
                margin-bottom: 16px;
                border: 1px solid #cbd5e1;
                border-radius: 10px;
                padding: 12px 14px;
                background: #f8fafc;
            }
            .deadline-title {
                margin: 0 0 6px;
                font-size: 14px;
                color: #334155;
                font-weight: 700;
            }
            .deadline-meta {
                margin: 0;
                font-size: 13px;
                color: #475569;
            }
            .deadline-status {
                margin-top: 8px;
                display: inline-block;
                font-size: 12px;
                font-weight: 700;
                padding: 4px 10px;
                border-radius: 999px;
            }
            .deadline-status.open {
                background: #dcfce7;
                color: #166534;
                border: 1px solid #86efac;
            }
            .deadline-status.closed {
                background: #fee2e2;
                color: #b91c1c;
                border: 1px solid #fecaca;
            }
            .import-box {
                margin-bottom: 16px;
                border: 1px solid #cbd5e1;
                border-radius: 10px;
                padding: 14px;
                background: #f8fafc;
            }
            .import-title {
                margin: 0 0 6px;
                font-size: 15px;
                font-weight: 700;
                color: #1e293b;
            }
            .import-note {
                margin: 0 0 10px;
                font-size: 13px;
                color: #475569;
                line-height: 1.45;
            }
            .import-form {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                align-items: center;
            }
            .file-input {
                flex: 1 1 320px;
                min-width: 220px;
                font-size: 13px;
                color: #334155;
                background: #fff;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                padding: 8px 10px;
            }
            .btn-import {
                background: #0f766e;
            }
            .btn-import:hover {
                background: #0d9488;
            }
            .import-alert {
                margin-top: 10px;
                border-radius: 8px;
                padding: 10px 12px;
                font-size: 13px;
                line-height: 1.5;
            }
            .import-alert.success {
                border: 1px solid #86efac;
                background: #dcfce7;
                color: #166534;
            }
            .import-alert.error {
                border: 1px solid #fecaca;
                background: #fee2e2;
                color: #b91c1c;
            }
            .import-alert.warning {
                border: 1px solid #fde68a;
                background: #fffbeb;
                color: #92400e;
            }
            .import-alert ul {
                margin: 6px 0 0;
                padding-left: 18px;
            }
            .import-alert li {
                margin-bottom: 4px;
            }
            .stat {
                border: 1px solid #e2e8f0;
                background: #f8fafc;
                border-radius: 10px;
                padding: 14px;
            }
            .stat-label {
                margin: 0 0 6px;
                color: #64748b;
                font-size: 13px;
            }
            .stat-value {
                margin: 0;
                font-size: 24px;
                font-weight: 700;
                color: #0f172a;
            }
            .progress-card {
                border: 1px solid #bfdbfe;
                background: linear-gradient(180deg, #eff6ff 0%, #dbeafe 100%);
                border-radius: 12px;
                padding: 14px;
                margin-bottom: 16px;
            }
            .progress-head {
                display: flex;
                justify-content: space-between;
                align-items: baseline;
                gap: 10px;
                margin-bottom: 8px;
            }
            .progress-title {
                margin: 0;
                font-size: 16px;
                color: #1e3a8a;
            }
            .progress-percent {
                margin: 0;
                font-size: 18px;
                font-weight: 700;
                color: #1d4ed8;
            }
            .progress-meta {
                margin: 0 0 10px;
                font-size: 13px;
                color: #334155;
            }
            .progress-track {
                width: 100%;
                height: 10px;
                border-radius: 999px;
                background: #bfdbfe;
                overflow: hidden;
            }
            .progress-fill {
                height: 100%;
                border-radius: 999px;
                background: linear-gradient(90deg, #2563eb 0%, #1d4ed8 100%);
                transition: width 0.3s ease;
            }
            .progress-detail {
                margin-top: 10px;
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 8px;
                color: #334155;
                font-size: 13px;
            }
            .progress-detail strong {
                color: #0f172a;
            }
            .kandidat-filter-bar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 12px;
                margin-bottom: 16px;
                padding: 10px 12px;
                border: 1px solid #dbe3ef;
                border-radius: 10px;
                background: #f8fafc;
            }
            .kandidat-filter-label {
                margin: 0;
                font-size: 14px;
                font-weight: 700;
                color: #334155;
            }
            .kandidat-filter-select {
                width: min(100%, 220px);
                min-width: 180px;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                background: #fff;
                color: #0f172a;
                padding: 8px 10px;
                font-size: 14px;
            }
            .kandidat-filter-select:focus-visible,
            .assign-select:focus-visible,
            .flag-btn:focus-visible,
            .file-input:focus-visible,
            .btn-import:focus-visible {
                outline: 3px solid #bfdbfe;
                outline-offset: 2px;
            }
            .kandidat-filter-empty {
                display: none;
                margin-bottom: 16px;
                padding: 12px;
                border-radius: 8px;
                background: #f8fafc;
                border: 1px dashed #cbd5e1;
                color: #64748b;
                text-align: center;
            }
            .rekap-grid {
                display: grid;
                gap: 10px;
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .rekap-card {
                border: 1px solid #e2e8f0;
                border-radius: 10px;
                padding: 12px;
                background: #fff;
            }
            .rekap-head {
                display: flex;
                justify-content: flex-start;
                align-items: baseline;
                gap: 8px;
                margin-bottom: 10px;
            }
            .rekap-title {
                margin: 0;
                font-size: 18px;
            }
            .rekap-title-sub {
                display: block;
                margin-top: 3px;
                font-size: 12px;
                font-weight: 700;
                color: #64748b;
            }
            .rekap-total {
                margin: 0;
                font-size: 13px;
                color: #475569;
                font-weight: 700;
            }
            .candidate-list {
                margin: 0;
                padding: 0;
                list-style: none;
                color: #334155;
                display: grid;
                gap: 10px;
            }
            .candidate-item {
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                background: #f8fafc;
                padding: 10px;
                scroll-margin-top: 14px;
            }
            .candidate-main {
                color: #1e293b;
                font-size: 14px;
                font-weight: 600;
                line-height: 1.5;
            }
            .flag-state {
                margin-top: 6px;
                display: flex;
                gap: 4px;
                flex-wrap: wrap;
            }
            .assign-state {
                margin-top: 0;
            }
            .flag-badge {
                display: inline-block;
                padding: 2px 7px;
                border-radius: 999px;
                border: 1px solid #cbd5e1;
                background: #f1f5f9;
                color: #475569;
                font-size: 11px;
                font-weight: 700;
            }
            .flag-badge.on {
                border-color: #86efac;
                background: #dcfce7;
                color: #166534;
            }
            .flag-badge.screening-on {
                border-color: #a5b4fc;
                background: #e0e7ff;
                color: #3730a3;
            }
            .flag-badge.interviewer-on {
                border-color: #7dd3fc;
                background: #e0f2fe;
                color: #075985;
            }
            .flag-badge.kesediaan-empty {
                border-color: #cbd5e1;
                background: #f1f5f9;
                color: #475569;
            }
            .flag-badge.kesediaan-progress {
                border-color: #93c5fd;
                background: #dbeafe;
                color: #1e3a8a;
            }
            .flag-badge.kesediaan-complete {
                border-color: #86efac;
                background: #dcfce7;
                color: #166534;
            }
            .flag-badge.scorecard-empty {
                border-color: #cbd5e1;
                background: #f1f5f9;
                color: #64748b;
            }
            .flag-badge.scorecard-on {
                border-color: #fcd34d;
                background: #fef3c7;
                color: #92400e;
            }
            .flag-form {
                margin-top: 0;
                display: flex;
                gap: 6px;
                flex-wrap: nowrap;
                flex: 0 0 auto;
                min-width: auto;
            }
            .candidate-actions {
                margin-top: 8px;
                display: flex;
                gap: 6px;
                flex-wrap: nowrap;
                align-items: center;
            }
            .assign-form {
                margin-top: 0;
                display: flex;
                gap: 8px;
                flex-wrap: nowrap;
                align-items: center;
                flex: 0 0 auto;
            }
            .assign-select {
                flex: 0 1 168px;
                min-width: 132px;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                padding: 0 10px;
                height: 32px;
                font-size: 12px;
                background: #fff;
                color: #1e293b;
            }
            .assign-note {
                margin: 6px 0 0;
                color: #92400e;
                font-size: 12px;
            }
            .flag-btn {
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                background: #ffffff;
                color: #334155;
                padding: 0 10px;
                height: 32px;
                font-size: 12px;
                line-height: 1;
                font-weight: 700;
                cursor: pointer;
                white-space: nowrap;
            }
            .flag-btn:hover {
                background: #f8fafc;
            }
            .flag-btn.active-lanjut {
                border-color: #4ade80;
                background: #dcfce7;
                color: #166534;
            }
            .flag-btn.active-screening {
                border-color: #818cf8;
                background: #e0e7ff;
                color: #3730a3;
            }
            .flag-btn:disabled {
                opacity: 1;
                cursor: not-allowed;
                border-color: #cbd5e1;
                background: #f1f5f9;
                color: #64748b;
            }
            .top10-title {
                margin: 0 0 8px;
                font-size: 13px;
                color: #475569;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.03em;
            }
            .top10-note {
                margin: 10px 0 0;
                color: #64748b;
                font-size: 12px;
            }
            .empty {
                margin: 10px 0 0;
                padding: 12px;
                border-radius: 8px;
                background: #f8fafc;
                border: 1px dashed #cbd5e1;
                color: #64748b;
                text-align: center;
            }
            .log-section {
                margin-top: 18px;
            }
            .section-title {
                margin: 0 0 10px;
                font-size: 18px;
            }
            .table-wrap {
                border: 1px solid #e2e8f0;
                border-radius: 10px;
                overflow: auto;
                background: #fff;
                width: 100%;
                max-height: 320px;
                margin: 0;
            }
            .log-table {
                width: 100%;
                border-collapse: collapse;
                min-width: 780px;
                font-size: 12px;
            }
            .log-table th,
            .log-table td {
                padding: 8px 10px;
                text-align: left;
                border-bottom: 1px solid #e2e8f0;
                vertical-align: top;
                line-height: 1.4;
            }
            .log-table th {
                background: #f8fafc;
                color: #334155;
                font-weight: 700;
                position: sticky;
                top: 0;
                z-index: 1;
            }
            .log-table tr:last-child td {
                border-bottom: 0;
            }
            .mono {
                font-family: Consolas, monospace;
                color: #475569;
            }
            @media (max-width: 820px) {
                .stats {
                    grid-template-columns: 1fr;
                }
                .progress-detail {
                    grid-template-columns: 1fr;
                }
                .kandidat-filter-bar {
                    align-items: stretch;
                    flex-direction: column;
                }
                .kandidat-filter-select {
                    width: 100%;
                    min-width: 0;
                }
                .rekap-grid {
                    grid-template-columns: 1fr;
                }
                .candidate-actions {
                    flex-wrap: wrap;
                    align-items: stretch;
                }
                .flag-form {
                    flex-wrap: wrap;
                }
                .assign-form {
                    flex-wrap: wrap;
                    width: 100%;
                }
                .assign-select {
                    flex: 1 1 100%;
                    min-width: 0;
                    width: 100%;
                }
            }
        </style>
        <?php render_language_switcher_head(); ?>
    </head>
    <body>
        <main class="wrap">
            <section class="panel">
                <div class="topbar">
                    <div>
                        <h1 class="title" data-i18n="<?= h($isDashboardPage ? 'dashboard_title' : 'dashboard_candidates_title') ?>"><?= h($isDashboardPage ? 'Dashboard Rekap Pemilihan' : 'Halaman Kandidat') ?></h1>
                    </div>
                    <div class="actions">
                        <a class="btn-back" href="<?= h(app_index_url(['page' => 'bidang'])) ?>" data-i18n="dashboard_back">Kembali ke Halaman Bidang</a>
                    </div>
                </div>
                <?php if ($isDashboardPage): ?>
                <div class="deadline-box">
                    <p class="deadline-title" data-i18n="dashboard_deadline_title">Deadline Pemilihan</p>
                    <p class="deadline-meta" data-i18n-html="dashboard_deadline_meta" data-i18n-vars="<?= h((string)json_encode(['date' => ELECTION_DEADLINE_LABEL], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>">Batas akhir pemilihan sampai <strong><?= h(ELECTION_DEADLINE_LABEL) ?></strong>.</p>
                    <span class="deadline-status <?= $dashboardElectionClosed ? 'closed' : 'open' ?>" data-i18n="<?= h($dashboardElectionClosed ? 'dashboard_deadline_closed' : 'dashboard_deadline_open') ?>">
                        <?= $dashboardElectionClosed ? 'Masa pemilihan berakhir' : 'Masa pemilihan masih berjalan' ?>
                    </span>
                </div>

                <section class="import-box">
                    <h2 class="import-title" data-i18n="dashboard_import_title">Import Data User & Kandidat</h2>
                    <p class="import-note" data-i18n-html="dashboard_import_note">
                        Upload file template Excel (.xlsx) dengan 2 sheet: <strong>MASTER PEMILIH</strong> dan <strong>MASTER KANDIDAT</strong>.
                        User import otomatis memakai role <strong>user</strong>, username format nama depan + inisial nama berikutnya, dan password dari 6 digit belakang <strong>Nomor Telpon</strong>.
                        Sheet kandidat juga dapat memakai kolom opsional <strong>TIPE PENCALONAN</strong> dengan nilai <strong>SEMUA</strong>, <strong>SEMUA_KECUALI_KETUA_LOKAL</strong>, atau <strong>KETUA_LOKAL_SAJA</strong>.
                    </p>
                    <form class="import-form" method="post" action="<?= h(app_index_url(['page' => 'dashboard'])) ?>" enctype="multipart/form-data">
                        <input type="hidden" name="csrf_token" value="<?= h($dashboardLogoutToken) ?>">
                        <input type="hidden" name="dashboard_action" value="import_excel">
                        <input class="file-input" type="file" name="excel_file" accept=".xlsx" required>
                        <button class="btn btn-import" type="submit" data-i18n="dashboard_import_button">Import Excel</button>
                    </form>

                    <?php if ($importSuccessMessage !== ''): ?>
                        <div class="import-alert success"><?= h($importSuccessMessage) ?></div>
                    <?php endif; ?>

                    <?php if ($importErrors !== []): ?>
                        <div class="import-alert error">
                            <strong data-i18n="dashboard_import_failed">Import gagal:</strong>
                            <ul>
                                <?php foreach ($importErrors as $errorItem): ?>
                                    <li><?= h((string)$errorItem) ?></li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                    <?php endif; ?>

                    <?php if ($importWarnings !== []): ?>
                        <?php
                        $warningPreview = array_slice($importWarnings, 0, 12);
                        $warningRemaining = count($importWarnings) - count($warningPreview);
                        ?>
                        <div class="import-alert warning">
                            <strong data-i18n="dashboard_import_notes">Catatan import:</strong>
                            <ul>
                                <?php foreach ($warningPreview as $warningItem): ?>
                                    <li><?= h((string)$warningItem) ?></li>
                                <?php endforeach; ?>
                            </ul>
                            <?php if ($warningRemaining > 0): ?>
                                <div data-i18n="dashboard_import_more_notes" data-i18n-vars="<?= h((string)json_encode(['count' => (string)$warningRemaining], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>">... dan <?= h((string)$warningRemaining) ?> catatan lainnya.</div>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                </section>
                <?php endif; ?>

                <?php if ($isKandidatPage): ?>
                <?php if ($flaggingSuccessMessage !== ''): ?>
                    <div class="import-alert success"><?= h($flaggingSuccessMessage) ?></div>
                <?php endif; ?>
                <?php if ($flaggingErrorMessage !== ''): ?>
                    <div class="import-alert error"><?= h($flaggingErrorMessage) ?></div>
                <?php endif; ?>
                <?php endif; ?>

                <?php if ($isDashboardPage): ?>
                <div class="stats">
                    <article class="stat">
                        <p class="stat-label" data-i18n="dashboard_stat_votes">Total Vote Tersimpan</p>
                        <p class="stat-value"><?= h((string)$totalVotes) ?></p>
                    </article>
                    <article class="stat">
                        <p class="stat-label" data-i18n="dashboard_stat_voters">Total Pemilih Unik</p>
                        <p class="stat-value"><?= h((string)$totalPemilih) ?></p>
                    </article>
                    <article class="stat">
                        <p class="stat-label" data-i18n="dashboard_stat_positions">Bidang Terisi</p>
                        <p class="stat-value"><?= h((string)$totalBidangTerisi) ?></p>
                    </article>
                </div>

                <article class="progress-card">
                    <div class="progress-head">
                        <h2 class="progress-title" data-i18n="dashboard_progress_title">Progress Voting Keseluruhan</h2>
                        <p class="progress-percent"><?= h($progressPercentText) ?>%</p>
                    </div>
                    <p class="progress-meta" data-i18n="dashboard_progress_meta" data-i18n-vars="<?= h((string)json_encode(['completed' => (string)$completedVotes, 'target' => (string)$targetVotes, 'users' => (string)$totalUsers, 'bidang' => (string)$totalBidang], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>">
                        <?= h((string)$completedVotes) ?> dari <?= h((string)$targetVotes) ?> vote
                        (<?= h((string)$totalUsers) ?> user x <?= h((string)$totalBidang) ?> bidang)
                    </p>
                    <div class="progress-track">
                        <div class="progress-fill" style="width: <?= h($progressWidth) ?>%;"></div>
                    </div>
                    <div class="progress-detail">
                        <div data-i18n-html="dashboard_progress_users_started" data-i18n-vars="<?= h((string)json_encode(['started' => (string)$usersStarted, 'total' => (string)$totalUsers], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>">User sudah vote: <strong><?= h((string)$usersStarted) ?>/<?= h((string)$totalUsers) ?></strong></div>
                        <div data-i18n-html="dashboard_progress_users_completed" data-i18n-vars="<?= h((string)json_encode(['done' => (string)$usersCompletedAll, 'total' => (string)$totalUsers], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>">User tuntas semua bidang: <strong><?= h((string)$usersCompletedAll) ?>/<?= h((string)$totalUsers) ?></strong></div>
                    </div>
                </article>
                <?php endif; ?>

                <?php if ($isKandidatPage): ?>
                <?php if ($bidangSummary === []): ?>
                    <p class="empty" data-i18n="dashboard_empty_votes">Belum ada data pemilihan yang tersimpan.</p>
                <?php else: ?>
                    <div class="kandidat-filter-bar">
                        <p class="kandidat-filter-label" data-i18n="dashboard_candidate_filter_label">Filter proses kandidat</p>
                        <select class="kandidat-filter-select" id="kandidatProcessFilter" aria-label="Filter proses kandidat" data-i18n-aria-label="dashboard_candidate_filter_label">
                            <option value="all" <?= $kandidatProcessFilter === 'all' ? 'selected' : '' ?> data-i18n="filter_all">Semua</option>
                            <option value="belum_lanjut" <?= $kandidatProcessFilter === 'belum_lanjut' ? 'selected' : '' ?> data-i18n="filter_not_advanced">Belum Lanjut Proses</option>
                            <option value="lanjut" <?= $kandidatProcessFilter === 'lanjut' ? 'selected' : '' ?> data-i18n="filter_advanced">Lanjut Proses</option>
                            <option value="screening" <?= $kandidatProcessFilter === 'screening' ? 'selected' : '' ?> data-i18n="filter_screening">Lolos Screening</option>
                            <option value="scorecard_submitted" <?= $kandidatProcessFilter === 'scorecard_submitted' ? 'selected' : '' ?> data-i18n="filter_scorecard_submitted">Sudah Submit Score Card</option>
                        </select>
                    </div>
                    <div class="kandidat-filter-empty" id="kandidatFilterEmpty" data-i18n="dashboard_candidate_filter_empty">Tidak ada kandidat yang cocok dengan filter proses yang dipilih.</div>
                    <div class="rekap-grid">
                        <?php foreach ($bidangSummary as $bidang => $summary): ?>
                            <?php
                            $rekapBidangParts = bidang_title_parts((string)$bidang);
                            $rekapMainTitle = (string)($rekapBidangParts['main'] ?? (string)$bidang);
                            if ($rekapMainTitle === '') {
                                $rekapMainTitle = (string)$bidang;
                            }
                            $rekapCabangTitle = (string)($rekapBidangParts['cabang'] ?? '');
                            ?>
                            <article class="rekap-card" data-kandidat-card="1">
                                <div class="rekap-head">
                                    <h2 class="rekap-title">
                                        <span data-lang-text-id="<?= h($rekapMainTitle) ?>" data-lang-text-en="<?= h(bidang_translate_main_title($rekapMainTitle, 'en')) ?>"><?= h($rekapMainTitle) ?></span>
                                        <?php if ($rekapCabangTitle !== ''): ?>
                                            <span class="rekap-title-sub"><?= h($rekapCabangTitle) ?></span>
                                        <?php endif; ?>
                                    </h2>
                                    <p class="rekap-total" data-i18n="dashboard_rekap_total_votes" data-i18n-vars="<?= h((string)json_encode(['count' => (string)$summary['total']], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"><?= h((string)$summary['total']) ?> vote</p>
                                </div>
                                <p class="top10-title" data-i18n="dashboard_top10_title">Top 10 Kandidat</p>
                                <ul class="candidate-list">
                                    <?php foreach ($summary['top_candidates'] as $index => $candidate): ?>
                                        <?php
                                        $candidateNama = (string)($candidate['nama'] ?? '-');
                                        $candidateCabang = (string)($candidate['cabang'] ?? '-');
                                        $candidateCount = (int)($candidate['count'] ?? 0);
                                        $candidateFlagKey = flagging_candidate_key((string)$bidang, $candidateNama, $candidateCabang);
                                        $candidateAnchorId = 'flag-' . substr($candidateFlagKey, 0, 18);
                                        $candidateFlag = (array)($flaggingMap[$candidateFlagKey] ?? []);
                                        $isLanjutProses = !empty($candidateFlag['lanjut_proses']);
                                        $isLolosScreening = !empty($candidateFlag['lolos_screening']) && $isLanjutProses;
                                        $candidateKesediaanKey = kesediaan_candidate_key($candidateNama, $candidateCabang);
                                        $candidateForms = (array)($kesediaanFormMap[$candidateKesediaanKey] ?? []);
                                        $candidateTotalFormCount = 0;
                                        $candidateBersediaCount = 0;
                                        foreach ($candidateForms as $candidateFormItemRaw) {
                                            if (!is_array($candidateFormItemRaw)) {
                                                continue;
                                            }
                                            $candidateFormStatus = normalize_kesediaan_status((string)($candidateFormItemRaw['status_kesediaan'] ?? ''));
                                            if ($candidateFormStatus === '') {
                                                continue;
                                            }
                                            $candidateTotalFormCount++;
                                            if ($candidateFormStatus === 'bersedia') {
                                                $candidateBersediaCount++;
                                            }
                                        }
                                        $candidateKesediaanBadgeText = 'Belum Bersedia';
                                        $candidateKesediaanBadgeClass = ' kesediaan-empty';
                                        if ($candidateTotalFormCount > 0) {
                                            $candidateKesediaanBadgeText = $candidateBersediaCount . '/' . $candidateTotalFormCount . ' bersedia';
                                            $candidateKesediaanBadgeClass = $candidateBersediaCount >= $candidateTotalFormCount ? ' kesediaan-complete' : ' kesediaan-progress';
                                        }
                                        $canToggleCandidateLanjutProses = $isLanjutProses || $candidateTotalFormCount > 0;
                                        $candidateScorecardSubmission = (array)($scorecardSubmissionMap[$candidateFlagKey] ?? []);
                                        $candidateHasScorecard = $candidateScorecardSubmission !== [];
                                        $isScorecardSubmitted = !empty($candidateScorecardSubmission['is_submitted']);
                                        $candidateScorecardFinalScore = $candidateHasScorecard
                                            ? round((float)($candidateScorecardSubmission['final_score'] ?? 0), 2)
                                            : 0.0;
                                        $candidateScorecardBadgeText = 'Skor Akhir: ' . ($candidateHasScorecard
                                            ? number_format($candidateScorecardFinalScore, 2, '.', '')
                                            : '0');
                                        $candidateScorecardBadgeClass = $candidateHasScorecard ? ' scorecard-on' : ' scorecard-empty';
                                        $screeningActionType = $isScorecardSubmitted ? 'scorecard_submit' : 'screening';
                                        $screeningButtonClass = $isLolosScreening || $isScorecardSubmitted ? ' active-screening' : '';
                                        $screeningButtonDisabled = !$isLanjutProses && !$isScorecardSubmitted;
                                        $screeningButtonTitle = 'Status lanjut proses masih belum aktif.';
                                        if ($isScorecardSubmitted) {
                                            $screeningButtonTitle = 'Batalkan status submit score card kandidat ini agar dapat diedit lagi.';
                                        } elseif ($isLolosScreening) {
                                            $screeningButtonTitle = 'Batalkan status screening kandidat ini.';
                                        } elseif ($isLanjutProses) {
                                            $screeningButtonTitle = 'Tandai status screening kandidat ini.';
                                        }
                                        $screeningButtonLabel = $isScorecardSubmitted
                                            ? 'Batal Submit Score Card'
                                            : ($isLolosScreening ? 'Batal Screening' : 'Tandai Screening');
                                        ?>
                                        <li
                                            class="candidate-item"
                                            id="<?= h($candidateAnchorId) ?>"
                                            data-process-lanjut="<?= $isLanjutProses ? '1' : '0' ?>"
                                            data-process-screening="<?= $isLolosScreening ? '1' : '0' ?>"
                                            data-process-scorecard-submitted="<?= $isScorecardSubmitted ? '1' : '0' ?>"
                                        >
                                            <div class="candidate-main">
                                                #<?= h((string)($index + 1)) ?> -
                                                <?= h_name($candidateNama) ?>
                                                (<?= h($candidateCabang) ?>)
                                                - <?= h((string)$candidateCount) ?> suara
                                            </div>
                                            <div class="flag-state">
                                                <?php if ($isLolosScreening): ?>
                                                <span class="flag-badge<?= h($candidateKesediaanBadgeClass) ?>">
                                                    <?= h($candidateKesediaanBadgeText) ?>
                                                </span>
                                                <span class="flag-badge on screening-on" data-i18n="filter_screening">
                                                    Lolos Screening
                                                </span>
                                                <span class="flag-badge<?= h($candidateScorecardBadgeClass) ?>">
                                                    <?= h($candidateScorecardBadgeText) ?>
                                                </span>
                                                <?php elseif (!$isLanjutProses): ?>
                                                <span class="flag-badge<?= h($candidateKesediaanBadgeClass) ?>">
                                                    <?= h($candidateKesediaanBadgeText) ?>
                                                </span>
                                                <span class="flag-badge" data-i18n="filter_not_advanced">
                                                    Belum Lanjut Proses
                                                </span>
                                                <?php else: ?>
                                                <span class="flag-badge<?= h($candidateKesediaanBadgeClass) ?>">
                                                    <?= h($candidateKesediaanBadgeText) ?>
                                                </span>
                                                <span class="flag-badge on" data-i18n="filter_advanced">
                                                    Lanjut Proses
                                                </span>
                                                <?php endif; ?>
                                            </div>
                                            <div class="candidate-actions">
                                                <?php if (!$isLolosScreening): ?>
                                                <form class="flag-form" method="post" action="<?= h(app_index_url($kandidatPageParams) . '#' . $candidateAnchorId) ?>">
                                                    <input type="hidden" name="csrf_token" value="<?= h($dashboardLogoutToken) ?>">
                                                    <input type="hidden" name="dashboard_action" value="toggle_candidate_flag">
                                                    <input type="hidden" name="target_bidang" value="<?= h((string)$bidang) ?>">
                                                    <input type="hidden" name="target_kandidat_nama" value="<?= h($candidateNama) ?>">
                                                    <input type="hidden" name="target_kandidat_cabang" value="<?= h($candidateCabang) ?>">
                                                    <button
                                                        class="flag-btn<?= $isLanjutProses ? ' active-lanjut' : '' ?>"
                                                        type="submit"
                                                        name="flag_type"
                                                        value="lanjut"
                                                        <?= $canToggleCandidateLanjutProses ? '' : 'disabled' ?>
                                                        data-lang-title-id="<?= h(!$canToggleCandidateLanjutProses ? 'Tombol aktif setelah ada minimal 1 form kesediaan.' : ($isLanjutProses ? 'Batalkan status lanjut proses kandidat ini.' : 'Tandai kandidat ini sebagai lanjut proses.')) ?>"
                                                        data-lang-title-en="<?= h(!$canToggleCandidateLanjutProses ? 'This button becomes active after at least 1 consent form is submitted.' : ($isLanjutProses ? 'Cancel this candidate\\\'s advanced-process status.' : 'Mark this candidate as advanced.')) ?>"
                                                        title="<?= !$canToggleCandidateLanjutProses ? 'Tombol aktif setelah ada minimal 1 form kesediaan.' : ($isLanjutProses ? 'Batalkan status lanjut proses kandidat ini.' : 'Tandai kandidat ini sebagai lanjut proses.') ?>"
                                                    >
                                                        <span data-lang-text-id="<?= h($isLanjutProses ? 'Batalkan' : 'Lanjut Proses') ?>" data-lang-text-en="<?= h($isLanjutProses ? 'Cancel' : 'Advance') ?>"><?= $isLanjutProses ? 'Batalkan' : 'Lanjut Proses' ?></span>
                                                    </button>
                                                </form>
                                                <?php endif; ?>
                                                <form class="flag-form" method="post" action="<?= h(app_index_url($kandidatPageParams) . '#' . $candidateAnchorId) ?>">
                                                    <input type="hidden" name="csrf_token" value="<?= h($dashboardLogoutToken) ?>">
                                                    <input type="hidden" name="dashboard_action" value="toggle_candidate_flag">
                                                    <input type="hidden" name="target_bidang" value="<?= h((string)$bidang) ?>">
                                                    <input type="hidden" name="target_kandidat_nama" value="<?= h($candidateNama) ?>">
                                                    <input type="hidden" name="target_kandidat_cabang" value="<?= h($candidateCabang) ?>">
                                                    <button
                                                        class="flag-btn<?= $screeningButtonClass ?>"
                                                        type="submit"
                                                        name="flag_type"
                                                        value="<?= h($screeningActionType) ?>"
                                                        <?= $screeningButtonDisabled ? 'disabled' : '' ?>
                                                        data-lang-title-id="<?= h($screeningButtonTitle) ?>"
                                                        data-lang-title-en="<?= h($isScorecardSubmitted ? 'Cancel this candidate\\\'s score card submission status so it can be edited again.' : ($isLolosScreening ? 'Cancel this candidate\\\'s screening status.' : ($isLanjutProses ? 'Mark this candidate as screened.' : 'Advanced-process status is still inactive.'))) ?>"
                                                        title="<?= h($screeningButtonTitle) ?>"
                                                    >
                                                        <span data-lang-text-id="<?= h($screeningButtonLabel) ?>" data-lang-text-en="<?= h($isScorecardSubmitted ? 'Cancel Score Card Submission' : ($isLolosScreening ? 'Cancel Screening' : 'Mark Screening')) ?>"><?= h($screeningButtonLabel) ?></span>
                                                    </button>
                                                </form>
                                            </div>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                                <?php if ((int)($summary['candidate_total'] ?? 0) > 10): ?>
                                    <p class="top10-note" data-i18n="dashboard_top10_note" data-i18n-vars="<?= h((string)json_encode(['count' => (string)$summary['candidate_total']], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>">
                                        Menampilkan 10 dari <?= h((string)$summary['candidate_total']) ?> kandidat pada bidang ini.
                                    </p>
                                <?php endif; ?>
                            </article>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                <?php endif; ?>

                <?php if ($isDashboardPage): ?>
                <section class="log-section">
                    <h2 class="section-title" data-i18n="dashboard_log_title">Log Vote</h2>
                    <?php if ($voteLogs === []): ?>
                        <p class="empty" data-i18n="dashboard_log_empty">Belum ada log vote.</p>
                    <?php else: ?>
                        <div class="table-wrap">
                            <table class="log-table">
                                <thead>
                                    <tr>
                                        <th data-i18n="dashboard_log_no">No</th>
                                        <th data-i18n="dashboard_log_time">Waktu</th>
                                        <th data-i18n="dashboard_log_user">User</th>
                                        <th data-i18n="dashboard_log_user_branch">Cabang User</th>
                                        <th data-i18n="dashboard_log_position">Bidang</th>
                                        <th data-i18n="dashboard_log_candidate">Kandidat</th>
                                        <th data-i18n="dashboard_log_candidate_branch">Cabang Kandidat</th>
                                        <th>IP</th>
                                        <th data-i18n="dashboard_log_event">Event</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($voteLogs as $idx => $log): ?>
                                        <tr>
                                            <td><?= h((string)($idx + 1)) ?></td>
                                            <td class="mono"><?= h((string)($log['timestamp'] ?? '-')) ?></td>
                                            <td><?= h_name((string)($log['username'] ?? '-')) ?></td>
                                            <td><?= h((string)($log['asal_cabang_user'] ?? '-')) ?></td>
                                            <td><?= h((string)($log['bidang'] ?? '-')) ?></td>
                                            <td><?= h_name((string)($log['kandidat_nama'] ?? '-')) ?></td>
                                            <td><?= h((string)($log['kandidat_cabang'] ?? '-')) ?></td>
                                            <td class="mono"><?= h((string)($log['ip_address'] ?? '-')) ?></td>
                                            <td><?= h((string)($log['event'] ?? '-')) ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </section>
                <?php endif; ?>
            </section>
        </main>
        <?php render_language_switcher(); ?>
        <script>
            const kandidatProcessFilter = document.getElementById('kandidatProcessFilter');
            const kandidatFilterEmpty = document.getElementById('kandidatFilterEmpty');

            function buildKandidatFilterUrl(selectedFilter) {
                const url = new URL(window.location.href);
                url.searchParams.set('page', 'kandidat');
                if (selectedFilter && selectedFilter !== 'all') {
                    url.searchParams.set('kandidat_filter', selectedFilter);
                } else {
                    url.searchParams.delete('kandidat_filter');
                }
                url.hash = '';
                return url.toString();
            }

            function applyKandidatProcessFilter() {
                if (!kandidatProcessFilter) {
                    return;
                }

                const selectedFilter = String(kandidatProcessFilter.value || 'all').trim();

                const candidateItems = document.querySelectorAll('.candidate-item[data-process-lanjut]');
                const kandidatCards = document.querySelectorAll('.rekap-card[data-kandidat-card]');
                let visibleCandidateCount = 0;

                candidateItems.forEach(function (item) {
                    const isLanjut = item.getAttribute('data-process-lanjut') === '1';
                    const isScreening = item.getAttribute('data-process-screening') === '1';
                    const isScorecardSubmitted = item.getAttribute('data-process-scorecard-submitted') === '1';
                    let shouldShow = true;

                    if (selectedFilter === 'belum_lanjut') {
                        shouldShow = !isLanjut;
                    } else if (selectedFilter === 'lanjut') {
                        shouldShow = isLanjut && !isScreening;
                    } else if (selectedFilter === 'screening') {
                        shouldShow = isScreening && !isScorecardSubmitted;
                    } else if (selectedFilter === 'scorecard_submitted') {
                        shouldShow = isScorecardSubmitted;
                    }

                    item.style.display = shouldShow ? '' : 'none';
                    if (shouldShow) {
                        visibleCandidateCount++;
                    }
                });

                kandidatCards.forEach(function (card) {
                    const cardItems = card.querySelectorAll('.candidate-item[data-process-lanjut]');
                    let hasVisibleItem = false;

                    cardItems.forEach(function (item) {
                        if (item.style.display !== 'none') {
                            hasVisibleItem = true;
                        }
                    });

                    card.style.display = hasVisibleItem ? '' : 'none';
                });

                if (kandidatFilterEmpty) {
                    kandidatFilterEmpty.style.display = visibleCandidateCount > 0 ? 'none' : 'block';
                }
            }

            if (kandidatProcessFilter) {
                kandidatProcessFilter.addEventListener('change', function () {
                    const selectedFilter = String(kandidatProcessFilter.value || 'all').trim();
                    window.location.href = buildKandidatFilterUrl(selectedFilter);
                });
                applyKandidatProcessFilter();
            }
        </script>
        <?php render_language_script([
            'dashboard_title' => ['id' => 'Dashboard Rekap Pemilihan', 'en' => 'Voting Summary Dashboard'],
            'dashboard_candidates_title' => ['id' => 'Halaman Kandidat', 'en' => 'Candidates Page'],
            'dashboard_back' => ['id' => 'Kembali ke Halaman Bidang', 'en' => 'Back to Positions'],
            'dashboard_deadline_title' => ['id' => 'Deadline Pemilihan', 'en' => 'Voting Deadline'],
            'dashboard_deadline_meta' => ['id' => 'Batas akhir pemilihan sampai <strong>{date}</strong>.', 'en' => 'Voting is open until <strong>{date}</strong>.'],
            'dashboard_deadline_closed' => ['id' => 'Masa pemilihan berakhir', 'en' => 'Voting period ended'],
            'dashboard_deadline_open' => ['id' => 'Masa pemilihan masih berjalan', 'en' => 'Voting is still open'],
            'dashboard_import_title' => ['id' => 'Import Data User & Kandidat', 'en' => 'Import User & Candidate Data'],
            'dashboard_import_note' => ['id' => 'Upload file template Excel (.xlsx) dengan 2 sheet: <strong>MASTER PEMILIH</strong> dan <strong>MASTER KANDIDAT</strong>. User import otomatis memakai role <strong>user</strong>, username format nama depan + inisial nama berikutnya, dan password dari 6 digit belakang <strong>Nomor Telpon</strong>. Sheet kandidat juga dapat memakai kolom opsional <strong>TIPE PENCALONAN</strong> dengan nilai <strong>SEMUA</strong>, <strong>SEMUA_KECUALI_KETUA_LOKAL</strong>, atau <strong>KETUA_LOKAL_SAJA</strong>.', 'en' => 'Upload the Excel template file (.xlsx) with 2 sheets: <strong>MASTER PEMILIH</strong> and <strong>MASTER KANDIDAT</strong>. Imported users automatically use the <strong>user</strong> role, usernames follow the first-name plus following-initial format, and passwords use the last 6 digits of <strong>Nomor Telpon</strong>. The candidate sheet may also use the optional <strong>TIPE PENCALONAN</strong> column with values <strong>SEMUA</strong>, <strong>SEMUA_KECUALI_KETUA_LOKAL</strong>, or <strong>KETUA_LOKAL_SAJA</strong>.'],
            'dashboard_import_button' => ['id' => 'Import Excel', 'en' => 'Import Excel'],
            'dashboard_import_failed' => ['id' => 'Import gagal:', 'en' => 'Import failed:'],
            'dashboard_import_notes' => ['id' => 'Catatan import:', 'en' => 'Import notes:'],
            'dashboard_import_more_notes' => ['id' => '... dan {count} catatan lainnya.', 'en' => '... and {count} more notes.'],
            'dashboard_stat_votes' => ['id' => 'Total Vote Tersimpan', 'en' => 'Total Saved Votes'],
            'dashboard_stat_voters' => ['id' => 'Total Pemilih Unik', 'en' => 'Total Unique Voters'],
            'dashboard_stat_positions' => ['id' => 'Bidang Terisi', 'en' => 'Filled Positions'],
            'dashboard_progress_title' => ['id' => 'Progress Voting Keseluruhan', 'en' => 'Overall Voting Progress'],
            'dashboard_progress_meta' => ['id' => '{completed} dari {target} vote ({users} user x {bidang} bidang)', 'en' => '{completed} of {target} votes ({users} users x {bidang} positions)'],
            'dashboard_progress_users_started' => ['id' => 'User sudah vote: <strong>{started}/{total}</strong>', 'en' => 'Users who have voted: <strong>{started}/{total}</strong>'],
            'dashboard_progress_users_completed' => ['id' => 'User tuntas semua bidang: <strong>{done}/{total}</strong>', 'en' => 'Users who completed all positions: <strong>{done}/{total}</strong>'],
            'dashboard_empty_votes' => ['id' => 'Belum ada data pemilihan yang tersimpan.', 'en' => 'No voting data has been saved yet.'],
            'dashboard_candidate_filter_label' => ['id' => 'Filter proses kandidat', 'en' => 'Candidate process filter'],
            'filter_all' => ['id' => 'Semua', 'en' => 'All'],
            'filter_not_advanced' => ['id' => 'Belum Lanjut Proses', 'en' => 'Not advanced yet'],
            'filter_advanced' => ['id' => 'Lanjut Proses', 'en' => 'Advanced'],
            'filter_screening' => ['id' => 'Lolos Screening', 'en' => 'Passed Screening'],
            'filter_scorecard_submitted' => ['id' => 'Sudah Submit Score Card', 'en' => 'Score Card Submitted'],
            'dashboard_candidate_filter_empty' => ['id' => 'Tidak ada kandidat yang cocok dengan filter proses yang dipilih.', 'en' => 'No candidates match the selected process filter.'],
            'dashboard_rekap_total_votes' => ['id' => '{count} vote', 'en' => '{count} votes'],
            'dashboard_top10_title' => ['id' => 'Top 10 Kandidat', 'en' => 'Top 10 Candidates'],
            'dashboard_top10_note' => ['id' => 'Menampilkan 10 dari {count} kandidat pada bidang ini.', 'en' => 'Showing 10 of {count} candidates for this position.'],
            'dashboard_log_title' => ['id' => 'Log Vote', 'en' => 'Vote Log'],
            'dashboard_log_empty' => ['id' => 'Belum ada log vote.', 'en' => 'There are no vote logs yet.'],
            'dashboard_log_no' => ['id' => 'No', 'en' => 'No'],
            'dashboard_log_time' => ['id' => 'Waktu', 'en' => 'Time'],
            'dashboard_log_user' => ['id' => 'User', 'en' => 'User'],
            'dashboard_log_user_branch' => ['id' => 'Cabang User', 'en' => 'User Branch'],
            'dashboard_log_position' => ['id' => 'Bidang', 'en' => 'Position'],
            'dashboard_log_candidate' => ['id' => 'Kandidat', 'en' => 'Candidate'],
            'dashboard_log_candidate_branch' => ['id' => 'Cabang Kandidat', 'en' => 'Candidate Branch'],
            'dashboard_log_event' => ['id' => 'Event', 'en' => 'Event'],
        ]); ?>
    </body>
    </html>
    <?php
    exit;
}

if ($page === 'rekap_kesediaan') {
    $authUser = current_authenticated_user($usersForLogin);
    if ($authUser === null) {
        clear_auth_session();
        redirect_to_page('login');
    }
    if (!user_has_role($authUser, 'admin')) {
        redirect_to_page('bidang', ['info' => 'admin-only']);
    }

    sync_session_roles($authUser);

    $kesediaanRecapRows = build_kesediaan_recap_rows(load_kesediaan_form_map());
    $kesediaanRecapTotalCandidates = count($kesediaanRecapRows);
    $kesediaanRecapTotalForms = 0;
    foreach ($kesediaanRecapRows as $rekapRow) {
        $kesediaanRecapTotalForms += (int)($rekapRow['total_forms'] ?? 0);
    }
    ?>
    <!doctype html>
    <html lang="id">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>PeMa REC Indonesia</title>
        <link rel="icon" type="image/png" href="logo.png">
        <style>
            * { box-sizing: border-box; }
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: linear-gradient(180deg, #f8fafc 0%, #e2e8f0 100%);
                color: #0f172a;
                min-height: 100vh;
                padding: 24px 16px;
            }
            body.modal-open {
                overflow: hidden;
            }
            .wrap {
                width: 100%;
                max-width: 1180px;
                margin: 0 auto;
            }
            .panel {
                background: #fff;
                border: 1px solid #e2e8f0;
                border-radius: 18px;
                box-shadow: 0 18px 48px rgba(15, 23, 42, 0.08);
                padding: 24px;
            }
            .topbar {
                display: flex;
                justify-content: space-between;
                gap: 16px;
                align-items: flex-start;
                margin-bottom: 18px;
            }
            .topbar-copy h1 {
                margin: 0 0 6px;
                font-size: 28px;
            }
            .topbar-copy p {
                margin: 0;
                color: #475569;
                line-height: 1.5;
            }
            .top-actions {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                align-items: center;
                justify-content: flex-end;
            }
            .btn-back {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                min-height: 38px;
                padding: 0 14px;
                border-radius: 10px;
                border: 1px solid #cbd5e1;
                background: #f8fafc;
                color: #0f172a;
                text-decoration: none;
                font-size: 14px;
                font-weight: 700;
            }
            .btn-back:hover {
                background: #eef2ff;
                border-color: #94a3b8;
            }
            .summary-bar {
                margin-bottom: 16px;
                padding: 14px 16px;
                border: 1px solid #dbeafe;
                border-radius: 12px;
                background: linear-gradient(180deg, #eff6ff 0%, #f8fafc 100%);
            }
            .summary-bar p {
                margin: 0;
                color: #1e3a8a;
                line-height: 1.5;
            }
            .empty {
                margin: 0;
                padding: 18px;
                border-radius: 12px;
                border: 1px dashed #cbd5e1;
                background: #f8fafc;
                color: #64748b;
                text-align: center;
            }
            .table-wrap {
                border: 1px solid #e2e8f0;
                border-radius: 14px;
                overflow: auto;
                background: #fff;
            }
            .recap-table {
                width: 100%;
                min-width: 940px;
                border-collapse: collapse;
            }
            .recap-table th,
            .recap-table td {
                padding: 12px 14px;
                border-bottom: 1px solid #e2e8f0;
                text-align: left;
                vertical-align: top;
                font-size: 14px;
                line-height: 1.45;
            }
            .recap-table th {
                background: #f8fafc;
                color: #334155;
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.04em;
                position: sticky;
                top: 0;
                z-index: 1;
            }
            .recap-table tr:last-child td {
                border-bottom: 0;
            }
            .recap-table .col-no,
            .recap-table .cell-no {
                width: 62px;
                text-align: center;
                white-space: nowrap;
            }
            .candidate-name {
                margin: 0;
                font-size: 15px;
                font-weight: 700;
                color: #0f172a;
            }
            .candidate-branch {
                margin: 4px 0 0;
                color: #64748b;
                font-size: 12px;
                font-weight: 700;
            }
            .ratio-badge {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                padding: 6px 10px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: 700;
                border: 1px solid #cbd5e1;
                background: #f1f5f9;
                color: #475569;
                white-space: nowrap;
            }
            .ratio-badge.partial {
                border-color: #93c5fd;
                background: #dbeafe;
                color: #1d4ed8;
            }
            .ratio-badge.complete {
                border-color: #86efac;
                background: #dcfce7;
                color: #166534;
            }
            .view-btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                min-height: 34px;
                padding: 0 12px;
                border: 1px solid #0f766e;
                border-radius: 8px;
                background: #0f766e;
                color: #fff;
                font-size: 13px;
                font-weight: 700;
                cursor: pointer;
            }
            .view-btn:hover {
                background: #0d9488;
                border-color: #0d9488;
            }
            .view-btn:focus-visible,
            .btn-back:focus-visible,
            .doc-modal-close:focus-visible,
            .doc-view-link:focus-visible {
                outline: 3px solid #bfdbfe;
                outline-offset: 2px;
            }
            .interviewer-main {
                margin: 0;
                color: #0f172a;
                font-weight: 600;
            }
            .interviewer-more {
                margin: 4px 0 0;
                color: #64748b;
                font-size: 12px;
            }
            .mono {
                font-family: Consolas, monospace;
                color: #475569;
                white-space: nowrap;
            }
            .doc-modal {
                position: fixed;
                inset: 0;
                display: none;
                align-items: center;
                justify-content: center;
                padding: 20px;
                background: rgba(15, 23, 42, 0.6);
                z-index: 1000;
            }
            .doc-modal.open {
                display: flex;
            }
            .doc-modal-panel {
                width: min(1040px, 100%);
                max-height: calc(100vh - 40px);
                overflow: auto;
                background: #fff;
                border-radius: 16px;
                border: 1px solid #dbe3ef;
                box-shadow: 0 24px 60px rgba(15, 23, 42, 0.24);
                padding: 20px;
            }
            .doc-modal-title {
                margin: 0 0 8px;
                font-size: 22px;
                color: #0f172a;
            }
            .doc-modal-text {
                margin: 0 0 14px;
                color: #475569;
                line-height: 1.5;
            }
            .doc-view-table-wrap {
                border: 1px solid #e2e8f0;
                border-radius: 12px;
                overflow: auto;
            }
            .doc-view-table {
                width: 100%;
                min-width: 920px;
                border-collapse: collapse;
            }
            .doc-view-table th,
            .doc-view-table td {
                padding: 10px 12px;
                border-bottom: 1px solid #e2e8f0;
                text-align: left;
                vertical-align: top;
                font-size: 13px;
                line-height: 1.45;
            }
            .doc-view-table th {
                background: #f8fafc;
                color: #334155;
                font-size: 12px;
                font-weight: 700;
            }
            .doc-view-table tr:last-child td {
                border-bottom: 0;
            }
            .doc-view-link-group {
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
            }
            .doc-view-link {
                color: #0f766e;
                font-weight: 700;
                text-decoration: none;
            }
            .doc-view-link:hover {
                text-decoration: underline;
            }
            .doc-view-empty {
                padding: 16px;
                border-radius: 12px;
                border: 1px dashed #cbd5e1;
                background: #f8fafc;
                color: #64748b;
                text-align: center;
            }
            .doc-modal-actions {
                margin-top: 16px;
                display: flex;
                justify-content: flex-end;
            }
            .doc-modal-close {
                min-height: 38px;
                padding: 0 14px;
                border: 1px solid #cbd5e1;
                border-radius: 10px;
                background: #f8fafc;
                color: #0f172a;
                font-size: 14px;
                font-weight: 700;
                cursor: pointer;
            }
            .doc-modal-close:hover {
                background: #eef2ff;
            }
            @media (max-width: 760px) {
                .panel {
                    padding: 18px;
                }
                .topbar {
                    flex-direction: column;
                }
                .top-actions {
                    width: 100%;
                    justify-content: flex-start;
                }
                .btn-back {
                    width: 100%;
                }
            }
        </style>
        <?php render_language_switcher_head(); ?>
    </head>
    <body>
        <main class="wrap">
            <section class="panel">
                <div class="topbar">
                    <div class="topbar-copy">
                        <h1 data-i18n="consent_recap_title">Rekap Form Kesediaan</h1>
                        <p data-i18n-html="consent_recap_intro" data-i18n-vars="<?= h((string)json_encode(['candidates' => (string)$kesediaanRecapTotalCandidates, 'forms' => (string)$kesediaanRecapTotalForms], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>">Menampilkan <strong><?= h((string)$kesediaanRecapTotalCandidates) ?></strong> kandidat dengan total <strong><?= h((string)$kesediaanRecapTotalForms) ?></strong> form kesediaan yang sudah tersimpan.</p>
                    </div>
                    <div class="top-actions">
                        <a class="btn-back" href="<?= h(app_index_url(['page' => 'bidang'])) ?>" data-i18n="consent_recap_back">Kembali ke Halaman Bidang</a>
                    </div>
                </div>

                <?php if ($kesediaanRecapRows === []): ?>
                    <p class="empty" data-i18n="consent_recap_empty">Belum ada form kesediaan yang tersimpan.</p>
                <?php else: ?>
                    <div class="summary-bar">
                        <p data-i18n="consent_recap_summary_note">Kolom user pewawancara dan waktu menampilkan pengisian form terbaru untuk masing-masing kandidat.</p>
                    </div>
                    <div class="table-wrap">
                        <table class="recap-table">
                            <thead>
                                <tr>
                                    <th class="col-no" data-i18n="consent_recap_no">No</th>
                                    <th data-i18n="consent_recap_candidate">Nama Kandidat</th>
                                    <th data-i18n="consent_recap_willingness">Kesediaan</th>
                                    <th data-i18n="consent_recap_view_forms">Lihat Form</th>
                                    <th data-i18n="consent_recap_interviewer_user">User Pewawancara</th>
                                    <th data-i18n="consent_recap_time">Waktu</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($kesediaanRecapRows as $rowIndex => $row): ?>
                                    <?php
                                    $rowTotalForms = (int)($row['total_forms'] ?? 0);
                                    $rowBersediaCount = (int)($row['bersedia_count'] ?? 0);
                                    $ratioBadgeClass = 'ratio-badge';
                                    if ($rowTotalForms > 0 && $rowBersediaCount >= $rowTotalForms) {
                                        $ratioBadgeClass .= ' complete';
                                    } elseif ($rowBersediaCount > 0) {
                                        $ratioBadgeClass .= ' partial';
                                    }
                                    $rowFormItemsJsonRaw = json_encode((array)($row['form_items'] ?? []), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                                    if (!is_string($rowFormItemsJsonRaw)) {
                                        $rowFormItemsJsonRaw = '[]';
                                    }
                                    $rowAdditionalInterviewers = max(0, (int)($row['additional_interviewer_count'] ?? 0));
                                    ?>
                                    <tr>
                                        <td class="cell-no"><?= h((string)($rowIndex + 1)) ?></td>
                                        <td>
                                            <p class="candidate-name"><?= h_name((string)($row['candidate_name'] ?? '-')) ?></p>
                                            <p class="candidate-branch"><?= h((string)($row['candidate_branch'] ?? '-')) ?></p>
                                        </td>
                                        <td>
                                            <span class="<?= h($ratioBadgeClass) ?>"><?= h((string)($row['consent_text'] ?? '0/0 bersedia')) ?></span>
                                        </td>
                                        <td>
                                            <button
                                                class="view-btn"
                                                type="button"
                                                data-candidate-label="<?= h((string)($row['candidate_label'] ?? '-')) ?>"
                                                data-form-items="<?= h($rowFormItemsJsonRaw) ?>"
                                                onclick="showKesediaanRecapModal(this)"
                                                data-i18n="consent_recap_view_forms"
                                            >Lihat Form</button>
                                        </td>
                                        <td>
                                            <p class="interviewer-main"><?= h((string)($row['latest_interviewer_user'] ?? '-')) ?></p>
                                            <?php if ($rowAdditionalInterviewers > 0): ?>
                                                <p class="interviewer-more" data-i18n="consent_recap_interviewer_more" data-i18n-vars="<?= h((string)json_encode(['count' => (string)$rowAdditionalInterviewers], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>">+<?= h((string)$rowAdditionalInterviewers) ?> pewawancara lainnya</p>
                                            <?php endif; ?>
                                        </td>
                                        <td class="mono"><?= h((string)($row['latest_updated_at'] ?? '-')) ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </section>
        </main>

        <div class="doc-modal" id="kesediaanRecapModal" role="dialog" aria-modal="true" aria-labelledby="kesediaanRecapTitle">
            <div class="doc-modal-panel">
                <h2 class="doc-modal-title" id="kesediaanRecapTitle" data-i18n="consent_recap_modal_title">Lihat Form Kesediaan</h2>
                <p class="doc-modal-text"><span data-i18n="consent_recap_modal_candidate_label">Kandidat:</span> <strong id="kesediaanRecapCandidate">-</strong></p>
                <div id="kesediaanRecapTableWrap" class="doc-view-table-wrap" style="display:none;">
                    <table class="doc-view-table">
                        <thead>
                            <tr>
                                <th data-i18n="consent_recap_no">No</th>
                                <th data-i18n="consent_recap_party">Pihak</th>
                                <th data-i18n="consent_recap_party_name">Nama Pihak</th>
                                <th data-i18n="consent_recap_status">Status</th>
                                <th data-i18n="consent_recap_reason">Alasan</th>
                                <th data-i18n="consent_recap_document">Dokumen</th>
                                <th data-i18n="consent_recap_interviewer_user">User Pewawancara</th>
                                <th data-i18n="consent_recap_time">Waktu</th>
                            </tr>
                        </thead>
                        <tbody id="kesediaanRecapBody"></tbody>
                    </table>
                </div>
                <div id="kesediaanRecapEmpty" class="doc-view-empty" data-i18n="consent_recap_modal_empty">Belum ada form kesediaan yang tersimpan untuk kandidat ini.</div>
                <div class="doc-modal-actions">
                    <button class="doc-modal-close" type="button" onclick="closeKesediaanRecapModal()" data-i18n="consent_recap_close">Tutup</button>
                </div>
            </div>
        </div>

        <?php render_language_switcher(); ?>
        <script>
            const kesediaanRecapModal = document.getElementById('kesediaanRecapModal');
            const kesediaanRecapCandidate = document.getElementById('kesediaanRecapCandidate');
            const kesediaanRecapTableWrap = document.getElementById('kesediaanRecapTableWrap');
            const kesediaanRecapBody = document.getElementById('kesediaanRecapBody');
            const kesediaanRecapEmpty = document.getElementById('kesediaanRecapEmpty');

            function recapT(key, fallback, vars) {
                if (window.majelisLang && typeof window.majelisLang.t === 'function') {
                    return window.majelisLang.t(key, vars || {}, fallback || '');
                }
                return fallback || '';
            }

            function escapeHtml(value) {
                return String(value || '')
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#39;');
            }

            function sanitizeSafeUrl(value) {
                const trimmed = String(value || '').trim();
                if (trimmed === '') {
                    return '';
                }

                try {
                    const parsed = new URL(trimmed, window.location.href);
                    if (parsed.origin !== window.location.origin) {
                        return '';
                    }
                    return parsed.toString();
                } catch (error) {
                    return '';
                }
            }

            function syncRecapBodyScrollState() {
                document.body.classList.toggle('modal-open', !!(kesediaanRecapModal && kesediaanRecapModal.classList.contains('open')));
            }

            function closeKesediaanRecapModal() {
                if (!kesediaanRecapModal) {
                    return;
                }
                kesediaanRecapModal.classList.remove('open');
                syncRecapBodyScrollState();
            }

            function showKesediaanRecapModal(buttonElement) {
                if (!buttonElement || !kesediaanRecapModal || !kesediaanRecapCandidate || !kesediaanRecapTableWrap || !kesediaanRecapBody || !kesediaanRecapEmpty) {
                    return;
                }

                const candidateLabel = String(buttonElement.dataset.candidateLabel || '').trim();
                let formItems = [];
                try {
                    const decoded = JSON.parse(buttonElement.dataset.formItems || '[]');
                    if (Array.isArray(decoded)) {
                        formItems = decoded;
                    }
                } catch (error) {
                    formItems = [];
                }

                kesediaanRecapCandidate.textContent = candidateLabel !== '' ? candidateLabel : '-';
                if (formItems.length === 0) {
                    kesediaanRecapBody.innerHTML = '';
                    kesediaanRecapTableWrap.style.display = 'none';
                    kesediaanRecapEmpty.style.display = 'block';
                } else {
                    const rows = [];
                    formItems.forEach(function (item, idx) {
                        const recapHubungan = item && item.hubungan ? String(item.hubungan) : '-';
                        const recapNamaPihak = item && item.nama_pihak ? String(item.nama_pihak) : '-';
                        const recapStatus = item && item.status ? String(item.status) : '-';
                        const recapAlasan = item && item.alasan ? String(item.alasan) : '-';
                        const recapInterviewerUser = item && item.interviewer_user ? String(item.interviewer_user) : '-';
                        const recapUpdatedAt = item && item.updated_at ? String(item.updated_at) : '-';
                        const recapFileUrl = sanitizeSafeUrl(item && item.file_url ? String(item.file_url) : '');
                        const recapDownloadUrl = sanitizeSafeUrl(item && item.file_download_url ? String(item.file_download_url) : '');

                        let recapDocCell = '<span>-</span>';
                        if (recapFileUrl !== '' || recapDownloadUrl !== '') {
                            const actionLinks = [];
                            if (recapFileUrl !== '') {
                                actionLinks.push('<a class="doc-view-link" href="' + escapeHtml(recapFileUrl) + '" target="_blank" rel="noopener">' + escapeHtml(recapT('consent_recap_view', 'Lihat')) + '</a>');
                            }
                            if (recapDownloadUrl !== '') {
                                actionLinks.push('<a class="doc-view-link" href="' + escapeHtml(recapDownloadUrl) + '" target="_blank" rel="noopener">' + escapeHtml(recapT('consent_recap_download', 'Unduh')) + '</a>');
                            }
                            recapDocCell = '<div class="doc-view-link-group">' + actionLinks.join('') + '</div>';
                        }

                        rows.push(
                            '<tr>' +
                                '<td>' + escapeHtml(String(idx + 1)) + '</td>' +
                                '<td>' + escapeHtml(recapHubungan) + '</td>' +
                                '<td>' + escapeHtml(recapNamaPihak) + '</td>' +
                                '<td>' + escapeHtml(recapStatus) + '</td>' +
                                '<td>' + escapeHtml(recapAlasan) + '</td>' +
                                '<td>' + recapDocCell + '</td>' +
                                '<td>' + escapeHtml(recapInterviewerUser) + '</td>' +
                                '<td>' + escapeHtml(recapUpdatedAt) + '</td>' +
                            '</tr>'
                        );
                    });

                    if (rows.length === 0) {
                        rows.push('<tr><td colspan="8">' + escapeHtml(recapT('consent_recap_modal_empty', 'Belum ada form kesediaan yang tersimpan untuk kandidat ini.')) + '</td></tr>');
                    }

                    kesediaanRecapBody.innerHTML = rows.join('');
                    kesediaanRecapTableWrap.style.display = 'block';
                    kesediaanRecapEmpty.style.display = 'none';
                }

                kesediaanRecapModal.classList.add('open');
                syncRecapBodyScrollState();
            }

            if (kesediaanRecapModal) {
                kesediaanRecapModal.addEventListener('click', function (event) {
                    if (event.target === kesediaanRecapModal) {
                        closeKesediaanRecapModal();
                    }
                });
            }

            document.addEventListener('keydown', function (event) {
                if (event.key === 'Escape' && kesediaanRecapModal && kesediaanRecapModal.classList.contains('open')) {
                    closeKesediaanRecapModal();
                }
            });
        </script>
        <?php render_language_script([
            'consent_recap_title' => ['id' => 'Rekap Form Kesediaan', 'en' => 'Consent Form Recap'],
            'consent_recap_intro' => ['id' => 'Menampilkan <strong>{candidates}</strong> kandidat dengan total <strong>{forms}</strong> form kesediaan yang sudah tersimpan.', 'en' => 'Showing <strong>{candidates}</strong> candidates with a total of <strong>{forms}</strong> saved consent forms.'],
            'consent_recap_back' => ['id' => 'Kembali ke Halaman Bidang', 'en' => 'Back to Positions'],
            'consent_recap_empty' => ['id' => 'Belum ada form kesediaan yang tersimpan.', 'en' => 'There are no saved consent forms yet.'],
            'consent_recap_summary_note' => ['id' => 'Kolom user pewawancara dan waktu menampilkan pengisian form terbaru untuk masing-masing kandidat.', 'en' => 'The interviewer user and time columns show the latest form submission for each candidate.'],
            'consent_recap_candidate' => ['id' => 'Nama Kandidat', 'en' => 'Candidate Name'],
            'consent_recap_willingness' => ['id' => 'Kesediaan', 'en' => 'Willingness'],
            'consent_recap_view_forms' => ['id' => 'Lihat Form', 'en' => 'View Forms'],
            'consent_recap_interviewer_user' => ['id' => 'User Pewawancara', 'en' => 'Interviewer User'],
            'consent_recap_time' => ['id' => 'Waktu', 'en' => 'Time'],
            'consent_recap_interviewer_more' => ['id' => '+{count} pewawancara lainnya', 'en' => '+{count} other interviewers'],
            'consent_recap_modal_title' => ['id' => 'Lihat Form Kesediaan', 'en' => 'View Consent Forms'],
            'consent_recap_modal_candidate_label' => ['id' => 'Kandidat:', 'en' => 'Candidate:'],
            'consent_recap_no' => ['id' => 'No', 'en' => 'No'],
            'consent_recap_party' => ['id' => 'Pihak', 'en' => 'Party'],
            'consent_recap_party_name' => ['id' => 'Nama Pihak', 'en' => 'Party Name'],
            'consent_recap_status' => ['id' => 'Status', 'en' => 'Status'],
            'consent_recap_reason' => ['id' => 'Alasan', 'en' => 'Reason'],
            'consent_recap_document' => ['id' => 'Dokumen', 'en' => 'Document'],
            'consent_recap_modal_empty' => ['id' => 'Belum ada form kesediaan yang tersimpan untuk kandidat ini.', 'en' => 'There are no saved consent forms for this candidate yet.'],
            'consent_recap_close' => ['id' => 'Tutup', 'en' => 'Close'],
            'consent_recap_view' => ['id' => 'Lihat', 'en' => 'View'],
            'consent_recap_download' => ['id' => 'Unduh', 'en' => 'Download'],
        ]); ?>
    </body>
    </html>
    <?php
    exit;
}

if ($page === 'wawancara') {
    $authUser = current_authenticated_user($usersForLogin);
    if ($authUser === null) {
        clear_auth_session();
        redirect_to_page('login');
    }
    if (!can_access_wawancara_user($authUser)) {
        redirect_to_page('bidang', ['info' => 'wawancara-only']);
    }

    $wawancaraAllowedProcessFilters = ['all', 'belum_lanjut', 'lanjut', 'screening', 'scorecard_submitted'];
    $wawancaraProcessFilter = normalize_query_choice((string)($_GET['wawancara_filter'] ?? ''), $wawancaraAllowedProcessFilters, 'all');
    $wawancaraPageParams = ['page' => 'wawancara'];
    if ($wawancaraProcessFilter !== 'all') {
        $wawancaraPageParams['wawancara_filter'] = $wawancaraProcessFilter;
    }
    sync_session_roles($authUser);
    $wawancaraCsrfToken = csrf_token();
    $wawancaraSuccessMessage = '';
    $wawancaraErrorMessage = '';
    $wawancaraAction = trim((string)($_POST['wawancara_action'] ?? ''));
    $wawancaraVotesRaw = load_pemilihan_data();
    $wawancaraVoteItems = $wawancaraVotesRaw['pemilihan'] ?? [];
    if (!is_array($wawancaraVoteItems)) {
        $wawancaraVoteItems = [];
    }
    $wawancaraFlagMap = load_flagging_map();
    $wawancaraKesediaanFormMap = load_kesediaan_form_map();
    $wawancaraScorecardSubmissionMap = load_scorecard_submission_map();
    $wawancaraEmptyMessage = 'Belum ada kandidat Top 10 untuk ditampilkan.';

    $wawancaraBidangSummary = [];
    foreach ($wawancaraVoteItems as $voteItem) {
        if (!is_array($voteItem)) {
            continue;
        }

        $bidang = trim((string)($voteItem['bidang'] ?? '-'));
        if ($bidang === '') {
            $bidang = '-';
        }

        $candidateName = trim((string)($voteItem['kandidat']['nama_lengkap'] ?? '-'));
        if ($candidateName === '') {
            $candidateName = '-';
        }
        $candidateCabang = trim((string)($voteItem['kandidat']['asal_cabang'] ?? '-'));
        if ($candidateCabang === '') {
            $candidateCabang = '-';
        }

        if (!isset($wawancaraBidangSummary[$bidang])) {
            $wawancaraBidangSummary[$bidang] = [
                'total' => 0,
                'candidates' => [],
            ];
        }

        $wawancaraBidangSummary[$bidang]['total']++;
        $candidateKey = $candidateName . '||' . $candidateCabang;
        if (!isset($wawancaraBidangSummary[$bidang]['candidates'][$candidateKey])) {
            $wawancaraBidangSummary[$bidang]['candidates'][$candidateKey] = [
                'nama' => $candidateName,
                'cabang' => $candidateCabang,
                'count' => 0,
            ];
        }
        $wawancaraBidangSummary[$bidang]['candidates'][$candidateKey]['count']++;
    }

    foreach ($wawancaraBidangSummary as $bidang => $summary) {
        uasort($summary['candidates'], static function (array $a, array $b): int {
            $countCompare = ((int)($b['count'] ?? 0)) <=> ((int)($a['count'] ?? 0));
            if ($countCompare !== 0) {
                return $countCompare;
            }
            return strcmp((string)($a['nama'] ?? ''), (string)($b['nama'] ?? ''));
        });
        $sortedCandidates = array_values($summary['candidates']);
        $topCandidates = array_slice($sortedCandidates, 0, 10);
        $wawancaraBidangSummary[$bidang]['candidates'] = $sortedCandidates;
        $wawancaraBidangSummary[$bidang]['candidate_total'] = count($sortedCandidates);
        $wawancaraBidangSummary[$bidang]['top_candidates'] = $topCandidates;
    }

    $orderedWawancaraBidangSummary = [];
    $orderedAssigned = [];
    $bidangOrder = load_bidang_data();
    $cabangOrderMap = [];
    foreach (known_cabang_values() as $idx => $cabangItem) {
        $cabangKey = normalize_header_key((string)$cabangItem);
        if ($cabangKey !== '' && !isset($cabangOrderMap[$cabangKey])) {
            $cabangOrderMap[$cabangKey] = (int)$idx;
        }
    }

    foreach ($bidangOrder as $bidangItem) {
        if (!is_array($bidangItem)) {
            continue;
        }

        $orderTitle = trim((string)($bidangItem['title'] ?? ''));
        if ($orderTitle === '') {
            continue;
        }

        if (is_ketua_pengurus_lokal_bidang($orderTitle)) {
            $kplTitles = [];
            foreach ($wawancaraBidangSummary as $summaryTitle => $_summaryValue) {
                if (isset($orderedAssigned[$summaryTitle])) {
                    continue;
                }
                if (is_ketua_pengurus_lokal_bidang((string)$summaryTitle)) {
                    $kplTitles[] = (string)$summaryTitle;
                }
            }

            usort($kplTitles, static function (string $a, string $b) use ($cabangOrderMap): int {
                $cabangA = normalize_header_key(extract_ketua_pengurus_lokal_cabang($a));
                $cabangB = normalize_header_key(extract_ketua_pengurus_lokal_cabang($b));
                $idxA = $cabangOrderMap[$cabangA] ?? PHP_INT_MAX;
                $idxB = $cabangOrderMap[$cabangB] ?? PHP_INT_MAX;
                if ($idxA !== $idxB) {
                    return $idxA <=> $idxB;
                }
                return strnatcasecmp($a, $b);
            });

            foreach ($kplTitles as $kplTitle) {
                $orderedWawancaraBidangSummary[$kplTitle] = $wawancaraBidangSummary[$kplTitle];
                $orderedAssigned[$kplTitle] = true;
            }
            continue;
        }

        if (!isset($orderedAssigned[$orderTitle]) && isset($wawancaraBidangSummary[$orderTitle])) {
            $orderedWawancaraBidangSummary[$orderTitle] = $wawancaraBidangSummary[$orderTitle];
            $orderedAssigned[$orderTitle] = true;
        }
    }

    $remainingTitles = [];
    foreach ($wawancaraBidangSummary as $summaryTitle => $_summaryValue) {
        if (!isset($orderedAssigned[$summaryTitle])) {
            $remainingTitles[] = (string)$summaryTitle;
        }
    }
    natcasesort($remainingTitles);
    foreach ($remainingTitles as $remainingTitle) {
        $orderedWawancaraBidangSummary[$remainingTitle] = $wawancaraBidangSummary[$remainingTitle];
    }
    $wawancaraBidangSummary = array_filter(
        $orderedWawancaraBidangSummary,
        static function (array $summary): bool {
            return (array)($summary['top_candidates'] ?? []) !== [];
        }
    );

    if ($method === 'POST' && $wawancaraAction === 'mark_lanjut_proses') {
        $wawancaraErrorMessage = 'Perubahan status lanjut proses dilakukan dari halaman kandidat admin.';
    }

    if ($method === 'POST' && $wawancaraAction === 'save_kesediaan_form') {
        $postedCsrfToken = trim((string)($_POST['csrf_token'] ?? ''));
        $targetBidang = trim((string)($_POST['target_bidang'] ?? ''));
        $targetKandidatNama = trim((string)($_POST['target_kandidat_nama'] ?? ''));
        $targetKandidatCabang = trim((string)($_POST['target_kandidat_cabang'] ?? ''));
        $hubungan = trim((string)($_POST['hubungan'] ?? ''));
        $namaPihak = trim((string)($_POST['nama_pihak'] ?? ''));
        $statusKesediaan = trim((string)($_POST['status_kesediaan'] ?? ''));
        $alasan = trim((string)($_POST['alasan'] ?? ''));
        $uploadedFile = $_FILES['kesediaan_file'] ?? null;

        if (!is_valid_csrf_token($postedCsrfToken)) {
            $wawancaraErrorMessage = 'Sesi tidak valid. Muat ulang halaman lalu coba lagi.';
        } elseif ($targetBidang === '' || $targetKandidatNama === '' || $targetKandidatCabang === '') {
            $wawancaraErrorMessage = 'Data kandidat tidak valid untuk form kesediaan.';
        } elseif (!is_array($uploadedFile)) {
            $wawancaraErrorMessage = 'Bukti foto pertemuan wajib diupload.';
        } else {
            $candidateKey = flagging_candidate_key($targetBidang, $targetKandidatNama, $targetKandidatCabang);
            $candidateFlag = (array)($wawancaraFlagMap[$candidateKey] ?? []);
            $isCandidateLanjutProses = !empty($candidateFlag['lanjut_proses']);

            if ($isCandidateLanjutProses) {
                $wawancaraErrorMessage = 'Kandidat ini sudah lanjut proses. Form kesediaan tidak dapat diinput lagi.';
            } else {
                $saveResult = save_kesediaan_form_submission(
                    $targetBidang,
                    $targetKandidatNama,
                    $targetKandidatCabang,
                    $hubungan,
                    $namaPihak,
                    $statusKesediaan,
                    $alasan,
                    $uploadedFile,
                    (string)($authUser['login_username'] ?? ''),
                    (string)($authUser['username'] ?? ''),
                    (string)$authUser['username']
                );

                if (!($saveResult['ok'] ?? false)) {
                    $wawancaraErrorMessage = (string)($saveResult['message'] ?? 'Gagal menyimpan form kesediaan.');
                } else {
                    $wawancaraSuccessMessage = (string)($saveResult['message'] ?? 'Form kesediaan berhasil disimpan.');
                    $wawancaraKesediaanFormMap = load_kesediaan_form_map();
                }
            }
        }
    }

    if ($method === 'POST' && $wawancaraAction === 'save_scorecard') {
        $postedCsrfToken = trim((string)($_POST['csrf_token'] ?? ''));
        $targetBidang = trim((string)($_POST['target_bidang'] ?? ''));
        $targetKandidatNama = trim((string)($_POST['target_kandidat_nama'] ?? ''));
        $targetKandidatCabang = trim((string)($_POST['target_kandidat_cabang'] ?? ''));
        $interviewDate = trim((string)($_POST['scorecard_interview_date'] ?? ''));
        $location = trim((string)($_POST['scorecard_location'] ?? ''));
        $rawAnswers = $_POST['scorecard_answers'] ?? [];
        $rawSectionNotes = $_POST['scorecard_section_notes'] ?? [];
        $interviewerDecision = trim((string)($_POST['scorecard_interviewer_decision'] ?? ''));
        $decisionNote = trim((string)($_POST['scorecard_decision_note'] ?? ''));

        if (!is_valid_csrf_token($postedCsrfToken)) {
            $wawancaraErrorMessage = 'Sesi tidak valid. Muat ulang halaman lalu coba lagi.';
        } elseif ($targetBidang === '' || $targetKandidatNama === '' || $targetKandidatCabang === '') {
            $wawancaraErrorMessage = 'Data kandidat tidak valid untuk score card.';
        } elseif (!is_array($rawAnswers) || !is_array($rawSectionNotes)) {
            $wawancaraErrorMessage = 'Data score card tidak valid.';
        } else {
            $candidateKey = flagging_candidate_key($targetBidang, $targetKandidatNama, $targetKandidatCabang);
            $candidateFlag = (array)($wawancaraFlagMap[$candidateKey] ?? []);
            $isCandidateLanjutProses = !empty($candidateFlag['lanjut_proses']);
            $isCandidateLolosScreening = !empty($candidateFlag['lolos_screening']) && $isCandidateLanjutProses;

            if (!$isCandidateLolosScreening) {
                $wawancaraErrorMessage = 'Score card hanya dapat diisi untuk kandidat yang sudah lolos screening.';
            } else {
                $saveResult = save_scorecard_submission(
                    $targetBidang,
                    $targetKandidatNama,
                    $targetKandidatCabang,
                    $interviewDate,
                    $location,
                    $rawAnswers,
                    $rawSectionNotes,
                    $interviewerDecision,
                    $decisionNote,
                    (string)($authUser['login_username'] ?? ''),
                    (string)($authUser['username'] ?? ''),
                    (string)($authUser['username'] ?? '')
                );

                if (!($saveResult['ok'] ?? false)) {
                    $wawancaraErrorMessage = (string)($saveResult['message'] ?? 'Gagal menyimpan score card.');
                } else {
                    $wawancaraSuccessMessage = (string)($saveResult['message'] ?? 'Score card berhasil disimpan.');
                    $wawancaraScorecardSubmissionMap = load_scorecard_submission_map();
                }
            }
        }
    }

    if ($method === 'POST' && $wawancaraAction === 'submit_scorecard') {
        $postedCsrfToken = trim((string)($_POST['csrf_token'] ?? ''));
        $targetBidang = trim((string)($_POST['target_bidang'] ?? ''));
        $targetKandidatNama = trim((string)($_POST['target_kandidat_nama'] ?? ''));
        $targetKandidatCabang = trim((string)($_POST['target_kandidat_cabang'] ?? ''));

        if (!is_valid_csrf_token($postedCsrfToken)) {
            $wawancaraErrorMessage = 'Sesi tidak valid. Muat ulang halaman lalu coba lagi.';
        } elseif ($targetBidang === '' || $targetKandidatNama === '' || $targetKandidatCabang === '') {
            $wawancaraErrorMessage = 'Data kandidat tidak valid untuk submit score card.';
        } else {
            $candidateKey = flagging_candidate_key($targetBidang, $targetKandidatNama, $targetKandidatCabang);
            $candidateFlag = (array)($wawancaraFlagMap[$candidateKey] ?? []);
            $isCandidateLanjutProses = !empty($candidateFlag['lanjut_proses']);
            $isCandidateLolosScreening = !empty($candidateFlag['lolos_screening']) && $isCandidateLanjutProses;

            if (!$isCandidateLolosScreening) {
                $wawancaraErrorMessage = 'Submit score card hanya dapat dilakukan untuk kandidat yang sudah lolos screening.';
            } else {
                $submitResult = submit_scorecard_submission(
                    $targetBidang,
                    $targetKandidatNama,
                    $targetKandidatCabang,
                    (string)($authUser['username'] ?? '')
                );

                if (!($submitResult['ok'] ?? false)) {
                    $wawancaraErrorMessage = (string)($submitResult['message'] ?? 'Gagal submit score card.');
                } else {
                    $wawancaraSuccessMessage = (string)($submitResult['message'] ?? 'Score card berhasil disubmit.');
                    $wawancaraScorecardSubmissionMap = load_scorecard_submission_map();
                }
            }
        }
    }

    $wawancaraScorecardTemplatesByBidang = [];
    foreach ($wawancaraBidangSummary as $bidang => $_summary) {
        $resolvedTemplate = find_scorecard_template_for_bidang((string)$bidang);
        if ($resolvedTemplate === null) {
            continue;
        }
        $wawancaraScorecardTemplatesByBidang[(string)$bidang] = scorecard_template_client_payload($resolvedTemplate);
    }
    $wawancaraScorecardTemplatesJsonRaw = json_encode($wawancaraScorecardTemplatesByBidang, JSON_UNESCAPED_UNICODE);
    if (!is_string($wawancaraScorecardTemplatesJsonRaw)) {
        $wawancaraScorecardTemplatesJsonRaw = '{}';
    }
    ?>
    <!doctype html>
    <html lang="id">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>PeMa REC Indonesia</title>
        <link rel="icon" type="image/png" href="logo.png">
        <style>
            * { box-sizing: border-box; }
            body {
                margin: 0;
                min-height: 100vh;
                font-family: Arial, sans-serif;
                background: #f3f4f6;
                color: #111827;
                padding: 24px 16px;
            }
            .wrap {
                width: 100%;
                max-width: 1060px;
                margin: 0 auto;
            }
            .card {
                background: #fff;
                border: 1px solid #e5e7eb;
                border-radius: 14px;
                padding: 22px;
                box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
            }
            .topbar {
                display: flex;
                gap: 16px;
                flex-wrap: wrap;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 18px;
            }
            h1 {
                margin: 0;
                font-size: 28px;
                line-height: 1.2;
                text-align: left;
            }
            .subtitle {
                margin: 8px 0 0;
                color: #4b5563;
                font-size: 14px;
                line-height: 1.6;
                text-align: left;
            }
            .top-actions {
                display: flex;
                justify-content: flex-end;
            }
            .wawancara-filter-bar {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 12px;
                flex-wrap: wrap;
                margin: 0 0 14px;
                padding: 10px 12px;
                border: 1px solid #e2e8f0;
                border-radius: 10px;
                background: #f8fafc;
            }
            .wawancara-filter-label {
                margin: 0;
                color: #334155;
                font-size: 13px;
                font-weight: 700;
            }
            .wawancara-filter-select {
                min-width: 220px;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                background: #ffffff;
                color: #0f172a;
                padding: 8px 10px;
                font-size: 13px;
                font-weight: 600;
            }
            .wawancara-filter-select:focus-visible,
            .doc-icon-btn:focus-visible,
            .doc-scorecard-submit-btn:focus-visible,
            .doc-modal-close:focus-visible,
            .doc-modal-submit:focus-visible,
            .doc-field-input:focus-visible,
            .doc-field-select:focus-visible,
            .doc-field-textarea:focus-visible {
                outline: 3px solid #bfdbfe;
                outline-offset: 2px;
            }
            .wawancara-filter-empty {
                display: none;
                margin: 0 0 14px;
                padding: 12px;
                border: 1px dashed #cbd5e1;
                border-radius: 10px;
                background: #f8fafc;
                color: #64748b;
                font-size: 13px;
            }
            .btn-back {
                display: inline-block;
                text-decoration: none;
                background: #111827;
                color: #fff;
                padding: 10px 16px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                border: 0;
            }
            .btn-back:hover {
                background: #0f172a;
            }
            .rekap-grid {
                display: grid;
                gap: 12px;
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .rekap-card {
                border: 1px solid #e2e8f0;
                border-radius: 10px;
                padding: 14px;
                background: #fff;
            }
            .rekap-head {
                display: flex;
                justify-content: space-between;
                align-items: baseline;
                gap: 8px;
                margin-bottom: 10px;
            }
            .rekap-title {
                margin: 0;
                font-size: 18px;
            }
            .rekap-title-sub {
                display: block;
                margin-top: 3px;
                font-size: 12px;
                font-weight: 700;
                color: #64748b;
            }
            .rekap-total {
                margin: 0;
                font-size: 13px;
                color: #475569;
                font-weight: 700;
            }
            .top10-title {
                margin: 0 0 8px;
                font-size: 13px;
                color: #475569;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.03em;
            }
            .candidate-list {
                margin: 0;
                padding: 0;
                list-style: none;
                color: #334155;
                display: grid;
                gap: 10px;
            }
            .candidate-item {
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                background: #f8fafc;
                padding: 10px;
            }
            .candidate-main {
                color: #1e293b;
                font-size: 14px;
                font-weight: 600;
                line-height: 1.5;
            }
            .flag-state {
                margin-top: 6px;
                display: flex;
                gap: 6px;
                flex-wrap: wrap;
            }
            .candidate-doc-action {
                margin-top: 8px;
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
                align-items: center;
            }
            .doc-icon-btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 6px;
                min-width: 34px;
                height: 32px;
                padding: 0 10px;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                background: #ffffff;
                color: #334155;
                font-size: 13px;
                line-height: 1;
                cursor: pointer;
                font-weight: 700;
                transition: background 0.15s ease, border-color 0.15s ease, color 0.15s ease;
            }
            .doc-icon-btn:hover {
                background: #f8fafc;
            }
            .doc-icon-btn:disabled {
                opacity: 1;
                cursor: not-allowed;
                border-color: #cbd5e1;
                background: #f1f5f9;
                color: #64748b;
            }
            .doc-icon-btn.secondary {
                background: #eef2ff;
                border-color: #c7d2fe;
                color: #3730a3;
            }
            .doc-icon-btn.secondary:hover {
                background: #e0e7ff;
            }
            .doc-icon-btn.secondary:disabled {
                border-color: #cbd5e1;
                background: #f1f5f9;
                color: #64748b;
            }
            .doc-icon {
                font-size: 16px;
                line-height: 1;
            }
            .doc-label {
                white-space: nowrap;
            }
            .doc-action-form {
                margin: 0;
                display: inline-flex;
            }
            .doc-scorecard-submit-btn {
                border: 1px solid #1d4ed8;
                border-radius: 8px;
                background: #dbeafe;
                color: #1d4ed8;
                padding: 0 10px;
                height: 32px;
                font-size: 13px;
                font-weight: 700;
                cursor: pointer;
                white-space: nowrap;
                transition: background 0.15s ease, border-color 0.15s ease, color 0.15s ease;
            }
            .doc-scorecard-submit-btn:hover {
                background: #bfdbfe;
            }
            .doc-scorecard-submit-btn:disabled {
                opacity: 1;
                cursor: not-allowed;
                border-color: #cbd5e1;
                background: #f1f5f9;
                color: #64748b;
            }
            .flag-badge {
                display: inline-block;
                padding: 2px 7px;
                border-radius: 999px;
                border: 1px solid #cbd5e1;
                background: #f1f5f9;
                color: #475569;
                font-size: 11px;
                font-weight: 700;
            }
            .flag-badge.on {
                border-color: #86efac;
                background: #dcfce7;
                color: #166534;
            }
            .flag-badge.screening-on {
                border-color: #a5b4fc;
                background: #e0e7ff;
                color: #3730a3;
            }
            .flag-badge.interviewer-on {
                border-color: #7dd3fc;
                background: #e0f2fe;
                color: #075985;
            }
            .flag-badge.kesediaan-empty {
                border-color: #cbd5e1;
                background: #f1f5f9;
                color: #475569;
            }
            .flag-badge.kesediaan-progress {
                border-color: #93c5fd;
                background: #dbeafe;
                color: #1e3a8a;
            }
            .flag-badge.kesediaan-complete {
                border-color: #86efac;
                background: #dcfce7;
                color: #166534;
            }
            .flag-badge.scorecard-empty {
                border-color: #cbd5e1;
                background: #f1f5f9;
                color: #64748b;
            }
            .flag-badge.scorecard-on {
                border-color: #fcd34d;
                background: #fef3c7;
                color: #92400e;
            }
            .wawancara-alert {
                margin: 0 0 14px;
                border-radius: 8px;
                padding: 10px 12px;
                font-size: 13px;
                line-height: 1.5;
            }
            .wawancara-alert.success {
                border: 1px solid #86efac;
                background: #dcfce7;
                color: #166534;
            }
            .wawancara-alert.error {
                border: 1px solid #fecaca;
                background: #fee2e2;
                color: #b91c1c;
            }
            .empty {
                margin: 0;
                padding: 12px;
                border: 1px dashed #cbd5e1;
                border-radius: 10px;
                color: #64748b;
                background: #f8fafc;
            }
            .doc-modal {
                position: fixed;
                inset: 0;
                display: none;
                align-items: flex-start;
                justify-content: center;
                padding: 16px;
                overflow-y: auto;
                background: rgba(15, 23, 42, 0.45);
                z-index: 1000;
            }
            .doc-modal.open {
                display: flex;
            }
            #candidateDocModal {
                align-items: center;
            }
            #candidateViewModal {
                align-items: center;
            }
            #candidateScoreCardModal {
                align-items: center;
            }
            .doc-modal-panel {
                width: 100%;
                max-width: 540px;
                max-height: calc(100vh - 32px);
                overflow-y: auto;
                background: #ffffff;
                border-radius: 12px;
                border: 1px solid #cbd5e1;
                padding: 16px;
                box-shadow: 0 20px 40px rgba(15, 23, 42, 0.2);
            }
            .doc-modal-panel.view {
                max-width: 760px;
            }
            .doc-modal-panel.scorecard {
                max-width: 980px;
            }
            .doc-modal-title {
                margin: 0 0 10px;
                color: #0f172a;
                font-size: 20px;
            }
            .doc-modal-text {
                margin: 0 0 12px;
                color: #334155;
                line-height: 1.5;
            }
            .doc-modal-form {
                display: grid;
                gap: 10px;
            }
            .doc-field {
                display: grid;
                gap: 6px;
            }
            .doc-field-label {
                color: #334155;
                font-size: 13px;
                font-weight: 700;
            }
            .doc-field-input,
            .doc-field-select {
                width: 100%;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                background: #fff;
                color: #0f172a;
                padding: 8px 10px;
                font-size: 13px;
            }
            .doc-field-textarea {
                width: 100%;
                min-height: 88px;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                background: #fff;
                color: #0f172a;
                padding: 8px 10px;
                font-size: 13px;
                line-height: 1.5;
                resize: vertical;
                font-family: inherit;
            }
            .name-display-uppercase {
                text-transform: uppercase;
            }
            .doc-check-group {
                display: flex;
                gap: 12px;
                flex-wrap: wrap;
            }
            .doc-check-item {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                font-size: 13px;
                color: #1e293b;
                font-weight: 600;
            }
            .doc-modal-actions {
                margin-top: 14px;
                display: flex;
                justify-content: flex-end;
                gap: 8px;
            }
            .doc-modal-close {
                border: 1px solid #94a3b8;
                border-radius: 8px;
                background: #f8fafc;
                color: #0f172a;
                padding: 8px 12px;
                font-size: 13px;
                font-weight: 700;
                cursor: pointer;
                transition: background 0.15s ease, border-color 0.15s ease, color 0.15s ease;
            }
            .doc-modal-close:hover {
                background: #e2e8f0;
            }
            .doc-modal-submit {
                border: 1px solid #1d4ed8;
                border-radius: 8px;
                background: #2563eb;
                color: #ffffff;
                padding: 8px 12px;
                font-size: 13px;
                font-weight: 700;
                cursor: pointer;
                transition: background 0.15s ease, border-color 0.15s ease, color 0.15s ease;
            }
            .doc-modal-submit:hover {
                background: #1d4ed8;
            }
            .doc-view-empty {
                margin: 0;
                padding: 10px 12px;
                border-radius: 8px;
                border: 1px dashed #cbd5e1;
                background: #f8fafc;
                color: #64748b;
                font-size: 13px;
            }
            .doc-view-recap {
                margin: 0 0 10px;
                padding: 10px 12px;
                border-radius: 8px;
                border: 1px solid #dbeafe;
                background: #f8fafc;
            }
            .doc-view-recap-title {
                margin: 0 0 8px;
                font-size: 12px;
                color: #1e3a8a;
                font-weight: 800;
                letter-spacing: 0.02em;
                text-transform: uppercase;
            }
            .doc-view-recap-table-wrap {
                border: 1px solid #dbeafe;
                border-radius: 8px;
                overflow: auto;
                background: #f8fafc;
            }
            .doc-view-recap-table {
                width: 100%;
                border-collapse: collapse;
                min-width: 620px;
                font-size: 12px;
            }
            .doc-view-recap-table th,
            .doc-view-recap-table td {
                padding: 8px 9px;
                border-bottom: 1px solid #e2e8f0;
                text-align: left;
                vertical-align: top;
                line-height: 1.4;
                color: #1e293b;
            }
            .doc-view-recap-table th {
                position: sticky;
                top: 0;
                z-index: 1;
                background: #f1f5f9;
                color: #334155;
                font-weight: 800;
            }
            .doc-view-recap-table tbody tr:last-child td {
                border-bottom: 0;
            }
            .doc-view-link {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                color: #1d4ed8;
                text-decoration: none;
                font-size: 13px;
                font-weight: 700;
            }
            .doc-view-link:hover {
                text-decoration: underline;
            }
            .doc-view-link-group {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                flex-wrap: wrap;
                margin-top: 4px;
            }
            .doc-modal-form.scorecard-form {
                gap: 14px;
            }
            .scorecard-scale-box,
            .scorecard-template-state,
            .scorecard-ranges {
                border: 1px solid #dbe3ef;
                border-radius: 10px;
                background: #f8fafc;
                padding: 12px;
            }
            .scorecard-scale-title,
            .scorecard-range-title {
                margin: 0 0 8px;
                color: #0f172a;
                font-size: 13px;
                font-weight: 800;
            }
            .scorecard-scale-list,
            .scorecard-range-list {
                margin: 0;
                padding-left: 18px;
                color: #334155;
                font-size: 13px;
                line-height: 1.5;
            }
            .scorecard-meta-grid {
                display: grid;
                gap: 12px;
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .scorecard-template-state {
                color: #64748b;
                font-size: 13px;
            }
            .scorecard-template-state.error {
                border-color: #fecaca;
                background: #fef2f2;
                color: #b91c1c;
            }
            .scorecard-section-list {
                display: grid;
                gap: 14px;
            }
            .scorecard-section {
                border: 1px solid #dbe3ef;
                border-radius: 12px;
                background: #ffffff;
                padding: 14px;
            }
            .scorecard-section-head {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                gap: 12px;
                margin-bottom: 12px;
            }
            .scorecard-section-title {
                margin: 0;
                color: #0f172a;
                font-size: 17px;
                font-weight: 800;
            }
            .scorecard-section-focus {
                margin: 6px 0 0;
                color: #475569;
                font-size: 13px;
                line-height: 1.5;
            }
            .scorecard-section-weight {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                padding: 5px 10px;
                border-radius: 999px;
                background: #e0e7ff;
                color: #3730a3;
                font-size: 12px;
                font-weight: 800;
                white-space: nowrap;
            }
            .scorecard-question-list {
                display: grid;
                gap: 12px;
            }
            .scorecard-question {
                border: 1px solid #e2e8f0;
                border-radius: 10px;
                background: #f8fafc;
                padding: 12px;
            }
            .scorecard-question-head {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                gap: 12px;
                margin-bottom: 10px;
            }
            .scorecard-question-title {
                margin: 0;
                color: #0f172a;
                font-size: 14px;
                font-weight: 700;
                line-height: 1.5;
            }
            .scorecard-score-group {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                flex-wrap: wrap;
                justify-content: flex-end;
            }
            .scorecard-score-option {
                display: inline-flex;
                align-items: center;
                gap: 4px;
                padding: 5px 8px;
                border: 1px solid #cbd5e1;
                border-radius: 999px;
                background: #fff;
                color: #1e293b;
                font-size: 12px;
                font-weight: 700;
                cursor: pointer;
            }
            .scorecard-score-option input {
                margin: 0;
            }
            .scorecard-indicators {
                display: grid;
                gap: 10px;
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .scorecard-indicator {
                border-radius: 10px;
                padding: 10px;
                font-size: 13px;
                line-height: 1.5;
            }
            .scorecard-indicator.low {
                border: 1px solid #fecaca;
                background: #fef2f2;
                color: #991b1b;
            }
            .scorecard-indicator.high {
                border: 1px solid #bbf7d0;
                background: #f0fdf4;
                color: #166534;
            }
            .scorecard-indicator-title {
                margin: 0 0 6px;
                font-size: 12px;
                font-weight: 800;
                text-transform: uppercase;
                letter-spacing: 0.03em;
            }
            .scorecard-indicator ul {
                margin: 0;
                padding-left: 18px;
            }
            .scorecard-indicator li + li {
                margin-top: 4px;
            }
            .scorecard-section-summary,
            .scorecard-final-grid {
                display: grid;
                gap: 10px;
                grid-template-columns: repeat(4, minmax(0, 1fr));
            }
            .scorecard-summary-item,
            .scorecard-final-card {
                border: 1px solid #dbe3ef;
                border-radius: 10px;
                background: #f8fafc;
                padding: 10px 12px;
            }
            .scorecard-summary-label,
            .scorecard-final-label {
                display: block;
                color: #64748b;
                font-size: 12px;
                font-weight: 700;
                margin-bottom: 4px;
            }
            .scorecard-summary-value,
            .scorecard-final-value {
                display: block;
                color: #0f172a;
                font-size: 18px;
                font-weight: 800;
                line-height: 1.2;
            }
            .scorecard-final-card.highlight {
                border-color: #93c5fd;
                background: #eff6ff;
            }
            .scorecard-range-list {
                display: grid;
                gap: 6px;
                padding-left: 18px;
            }
            .scorecard-range-item.active {
                color: #1d4ed8;
                font-weight: 800;
            }
            .scorecard-save-note {
                margin: 0;
                color: #64748b;
                font-size: 12px;
            }
            .scorecard-hidden {
                display: none !important;
            }
            @media (max-width: 820px) {
                .rekap-grid {
                    grid-template-columns: 1fr;
                }
                .scorecard-meta-grid,
                .scorecard-indicators,
                .scorecard-section-summary,
                .scorecard-final-grid {
                    grid-template-columns: 1fr;
                }
                .scorecard-question-head,
                .scorecard-section-head {
                    flex-direction: column;
                }
                .scorecard-score-group {
                    justify-content: flex-start;
                }
            }
            @media (max-width: 640px) {
                .card {
                    padding: 18px;
                }
                h1 {
                    font-size: 22px;
                }
                .top-actions {
                    width: 100%;
                }
                .btn-back {
                    width: 100%;
                    text-align: center;
                }
                .wawancara-filter-bar {
                    align-items: stretch;
                }
                .wawancara-filter-select {
                    width: 100%;
                    min-width: 0;
                }
                .doc-modal {
                    padding: 10px;
                }
                .doc-modal-panel {
                    width: 100%;
                    max-width: 540px;
                    max-height: calc(100vh - 20px);
                    padding: 12px;
                }
                .doc-modal-panel.scorecard {
                    max-width: 980px;
                }
            }
        </style>
        <?php render_language_switcher_head(); ?>
    </head>
    <body>
        <main class="wrap">
            <section class="card">
                <div class="topbar">
                    <div>
                        <h1 data-i18n="wawancara_title">Halaman Wawancara</h1>
                    </div>
                    <div class="top-actions">
                        <a class="btn-back" href="<?= h(app_index_url(['page' => 'bidang'])) ?>" data-i18n="wawancara_back">Kembali ke Halaman Bidang</a>
                    </div>
                </div>
                <?php if ($wawancaraSuccessMessage !== ''): ?>
                    <div class="wawancara-alert success"><?= h($wawancaraSuccessMessage) ?></div>
                <?php endif; ?>
                <?php if ($wawancaraErrorMessage !== ''): ?>
                    <div class="wawancara-alert error"><?= h($wawancaraErrorMessage) ?></div>
                <?php endif; ?>
                <?php if ($wawancaraBidangSummary === []): ?>
                    <p class="empty"><?= h($wawancaraEmptyMessage) ?></p>
                <?php else: ?>
                    <div class="wawancara-filter-bar">
                        <p class="wawancara-filter-label" data-i18n="wawancara_filter_label">Filter proses kandidat</p>
                        <select class="wawancara-filter-select" id="wawancaraProcessFilter" aria-label="Filter proses kandidat" data-i18n-aria-label="wawancara_filter_label">
                            <option value="all" <?= $wawancaraProcessFilter === 'all' ? 'selected' : '' ?> data-i18n="filter_all">Semua</option>
                            <option value="belum_lanjut" <?= $wawancaraProcessFilter === 'belum_lanjut' ? 'selected' : '' ?> data-i18n="filter_not_advanced">Belum Lanjut Proses</option>
                            <option value="lanjut" <?= $wawancaraProcessFilter === 'lanjut' ? 'selected' : '' ?> data-i18n="filter_advanced">Lanjut Proses</option>
                            <option value="screening" <?= $wawancaraProcessFilter === 'screening' ? 'selected' : '' ?> data-i18n="filter_screening">Lolos Screening</option>
                            <option value="scorecard_submitted" <?= $wawancaraProcessFilter === 'scorecard_submitted' ? 'selected' : '' ?> data-i18n="filter_scorecard_submitted">Sudah Submit Score Card</option>
                        </select>
                    </div>
                    <div class="wawancara-filter-empty" id="wawancaraFilterEmpty" data-i18n="wawancara_filter_empty">Tidak ada kandidat yang cocok dengan filter proses yang dipilih.</div>
                    <div class="rekap-grid">
                        <?php foreach ($wawancaraBidangSummary as $bidang => $summary): ?>
                            <?php
                            $wawancaraBidangParts = bidang_title_parts((string)$bidang);
                            $wawancaraMainTitle = (string)($wawancaraBidangParts['main'] ?? (string)$bidang);
                                if ($wawancaraMainTitle === '') {
                                    $wawancaraMainTitle = (string)$bidang;
                                }
                                $wawancaraCabangTitle = (string)($wawancaraBidangParts['cabang'] ?? '');
                            ?>
                            <article class="rekap-card" data-wawancara-card="1">
                                <div class="rekap-head">
                                    <h2 class="rekap-title">
                                        <span data-lang-text-id="<?= h($wawancaraMainTitle) ?>" data-lang-text-en="<?= h(bidang_translate_main_title($wawancaraMainTitle, 'en')) ?>"><?= h($wawancaraMainTitle) ?></span>
                                        <?php if ($wawancaraCabangTitle !== ''): ?>
                                            <span class="rekap-title-sub"><?= h($wawancaraCabangTitle) ?></span>
                                        <?php endif; ?>
                                    </h2>
                                    <p class="rekap-total" data-i18n="dashboard_rekap_total_votes" data-i18n-vars="<?= h((string)json_encode(['count' => (string)($summary['total'] ?? 0)], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"><?= h((string)($summary['total'] ?? 0)) ?> vote</p>
                                </div>
                                <?php if ((array)($summary['top_candidates'] ?? []) === []): ?>
                                    <p class="empty" data-i18n="wawancara_empty_candidates">Belum ada kandidat pada bidang ini.</p>
                                <?php else: ?>
                                    <ul class="candidate-list">
                                        <?php foreach ((array)($summary['top_candidates'] ?? []) as $index => $candidate): ?>
                                            <?php
                                            $wawancaraCandidateName = (string)($candidate['nama'] ?? '-');
                                            $wawancaraCandidateCabang = (string)($candidate['cabang'] ?? '-');
                                            $wawancaraCandidateCount = (int)($candidate['count'] ?? 0);
                                            $wawancaraCandidateKey = flagging_candidate_key((string)$bidang, $wawancaraCandidateName, $wawancaraCandidateCabang);
                                            $wawancaraCandidateFlag = (array)($wawancaraFlagMap[$wawancaraCandidateKey] ?? []);
                                            $isWawancaraLanjut = !empty($wawancaraCandidateFlag['lanjut_proses']);
                                            $isWawancaraScreening = !empty($wawancaraCandidateFlag['lolos_screening']) && $isWawancaraLanjut;
                                            $wawancaraKesediaanKey = kesediaan_candidate_key($wawancaraCandidateName, $wawancaraCandidateCabang);
                                            $wawancaraCandidateForms = (array)($wawancaraKesediaanFormMap[$wawancaraKesediaanKey] ?? []);
                                            $wawancaraTotalFormCount = 0;
                                            $wawancaraBersediaCount = 0;
                                            foreach ($wawancaraCandidateForms as $wawancaraKesediaanItemRaw) {
                                                if (!is_array($wawancaraKesediaanItemRaw)) {
                                                    continue;
                                                }
                                                $wawancaraKesediaanStatus = normalize_kesediaan_status((string)($wawancaraKesediaanItemRaw['status_kesediaan'] ?? ''));
                                                if ($wawancaraKesediaanStatus === '') {
                                                    continue;
                                                }
                                                $wawancaraTotalFormCount++;
                                                if ($wawancaraKesediaanStatus === 'bersedia') {
                                                    $wawancaraBersediaCount++;
                                                }
                                            }
                                            $wawancaraFormExists = $wawancaraTotalFormCount > 0;
                                            $wawancaraKesediaanBadgeText = 'Belum Bersedia';
                                            $wawancaraKesediaanBadgeTextEn = 'Not Yet Willing';
                                            $wawancaraKesediaanBadgeClass = ' kesediaan-empty';
                                            if ($wawancaraFormExists) {
                                                $wawancaraKesediaanBadgeText = $wawancaraBersediaCount . '/' . $wawancaraTotalFormCount . ' bersedia';
                                                $wawancaraKesediaanBadgeTextEn = $wawancaraBersediaCount . '/' . $wawancaraTotalFormCount . ' willing';
                                                $wawancaraKesediaanBadgeClass = $wawancaraBersediaCount >= $wawancaraTotalFormCount ? ' kesediaan-complete' : ' kesediaan-progress';
                                            }
                                            $canInputKesediaanForm = !$isWawancaraLanjut;
                                            $wawancaraFormKesediaanTitle = $canInputKesediaanForm
                                                ? 'Lihat dokumen sementara kandidat'
                                                : 'Form kesediaan terkunci karena kandidat sudah lanjut proses';
                                            $wawancaraFormKesediaanTitleEn = $canInputKesediaanForm
                                                ? 'View temporary candidate document'
                                                : 'Consent form is locked because the candidate has already advanced';
                                            $wawancaraLockedPihakUsed = kesediaan_used_single_submit_hubungan($wawancaraCandidateForms);
                                            $wawancaraLockedPihakUsedJsonRaw = json_encode(array_values($wawancaraLockedPihakUsed), JSON_UNESCAPED_UNICODE);
                                            if (!is_string($wawancaraLockedPihakUsedJsonRaw)) {
                                                $wawancaraLockedPihakUsedJsonRaw = '[]';
                                            }
                                            $wawancaraLockedPihakUsedJson = h($wawancaraLockedPihakUsedJsonRaw);
                                            $wawancaraScorecardSubmission = (array)($wawancaraScorecardSubmissionMap[$wawancaraCandidateKey] ?? []);
                                            $wawancaraHasScorecard = $wawancaraScorecardSubmission !== [];
                                            $wawancaraScorecardSubmitted = !empty($wawancaraScorecardSubmission['is_submitted']);
                                            $wawancaraScorecardFinalScore = $wawancaraHasScorecard
                                                ? round((float)($wawancaraScorecardSubmission['final_score'] ?? 0), 2)
                                                : 0.0;
                                            $wawancaraScorecardBadgeText = 'Skor Akhir: ' . ($wawancaraHasScorecard
                                                ? number_format($wawancaraScorecardFinalScore, 2, '.', '')
                                                : '0');
                                            $wawancaraScorecardBadgeClass = $wawancaraHasScorecard ? ' scorecard-on' : ' scorecard-empty';
                                            $wawancaraScorecardSubmissionPayload = $wawancaraHasScorecard
                                                ? scorecard_submission_client_payload($wawancaraScorecardSubmission)
                                                : [];
                                            $wawancaraScorecardSubmissionJsonRaw = json_encode($wawancaraScorecardSubmissionPayload, JSON_UNESCAPED_UNICODE);
                                            if (!is_string($wawancaraScorecardSubmissionJsonRaw)) {
                                                $wawancaraScorecardSubmissionJsonRaw = '{}';
                                            }
                                            $wawancaraScorecardSubmissionJson = h($wawancaraScorecardSubmissionJsonRaw);
                                            $wawancaraFormItems = [];
                                            foreach ($wawancaraCandidateForms as $wawancaraFormItemRaw) {
                                                if (!is_array($wawancaraFormItemRaw)) {
                                                    continue;
                                                }
                                                $wawancaraFormStatusRaw = (string)($wawancaraFormItemRaw['status_kesediaan'] ?? '');
                                                $wawancaraFormStatusLabel = match ($wawancaraFormStatusRaw) {
                                                    'bersedia' => 'Bersedia',
                                                    'tidak_bersedia' => 'Tidak Bersedia',
                                                    default => '-',
                                                };
                                                $wawancaraFormFileName = trim((string)($wawancaraFormItemRaw['file_name_original'] ?? ''));
                                                if ($wawancaraFormFileName === '') {
                                                    $wawancaraFormFileName = trim((string)($wawancaraFormItemRaw['file_path'] ?? '-'));
                                                }
                                                $wawancaraFormFileUrl = kesediaan_form_view_url($wawancaraFormItemRaw);
                                                $wawancaraFormDownloadUrl = kesediaan_form_view_url($wawancaraFormItemRaw, true);
                                                $wawancaraFormIsImage = kesediaan_form_is_image_document($wawancaraFormItemRaw);
                                                $wawancaraFormIsPdf = kesediaan_form_is_pdf_document($wawancaraFormItemRaw);
                                                $wawancaraFormItems[] = [
                                                    'hubungan' => (string)($wawancaraFormItemRaw['hubungan'] ?? '-'),
                                                    'nama_pihak' => (string)($wawancaraFormItemRaw['nama_pihak'] ?? '-'),
                                                    'status' => $wawancaraFormStatusLabel,
                                                    'alasan' => (string)($wawancaraFormItemRaw['alasan'] ?? ''),
                                                    'file' => $wawancaraFormFileName,
                                                    'file_url' => $wawancaraFormFileUrl,
                                                    'file_download_url' => $wawancaraFormDownloadUrl,
                                                    'file_is_image' => $wawancaraFormIsImage,
                                                    'file_is_pdf' => $wawancaraFormIsPdf,
                                                    'updated_at' => trim((string)($wawancaraFormItemRaw['updated_at'] ?? '-')),
                                                ];
                                            }
                                            $wawancaraFormItemsJson = h((string)json_encode($wawancaraFormItems, JSON_UNESCAPED_UNICODE));
                                            ?>
                                            <li
                                                class="candidate-item"
                                                data-process-lanjut="<?= $isWawancaraLanjut ? '1' : '0' ?>"
                                                data-process-screening="<?= $isWawancaraScreening ? '1' : '0' ?>"
                                                data-process-scorecard-submitted="<?= $wawancaraScorecardSubmitted ? '1' : '0' ?>"
                                            >
                                                <div class="candidate-main">
                                                    #<?= h((string)($index + 1)) ?> -
                                                    <?= h_name($wawancaraCandidateName) ?>
                                                    (<?= h($wawancaraCandidateCabang) ?>)
                                                    - <span data-i18n="wawancara_votes_count" data-i18n-vars="<?= h((string)json_encode(['count' => (string)$wawancaraCandidateCount], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"><?= h((string)$wawancaraCandidateCount) ?> suara</span>
                                                </div>
                                                <div class="flag-state">
                                                    <span class="flag-badge<?= h($wawancaraKesediaanBadgeClass) ?>">
                                                        <span data-lang-text-id="<?= h($wawancaraKesediaanBadgeText) ?>" data-lang-text-en="<?= h($wawancaraKesediaanBadgeTextEn) ?>"><?= h($wawancaraKesediaanBadgeText) ?></span>
                                                    </span>
                                                    <?php if (!$isWawancaraScreening && $isWawancaraLanjut): ?>
                                                    <span class="flag-badge<?= $isWawancaraLanjut ? ' on' : '' ?>" data-i18n="<?= h($isWawancaraLanjut ? 'filter_advanced' : 'filter_not_advanced') ?>">
                                                        <?= $isWawancaraLanjut ? 'Lanjut Proses' : 'Belum Lanjut Proses' ?>
                                                    </span>
                                                    <?php endif; ?>
                                                    <?php if ($isWawancaraScreening): ?>
                                                    <span class="flag-badge on screening-on" data-i18n="filter_screening">
                                                        Lolos Screening
                                                    </span>
                                                    <span class="flag-badge<?= h($wawancaraScorecardBadgeClass) ?>">
                                                        <span data-lang-text-id="<?= h($wawancaraScorecardBadgeText) ?>" data-lang-text-en="<?= h('Final Score: ' . ($wawancaraHasScorecard ? number_format($wawancaraScorecardFinalScore, 2, '.', '') : '0')) ?>"><?= h($wawancaraScorecardBadgeText) ?></span>
                                                    </span>
                                                    <?php endif; ?>
                                                </div>
                                                <div class="candidate-doc-action">
                                                    <?php if ($isWawancaraScreening): ?>
                                                        <button
                                                            class="doc-icon-btn"
                                                            type="button"
                                                            data-lang-title-id="<?= h($wawancaraScorecardSubmitted ? 'Lihat score card kandidat ini' : ($wawancaraHasScorecard ? 'Edit score card kandidat ini' : 'Input score card kandidat ini')) ?>"
                                                            data-lang-title-en="<?= h($wawancaraScorecardSubmitted ? 'View this candidate\'s score card' : ($wawancaraHasScorecard ? 'Edit this candidate\'s score card' : 'Input this candidate\'s score card')) ?>"
                                                            title="<?= $wawancaraScorecardSubmitted ? 'Lihat score card kandidat ini' : ($wawancaraHasScorecard ? 'Edit score card kandidat ini' : 'Input score card kandidat ini') ?>"
                                                            data-candidate-bidang="<?= h((string)$bidang) ?>"
                                                            data-candidate-name="<?= h($wawancaraCandidateName) ?>"
                                                            data-candidate-cabang="<?= h($wawancaraCandidateCabang) ?>"
                                                            data-scorecard-submission="<?= $wawancaraScorecardSubmissionJson ?>"
                                                            data-scorecard-readonly="<?= $wawancaraScorecardSubmitted ? '1' : '0' ?>"
                                                            data-scorecard-submitted="<?= $wawancaraScorecardSubmitted ? '1' : '0' ?>"
                                                            onclick="showScoreCardModal(this)"
                                                        >
                                                            <span class="doc-icon" aria-hidden="true">&#128203;</span>
                                                            <span class="doc-label" data-lang-text-id="<?= h($wawancaraScorecardSubmitted ? 'Lihat Score Card' : ($wawancaraHasScorecard ? 'Edit Score Card' : 'Input Score Card')) ?>" data-lang-text-en="<?= h($wawancaraScorecardSubmitted ? 'View Score Card' : ($wawancaraHasScorecard ? 'Edit Score Card' : 'Input Score Card')) ?>"><?= $wawancaraScorecardSubmitted ? 'Lihat Score Card' : ($wawancaraHasScorecard ? 'Edit Score Card' : 'Input Score Card') ?></span>
                                                        </button>
                                                    <?php else: ?>
                                                        <button
                                                            class="doc-icon-btn"
                                                            type="button"
                                                            data-lang-title-id="<?= h($wawancaraFormKesediaanTitle) ?>"
                                                            data-lang-title-en="<?= h($wawancaraFormKesediaanTitleEn) ?>"
                                                            title="<?= h($wawancaraFormKesediaanTitle) ?>"
                                                            data-candidate-bidang="<?= h((string)$bidang) ?>"
                                                            data-candidate-name="<?= h($wawancaraCandidateName) ?>"
                                                            data-candidate-cabang="<?= h($wawancaraCandidateCabang) ?>"
                                                            data-used-locked-pihak="<?= $wawancaraLockedPihakUsedJson ?>"
                                                            onclick="showTemporaryCandidatePopup(this)"
                                                            <?= $canInputKesediaanForm ? '' : 'disabled' ?>
                                                        >
                                                            <span class="doc-icon" aria-hidden="true">&#128196;</span>
                                                            <span class="doc-label" data-i18n="wawancara_form_consent">Form Kesediaan</span>
                                                        </button>
                                                    <?php endif; ?>
                                                    <button
                                                        class="doc-icon-btn secondary"
                                                        type="button"
                                                        data-lang-title-id="<?= h($wawancaraFormExists ? 'Lihat form kesediaan yang sudah diinput' : 'Belum ada form kesediaan yang diinput') ?>"
                                                        data-lang-title-en="<?= h($wawancaraFormExists ? 'View submitted consent forms' : 'No consent forms have been submitted yet') ?>"
                                                        title="<?= $wawancaraFormExists ? 'Lihat form kesediaan yang sudah diinput' : 'Belum ada form kesediaan yang diinput' ?>"
                                                        data-candidate-name="<?= h($wawancaraCandidateName) ?>"
                                                        data-form-exists="<?= $wawancaraFormExists ? '1' : '0' ?>"
                                                        data-form-items="<?= $wawancaraFormItemsJson ?>"
                                                        onclick="showExistingKesediaanFormModal(this)"
                                                        <?= $wawancaraFormExists ? '' : 'disabled' ?>
                                                    >
                                                        <span class="doc-icon" aria-hidden="true">&#128065;</span>
                                                        <span class="doc-label" data-i18n="wawancara_view_form">Lihat Form</span>
                                                    </button>
                                                    <?php if ($isWawancaraScreening): ?>
                                                        <form
                                                            class="doc-action-form"
                                                            method="post"
                                                            action="<?= h(app_index_url($wawancaraPageParams)) ?>"
                                                            onsubmit="return confirm(window.majelisLang && typeof window.majelisLang.t === 'function' ? window.majelisLang.t('wawancara_submit_confirm', {}, 'Setelah submit, score card tidak dapat diubah lagi. Lanjutkan?') : 'Setelah submit, score card tidak dapat diubah lagi. Lanjutkan?')"
                                                        >
                                                            <input type="hidden" name="csrf_token" value="<?= h($wawancaraCsrfToken) ?>">
                                                            <input type="hidden" name="wawancara_action" value="submit_scorecard">
                                                            <input type="hidden" name="target_bidang" value="<?= h((string)$bidang) ?>">
                                                            <input type="hidden" name="target_kandidat_nama" value="<?= h($wawancaraCandidateName) ?>">
                                                            <input type="hidden" name="target_kandidat_cabang" value="<?= h($wawancaraCandidateCabang) ?>">
                                                            <button
                                                                class="doc-scorecard-submit-btn"
                                                                type="submit"
                                                                data-lang-title-id="<?= h($wawancaraScorecardSubmitted ? 'Score card sudah disubmit.' : ($wawancaraHasScorecard ? 'Submit score card kandidat ini.' : 'Isi score card terlebih dahulu sebelum submit.')) ?>"
                                                                data-lang-title-en="<?= h($wawancaraScorecardSubmitted ? 'This score card has already been submitted.' : ($wawancaraHasScorecard ? 'Submit this candidate\'s score card.' : 'Fill in the score card before submitting.')) ?>"
                                                                title="<?= $wawancaraScorecardSubmitted ? 'Score card sudah disubmit.' : ($wawancaraHasScorecard ? 'Submit score card kandidat ini.' : 'Isi score card terlebih dahulu sebelum submit.') ?>"
                                                                <?= (!$wawancaraHasScorecard || $wawancaraScorecardSubmitted) ? 'disabled' : '' ?>
                                                            >
                                                                <span data-lang-text-id="<?= h($wawancaraScorecardSubmitted ? 'Sudah Submit' : 'Submit Score Card') ?>" data-lang-text-en="<?= h($wawancaraScorecardSubmitted ? 'Submitted' : 'Submit Score Card') ?>"><?= $wawancaraScorecardSubmitted ? 'Sudah Submit' : 'Submit Score Card' ?></span>
                                                            </button>
                                                        </form>
                                                    <?php endif; ?>
                                                </div>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                <?php endif; ?>
                            </article>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </section>
        </main>
        <div class="doc-modal" id="candidateDocModal" role="dialog" aria-modal="true" aria-labelledby="candidate-doc-title">
            <div class="doc-modal-panel">
                <h2 class="doc-modal-title" id="candidate-doc-title" data-i18n="wawancara_consent_title">Form Kesediaan</h2>
                <p class="doc-modal-text" data-i18n-html="wawancara_candidate_doc_label">Kandidat: <strong id="candidateDocName">-</strong></p>
                <form class="doc-modal-form" method="post" action="<?= h(app_index_url($wawancaraPageParams)) ?>" enctype="multipart/form-data" id="candidateDocForm">
                    <input type="hidden" name="csrf_token" value="<?= h($wawancaraCsrfToken) ?>">
                    <input type="hidden" name="wawancara_action" value="save_kesediaan_form">
                    <input type="hidden" name="target_bidang" id="candidateDocBidang" value="">
                    <input type="hidden" name="target_kandidat_nama" id="candidateDocNamaInput" value="">
                    <input type="hidden" name="target_kandidat_cabang" id="candidateDocCabang" value="">

                    <div class="doc-field">
                        <label class="doc-field-label" for="hubungan" data-i18n="wawancara_consent_party_label">Pihak yang Menyatakan Kesediaan</label>
                        <select class="doc-field-select" id="hubungan" name="hubungan" required>
                            <option value="" data-i18n="wawancara_select_party">Pilih pihak</option>
                            <?php foreach (kesediaan_hubungan_options() as $hubunganOption): ?>
                                <option value="<?= h($hubunganOption) ?>"><?= h($hubunganOption) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="doc-field">
                        <label class="doc-field-label" for="nama_pihak" data-i18n="wawancara_party_name_label">Nama Lengkap Pihak</label>
                        <input
                            class="doc-field-input name-display-uppercase"
                            type="text"
                            id="nama_pihak"
                            name="nama_pihak"
                            placeholder="Pilih pihak terlebih dahulu"
                            data-i18n-placeholder="wawancara_party_name_placeholder_select"
                            maxlength="120"
                            required
                            disabled
                        >
                    </div>

                    <div class="doc-field">
                        <label class="doc-field-label" for="kesediaan_file" data-i18n="wawancara_meeting_photo_label">Bukti Foto Pertemuan</label>
                        <input class="doc-field-input" type="file" id="kesediaan_file" name="kesediaan_file" accept="image/*" required>
                    </div>

                    <div class="doc-field">
                        <span class="doc-field-label" data-i18n="wawancara_willingness_label">Kesediaan</span>
                        <div class="doc-check-group">
                            <label class="doc-check-item">
                                <input type="radio" name="status_kesediaan" value="bersedia" required>
                                <span data-i18n="wawancara_willing">Bersedia</span>
                            </label>
                            <label class="doc-check-item">
                                <input type="radio" name="status_kesediaan" value="tidak_bersedia" required>
                                <span data-i18n="wawancara_not_willing">Tidak Bersedia</span>
                            </label>
                        </div>
                    </div>

                    <div class="doc-field">
                        <label class="doc-field-label" for="kesediaan_alasan" data-i18n="wawancara_reason_optional">Alasan (Opsional)</label>
                        <textarea
                            class="doc-field-textarea"
                            id="kesediaan_alasan"
                            name="alasan"
                            rows="3"
                            placeholder="Tambahkan alasan jika diperlukan"
                            data-i18n-placeholder="wawancara_reason_placeholder"
                            maxlength="2000"
                        ></textarea>
                    </div>

                    <div class="doc-modal-actions">
                        <button class="doc-modal-close" type="button" onclick="closeTemporaryCandidatePopup()" data-i18n="wawancara_cancel">Batal</button>
                        <button class="doc-modal-submit" type="submit" data-i18n="wawancara_save">Simpan</button>
                    </div>
                </form>
            </div>
        </div>
        <div class="doc-modal" id="candidateViewModal" role="dialog" aria-modal="true" aria-labelledby="candidate-view-title">
            <div class="doc-modal-panel view">
                <h2 class="doc-modal-title" id="candidate-view-title" data-i18n="wawancara_view_consent_title">Lihat Form Kesediaan</h2>
                <p class="doc-modal-text" data-i18n-html="wawancara_candidate_view_label">Kandidat: <strong id="candidateViewName">-</strong></p>
                <div id="candidateViewRecap" class="doc-view-recap" style="display:none;">
                    <p class="doc-view-recap-title" data-i18n="wawancara_consent_recap_title">Rekap Pengisi Form</p>
                    <div class="doc-view-recap-table-wrap">
                        <table class="doc-view-recap-table">
                            <thead>
                                <tr>
                                    <th data-i18n="dashboard_log_no">No</th>
                                    <th data-i18n="wawancara_party">Pihak</th>
                                    <th data-i18n="wawancara_party_name">Nama Pihak</th>
                                    <th data-i18n="gembala_table_status">Status</th>
                                    <th data-i18n="wawancara_reason">Alasan</th>
                                    <th data-i18n="wawancara_document">Dokumen</th>
                                    <th data-i18n="wawancara_saved_at">Waktu Simpan</th>
                                </tr>
                            </thead>
                            <tbody id="candidateViewRecapBody"></tbody>
                        </table>
                    </div>
                </div>
                <div id="candidateViewEmpty" class="doc-view-empty" data-i18n="wawancara_view_empty">Belum ada form kesediaan yang disimpan untuk kandidat ini.</div>
                <div class="doc-modal-actions">
                    <button class="doc-modal-close" type="button" onclick="closeExistingKesediaanFormModal()" data-i18n="wawancara_close">Tutup</button>
                </div>
            </div>
        </div>
        <div class="doc-modal" id="candidateScoreCardModal" role="dialog" aria-modal="true" aria-labelledby="candidate-scorecard-title">
            <div class="doc-modal-panel scorecard">
                <h2 class="doc-modal-title" id="candidate-scorecard-title" data-i18n="wawancara_input_scorecard">Input Score Card</h2>
                <p class="doc-modal-text" data-i18n-html="wawancara_candidate_scorecard_label">Kandidat: <strong id="candidateScoreCardName">-</strong></p>
                <p class="doc-modal-text" data-i18n-html="wawancara_position_label">Bidang: <strong id="candidateScoreCardBidangName">-</strong></p>
                <form class="doc-modal-form scorecard-form" method="post" action="<?= h(app_index_url($wawancaraPageParams)) ?>" id="candidateScoreCardForm">
                    <input type="hidden" name="csrf_token" value="<?= h($wawancaraCsrfToken) ?>">
                    <input type="hidden" name="wawancara_action" value="save_scorecard">
                    <input type="hidden" name="target_bidang" id="candidateScoreCardBidangInput" value="">
                    <input type="hidden" name="target_kandidat_nama" id="candidateScoreCardNamaInput" value="">
                    <input type="hidden" name="target_kandidat_cabang" id="candidateScoreCardCabangInput" value="">

                    <div class="scorecard-scale-box">
                        <p class="scorecard-scale-title" data-i18n="wawancara_score_scale_title">Skala Penilaian</p>
                        <ul class="scorecard-scale-list">
                            <li><strong>1</strong> = Sangat Kurang. Ada red flag signifikan dan tidak direkomendasikan.</li>
                            <li><strong>3</strong> = Cukup/Memenuhi Syarat. Memenuhi standar dasar namun jawaban masih umum.</li>
                            <li><strong>5</strong> = Sangat Baik/Ideal. Menunjukkan kedalaman rohani, kematangan, dan kompetensi yang sangat baik.</li>
                        </ul>
                    </div>

                    <div id="candidateScoreCardTemplateState" class="scorecard-template-state scorecard-hidden" data-i18n="wawancara_scorecard_template_missing">Template score card belum tersedia untuk bidang ini.</div>

                    <div class="scorecard-meta-grid">
                        <div class="doc-field">
                            <label class="doc-field-label" for="scorecardInterviewDate" data-i18n="wawancara_interview_date">Tanggal Wawancara</label>
                            <input class="doc-field-input" type="date" id="scorecardInterviewDate" name="scorecard_interview_date" required>
                        </div>
                        <div class="doc-field">
                            <label class="doc-field-label" for="scorecardLocation" data-i18n="wawancara_location">Lokasi</label>
                            <input class="doc-field-input" type="text" id="scorecardLocation" name="scorecard_location" maxlength="180" required>
                        </div>
                    </div>

                    <div id="candidateScoreCardSections" class="scorecard-section-list"></div>

                    <div class="scorecard-final-grid">
                        <div class="scorecard-final-card highlight">
                            <span class="scorecard-final-label" data-i18n="wawancara_final_score">Total Score Akhir</span>
                            <strong class="scorecard-final-value" id="candidateScoreCardFinalScore">0.00</strong>
                        </div>
                        <div class="scorecard-final-card highlight">
                            <span class="scorecard-final-label" data-i18n="wawancara_auto_result">Hasil Otomatis</span>
                            <strong class="scorecard-final-value" id="candidateScoreCardRecommendation" data-i18n="wawancara_complete_scores">Lengkapi semua skor</strong>
                        </div>
                        <div class="scorecard-final-card">
                            <span class="scorecard-final-label">Template</span>
                            <strong class="scorecard-final-value" id="candidateScoreCardTemplateTitle">-</strong>
                        </div>
                        <div class="scorecard-final-card">
                            <span class="scorecard-final-label" data-i18n="wawancara_last_saved">Terakhir Disimpan</span>
                            <strong class="scorecard-final-value" id="candidateScoreCardUpdatedAt" data-i18n="wawancara_never_saved">Belum pernah disimpan</strong>
                        </div>
                    </div>

                    <div class="scorecard-ranges">
                        <p class="scorecard-range-title" data-i18n="wawancara_score_criteria">Kriteria Total Score Akhir</p>
                        <ul class="scorecard-range-list" id="candidateScoreCardRangeList"></ul>
                    </div>

                    <div class="doc-field">
                        <label class="doc-field-label" for="candidateScoreCardDecision" data-i18n="wawancara_interviewer_decision">Keputusan Pewawancara</label>
                        <select class="doc-field-select" id="candidateScoreCardDecision" name="scorecard_interviewer_decision" required></select>
                    </div>

                    <div class="doc-field">
                        <label class="doc-field-label" for="candidateScoreCardDecisionNote" data-i18n="wawancara_decision_note">Catatan Keputusan</label>
                        <textarea class="doc-field-textarea" id="candidateScoreCardDecisionNote" name="scorecard_decision_note" rows="3" placeholder="Isi catatan jika diperlukan" data-i18n-placeholder="wawancara_decision_note_placeholder"></textarea>
                    </div>

                    <p class="scorecard-save-note" data-i18n="wawancara_scorecard_note">Nilai bobot dan hasil akhir dihitung otomatis berdasarkan skor tiap pertanyaan.</p>

                    <div class="doc-modal-actions">
                        <button class="doc-modal-close" type="button" onclick="closeScoreCardModal()" data-i18n="wawancara_close">Tutup</button>
                        <button class="doc-modal-submit" type="submit" id="candidateScoreCardSubmit" data-i18n="wawancara_save_scorecard">Simpan Score Card</button>
                    </div>
                </form>
            </div>
        </div>
        <script>
            const scorecardTemplatesByBidang = <?= $wawancaraScorecardTemplatesJsonRaw ?>;
            const candidateDocModal = document.getElementById('candidateDocModal');
            const candidateDocName = document.getElementById('candidateDocName');
            const candidateDocForm = document.getElementById('candidateDocForm');
            const candidateDocBidang = document.getElementById('candidateDocBidang');
            const candidateDocNamaInput = document.getElementById('candidateDocNamaInput');
            const candidateDocCabang = document.getElementById('candidateDocCabang');
            const candidateDocPihakSelect = document.getElementById('hubungan');
            const candidateDocNamaPihakInput = document.getElementById('nama_pihak');
            const candidateViewModal = document.getElementById('candidateViewModal');
            const candidateViewName = document.getElementById('candidateViewName');
            const candidateViewRecap = document.getElementById('candidateViewRecap');
            const candidateViewRecapBody = document.getElementById('candidateViewRecapBody');
            const candidateViewEmpty = document.getElementById('candidateViewEmpty');
            const candidateScoreCardModal = document.getElementById('candidateScoreCardModal');
            const candidateScoreCardTitle = document.getElementById('candidate-scorecard-title');
            const candidateScoreCardName = document.getElementById('candidateScoreCardName');
            const candidateScoreCardBidangName = document.getElementById('candidateScoreCardBidangName');
            const candidateScoreCardForm = document.getElementById('candidateScoreCardForm');
            const candidateScoreCardBidangInput = document.getElementById('candidateScoreCardBidangInput');
            const candidateScoreCardNamaInput = document.getElementById('candidateScoreCardNamaInput');
            const candidateScoreCardCabangInput = document.getElementById('candidateScoreCardCabangInput');
            const candidateScoreCardTemplateState = document.getElementById('candidateScoreCardTemplateState');
            const candidateScoreCardTemplateTitle = document.getElementById('candidateScoreCardTemplateTitle');
            const candidateScoreCardInterviewDate = document.getElementById('scorecardInterviewDate');
            const candidateScoreCardLocation = document.getElementById('scorecardLocation');
            const candidateScoreCardSections = document.getElementById('candidateScoreCardSections');
            const candidateScoreCardRangeList = document.getElementById('candidateScoreCardRangeList');
            const candidateScoreCardFinalScore = document.getElementById('candidateScoreCardFinalScore');
            const candidateScoreCardRecommendation = document.getElementById('candidateScoreCardRecommendation');
            const candidateScoreCardUpdatedAt = document.getElementById('candidateScoreCardUpdatedAt');
            const candidateScoreCardDecision = document.getElementById('candidateScoreCardDecision');
            const candidateScoreCardDecisionNote = document.getElementById('candidateScoreCardDecisionNote');
            const candidateScoreCardSubmit = document.getElementById('candidateScoreCardSubmit');
            const wawancaraProcessFilter = document.getElementById('wawancaraProcessFilter');
            const wawancaraFilterEmpty = document.getElementById('wawancaraFilterEmpty');
            const singleSubmitPihakSet = new Set(['Diri Sendiri (Kandidat)', 'Ibu', 'Ayah']);
            let activeScoreCardTemplate = null;
            let activeScoreCardReadOnly = false;

            function t(key, fallback, vars) {
                if (window.majelisLang && typeof window.majelisLang.t === 'function') {
                    return window.majelisLang.t(key, vars || {}, fallback || '');
                }
                return fallback || '';
            }

            function displayNameText(value) {
                const raw = String(value || '').trim();
                if (raw === '') {
                    return '';
                }
                return typeof raw.toLocaleUpperCase === 'function'
                    ? raw.toLocaleUpperCase('id-ID')
                    : raw.toUpperCase();
            }

            function buildWawancaraFilterUrl(selectedFilter) {
                const url = new URL(window.location.href);
                url.searchParams.set('page', 'wawancara');
                if (selectedFilter && selectedFilter !== 'all') {
                    url.searchParams.set('wawancara_filter', selectedFilter);
                } else {
                    url.searchParams.delete('wawancara_filter');
                }
                url.hash = '';
                return url.toString();
            }

            function syncBodyScrollState() {
                const isDocOpen = candidateDocModal && candidateDocModal.classList.contains('open');
                const isViewOpen = candidateViewModal && candidateViewModal.classList.contains('open');
                const isScoreCardOpen = candidateScoreCardModal && candidateScoreCardModal.classList.contains('open');
                document.body.style.overflow = (isDocOpen || isViewOpen || isScoreCardOpen) ? 'hidden' : '';
            }

            function syncNamaPihakInputState() {
                if (!candidateDocPihakSelect || !candidateDocNamaPihakInput || !candidateDocNamaInput) {
                    return;
                }

                const selectedPihak = (candidateDocPihakSelect.value || '').trim();
                const kandidatName = (candidateDocNamaInput.value || '').trim();

                if (selectedPihak === '') {
                    candidateDocNamaPihakInput.value = '';
                    candidateDocNamaPihakInput.disabled = true;
                    candidateDocNamaPihakInput.readOnly = false;
                    candidateDocNamaPihakInput.placeholder = t('wawancara_party_name_placeholder_select', 'Pilih pihak terlebih dahulu');
                    candidateDocNamaPihakInput.dataset.autofilled = '0';
                    return;
                }

                candidateDocNamaPihakInput.disabled = false;
                candidateDocNamaPihakInput.placeholder = t('wawancara_party_name_placeholder_input', 'Masukkan nama lengkap');
                if (selectedPihak === 'Diri Sendiri (Kandidat)') {
                    candidateDocNamaPihakInput.value = kandidatName;
                    candidateDocNamaPihakInput.readOnly = true;
                    candidateDocNamaPihakInput.dataset.autofilled = '1';
                    return;
                }

                if (candidateDocNamaPihakInput.dataset.autofilled === '1') {
                    candidateDocNamaPihakInput.value = '';
                }
                candidateDocNamaPihakInput.readOnly = false;
                candidateDocNamaPihakInput.dataset.autofilled = '0';
            }

            function applyLockedPihakOptions(buttonElement) {
                if (!candidateDocPihakSelect) {
                    return;
                }

                let usedPihak = [];
                try {
                    const decoded = JSON.parse(buttonElement && buttonElement.dataset.usedLockedPihak ? buttonElement.dataset.usedLockedPihak : '[]');
                    if (Array.isArray(decoded)) {
                        usedPihak = decoded.map(function (item) {
                            return String(item || '').trim();
                        }).filter(function (item) {
                            return item !== '';
                        });
                    }
                } catch (error) {
                    usedPihak = [];
                }

                const usedSet = new Set(usedPihak);
                Array.prototype.forEach.call(candidateDocPihakSelect.options, function (option) {
                    const optionValue = String(option.value || '').trim();
                    if (!Object.prototype.hasOwnProperty.call(option.dataset, 'baseLabel')) {
                        option.dataset.baseLabel = option.textContent;
                    }
                    option.textContent = option.dataset.baseLabel;
                    option.disabled = false;

                    if (optionValue === '') {
                        return;
                    }
                    if (singleSubmitPihakSet.has(optionValue) && usedSet.has(optionValue)) {
                        option.disabled = true;
                        option.textContent = option.dataset.baseLabel + ' (sudah mengisi)';
                    }
                });

                const selectedOption = candidateDocPihakSelect.options[candidateDocPihakSelect.selectedIndex];
                if (selectedOption && selectedOption.disabled) {
                    candidateDocPihakSelect.value = '';
                }
            }

            function showTemporaryCandidatePopup(buttonElement) {
                if (
                    !buttonElement ||
                    !candidateDocModal ||
                    !candidateDocName ||
                    !candidateDocForm ||
                    !candidateDocBidang ||
                    !candidateDocNamaInput ||
                    !candidateDocCabang
                ) {
                    return;
                }

                const candidateBidang = (buttonElement.dataset.candidateBidang || '').trim();
                const candidateName = (buttonElement.dataset.candidateName || '').trim();
                const candidateCabang = (buttonElement.dataset.candidateCabang || '').trim();
                const displayName = candidateName !== '' ? displayNameText(candidateName) : '-';

                candidateDocForm.reset();
                candidateDocBidang.value = candidateBidang;
                candidateDocNamaInput.value = candidateName;
                candidateDocCabang.value = candidateCabang;
                candidateDocName.textContent = displayName;
                applyLockedPihakOptions(buttonElement);
                syncNamaPihakInputState();
                candidateDocModal.classList.add('open');
                syncBodyScrollState();
            }

            function closeTemporaryCandidatePopup() {
                if (!candidateDocModal) {
                    return;
                }
                candidateDocModal.classList.remove('open');
                syncBodyScrollState();
            }

            function showExistingKesediaanFormModal(buttonElement) {
                if (
                    !buttonElement ||
                    !candidateViewModal ||
                    !candidateViewName ||
                    !candidateViewRecap ||
                    !candidateViewRecapBody ||
                    !candidateViewEmpty
                ) {
                    return;
                }

                const candidateName = (buttonElement.dataset.candidateName || '').trim();
                let formItems = [];
                try {
                    const decoded = JSON.parse(buttonElement.dataset.formItems || '[]');
                    if (Array.isArray(decoded)) {
                        formItems = decoded;
                    }
                } catch (error) {
                    formItems = [];
                }

                const hasForm = formItems.length > 0;
                candidateViewName.textContent = candidateName !== '' ? displayNameText(candidateName) : '-';

                if (!hasForm) {
                    candidateViewRecapBody.innerHTML = '';
                    candidateViewRecap.style.display = 'none';
                    candidateViewEmpty.style.display = 'block';
                } else {
                    const recapRows = [];
                    formItems.forEach(function (item, idx) {
                        const recapHubungan = (item && item.hubungan ? String(item.hubungan) : '-');
                        const recapNamaPihak = (item && item.nama_pihak ? displayNameText(item.nama_pihak) : '-');
                        const recapStatus = (item && item.status ? String(item.status) : '-');
                        const recapAlasan = (item && item.alasan ? String(item.alasan) : '-');
                        const recapFileName = (item && item.file ? String(item.file) : '-');
                        const recapFileUrl = sanitizeSafeUrl(item && item.file_url ? String(item.file_url) : '');
                        const recapDownloadUrl = sanitizeSafeUrl(item && item.file_download_url ? String(item.file_download_url) : '');
                        const recapUpdatedAt = (item && item.updated_at ? String(item.updated_at) : '-');

                        let recapDocCell = '<span>-</span>';
                        if (recapFileUrl !== '' || recapDownloadUrl !== '') {
                            const actionLinks = [];
                            if (recapFileUrl !== '') {
                                actionLinks.push('<a class=\"doc-view-link\" href=\"' + escapeHtml(recapFileUrl) + '\" target=\"_blank\" rel=\"noopener\">' + escapeHtml(t('wawancara_view', 'Lihat')) + '</a>');
                            }
                            if (recapDownloadUrl !== '') {
                                actionLinks.push('<a class=\"doc-view-link\" href=\"' + escapeHtml(recapDownloadUrl) + '\" target=\"_blank\" rel=\"noopener\">Unduh</a>');
                            }
                            recapDocCell = '<div class=\"doc-view-link-group\">' + actionLinks.join('') + '</div>';
                        }

                        recapRows.push(
                            '<tr>' +
                                '<td>' + escapeHtml(String(idx + 1)) + '</td>' +
                                '<td>' + escapeHtml(recapHubungan) + '</td>' +
                                '<td>' + escapeHtml(recapNamaPihak) + '</td>' +
                                '<td>' + escapeHtml(recapStatus) + '</td>' +
                                '<td>' + escapeHtml(recapAlasan) + '</td>' +
                                '<td>' + recapDocCell + '</td>' +
                                '<td>' + escapeHtml(recapUpdatedAt) + '</td>' +
                            '</tr>'
                        );
                    });
                    if (recapRows.length === 0) {
                        recapRows.push('<tr><td colspan=\"7\">' + escapeHtml(t('wawancara_no_consent_data', 'Belum ada data form kesediaan.')) + '</td></tr>');
                    }
                    candidateViewRecapBody.innerHTML = recapRows.join('');
                    candidateViewRecap.style.display = 'block';
                    candidateViewEmpty.style.display = 'none';
                }

                candidateViewModal.classList.add('open');
                syncBodyScrollState();
            }

            function closeExistingKesediaanFormModal() {
                if (!candidateViewModal) {
                    return;
                }
                candidateViewModal.classList.remove('open');
                syncBodyScrollState();
            }

            function currentDateInputValue() {
                const now = new Date();
                const year = now.getFullYear();
                const month = String(now.getMonth() + 1).padStart(2, '0');
                const day = String(now.getDate()).padStart(2, '0');
                return year + '-' + month + '-' + day;
            }

            function getScoreCardTemplateForBidang(bidang) {
                const key = String(bidang || '').trim();
                if (key !== '' && scorecardTemplatesByBidang && Object.prototype.hasOwnProperty.call(scorecardTemplatesByBidang, key)) {
                    return scorecardTemplatesByBidang[key];
                }
                return null;
            }

            function getScoreCardRecommendation(template, score) {
                if (!template || !Array.isArray(template.final_ranges)) {
                    return '';
                }

                for (let i = 0; i < template.final_ranges.length; i++) {
                    const range = template.final_ranges[i] || {};
                    const min = Number(range.min || 0);
                    const max = Number(range.max || 0);
                    if (score >= min && score <= max) {
                        return String(range.label || '').trim();
                    }
                }

                return '';
            }

            function formatScoreCardNumber(value) {
                const numericValue = Number(value || 0);
                if (!Number.isFinite(numericValue)) {
                    return '0.00';
                }
                return numericValue.toFixed(2);
            }

            function scoreCardWeightLabel(weight) {
                const numericWeight = Number(weight || 0);
                if (!Number.isFinite(numericWeight)) {
                    return '0%';
                }
                return formatScoreCardNumber(numericWeight * 100).replace(/\.00$/, '') + '%';
            }

            function parseScoreCardSubmission(buttonElement) {
                if (!buttonElement) {
                    return {};
                }

                try {
                    const decoded = JSON.parse(buttonElement.dataset.scorecardSubmission || '{}');
                    return decoded && typeof decoded === 'object' ? decoded : {};
                } catch (error) {
                    return {};
                }
            }

            function renderScoreCardRanges(template, score, allAnswered) {
                if (!candidateScoreCardRangeList) {
                    return;
                }

                const ranges = template && Array.isArray(template.final_ranges) ? template.final_ranges : [];
                const recommendation = allAnswered ? getScoreCardRecommendation(template, score) : '';
                const items = ranges.map(function (range) {
                    const label = String(range && range.label ? range.label : '').trim();
                    const min = formatScoreCardNumber(range && range.min ? range.min : 0);
                    const max = formatScoreCardNumber(range && range.max ? range.max : 0);
                    const isActive = recommendation !== '' && recommendation === label;
                    return '<li class="scorecard-range-item' + (isActive ? ' active' : '') + '">' +
                        escapeHtml(min + ' - ' + max + ' = ' + label) +
                    '</li>';
                });

                candidateScoreCardRangeList.innerHTML = items.join('');
            }

            function renderScoreCardDecisionOptions(template, selectedValue) {
                if (!candidateScoreCardDecision) {
                    return;
                }

                const options = template && Array.isArray(template.decision_options) ? template.decision_options : [];
                const rows = ['<option value="">' + escapeHtml(t('wawancara_choose_decision', 'Pilih keputusan')) + '</option>'];
                options.forEach(function (option) {
                    const value = String(option || '').trim();
                    if (value === '') {
                        return;
                    }
                    const selected = value === selectedValue ? ' selected' : '';
                    rows.push('<option value="' + escapeHtml(value) + '"' + selected + '>' + escapeHtml(value) + '</option>');
                });
                candidateScoreCardDecision.innerHTML = rows.join('');
            }

            function renderScoreCardSections(template, submission) {
                if (!candidateScoreCardSections) {
                    return;
                }

                const answers = submission && submission.answers && typeof submission.answers === 'object' ? submission.answers : {};
                const sectionNotes = submission && submission.section_notes && typeof submission.section_notes === 'object' ? submission.section_notes : {};
                const sections = template && Array.isArray(template.sections) ? template.sections : [];
                const html = [];

                sections.forEach(function (section) {
                    const sectionId = String(section && section.id ? section.id : '').trim();
                    const sectionTitle = String(section && section.title ? section.title : '').trim();
                    const noteLabel = String(section && section.note_label ? section.note_label : ('Catatan Bagian ' + sectionId)).trim();
                    const focus = String(section && section.focus ? section.focus : '').trim();
                    const questions = Array.isArray(section && section.questions) ? section.questions : [];

                    const questionRows = questions.map(function (question) {
                        const questionId = String(question && question.id ? question.id : '').trim();
                        const label = String(question && question.label ? question.label : '').trim();
                        const lowIndicator = Array.isArray(question && question.low_indicator) ? question.low_indicator : [];
                        const highIndicator = Array.isArray(question && question.high_indicator) ? question.high_indicator : [];
                        const minScore = Number(question && question.min_score ? question.min_score : 1);
                        const maxScore = Number(question && question.max_score ? question.max_score : 5);
                        const existingScore = Number(Object.prototype.hasOwnProperty.call(answers, questionId) ? answers[questionId] : 0);
                        const radios = [];

                        for (let score = minScore; score <= maxScore; score++) {
                            const checked = existingScore === score ? ' checked' : '';
                            const required = score === minScore ? ' required' : '';
                            radios.push(
                                '<label class="scorecard-score-option">' +
                                    '<input type="radio" name="scorecard_answers[' + escapeHtml(questionId) + ']" value="' + escapeHtml(String(score)) + '"' + checked + required + '>' +
                                    '<span>' + escapeHtml(String(score)) + '</span>' +
                                '</label>'
                            );
                        }

                        const lowList = lowIndicator.length > 0
                            ? '<ul>' + lowIndicator.map(function (item) { return '<li>' + escapeHtml(String(item || '')) + '</li>'; }).join('') + '</ul>'
                            : '<div>-</div>';
                        const highList = highIndicator.length > 0
                            ? '<ul>' + highIndicator.map(function (item) { return '<li>' + escapeHtml(String(item || '')) + '</li>'; }).join('') + '</ul>'
                            : '<div>-</div>';

                        return (
                            '<article class="scorecard-question">' +
                                '<div class="scorecard-question-head">' +
                                    '<p class="scorecard-question-title">' + escapeHtml(questionId + '. ' + label) + '</p>' +
                                    '<div class="scorecard-score-group">' + radios.join('') + '</div>' +
                                '</div>' +
                                '<div class="scorecard-indicators">' +
                                    '<div class="scorecard-indicator low">' +
                                        '<p class="scorecard-indicator-title">Indikator Skor Rendah</p>' +
                                        lowList +
                                    '</div>' +
                                    '<div class="scorecard-indicator high">' +
                                        '<p class="scorecard-indicator-title">Indikator Skor Tinggi</p>' +
                                        highList +
                                    '</div>' +
                                '</div>' +
                            '</article>'
                        );
                    }).join('');

                    html.push(
                        '<section class="scorecard-section" data-section-id="' + escapeHtml(sectionId) + '" data-section-weight="' + escapeHtml(String(section && section.weight ? section.weight : 0)) + '">' +
                            '<div class="scorecard-section-head">' +
                                '<div>' +
                                    '<h3 class="scorecard-section-title">' + escapeHtml(sectionId + '. ' + sectionTitle) + '</h3>' +
                                    (focus !== '' ? '<p class="scorecard-section-focus">Fokus: ' + escapeHtml(focus) + '</p>' : '') +
                                '</div>' +
                                '<span class="scorecard-section-weight">Bobot ' + escapeHtml(scoreCardWeightLabel(section && section.weight ? section.weight : 0)) + '</span>' +
                            '</div>' +
                            '<div class="scorecard-question-list">' + questionRows + '</div>' +
                            '<div class="scorecard-section-summary">' +
                                '<div class="scorecard-summary-item"><span class="scorecard-summary-label">Total Score</span><strong class="scorecard-summary-value" data-section-total="' + escapeHtml(sectionId) + '">0.00</strong></div>' +
                                '<div class="scorecard-summary-item"><span class="scorecard-summary-label">Rata-rata</span><strong class="scorecard-summary-value" data-section-average="' + escapeHtml(sectionId) + '">0.00</strong></div>' +
                                '<div class="scorecard-summary-item"><span class="scorecard-summary-label">Nilai Bobot</span><strong class="scorecard-summary-value" data-section-weighted="' + escapeHtml(sectionId) + '">0.00</strong></div>' +
                                '<div class="scorecard-summary-item"><span class="scorecard-summary-label">Pertanyaan Terisi</span><strong class="scorecard-summary-value" data-section-answered="' + escapeHtml(sectionId) + '">0/' + escapeHtml(String(questions.length)) + '</strong></div>' +
                            '</div>' +
                            '<div class="doc-field">' +
                                '<label class="doc-field-label" for="scorecard_section_note_' + escapeHtml(sectionId) + '">' + escapeHtml(noteLabel) + '</label>' +
                                '<textarea class="doc-field-textarea" id="scorecard_section_note_' + escapeHtml(sectionId) + '" name="scorecard_section_notes[' + escapeHtml(sectionId) + ']" rows="3">' + escapeHtml(String(Object.prototype.hasOwnProperty.call(sectionNotes, sectionId) ? sectionNotes[sectionId] : '')) + '</textarea>' +
                            '</div>' +
                        '</section>'
                    );
                });

                candidateScoreCardSections.innerHTML = html.join('');
            }

            function syncScoreCardDecisionNoteRequirement() {
                if (!candidateScoreCardDecision || !candidateScoreCardDecisionNote) {
                    return;
                }

                const selectedDecision = String(candidateScoreCardDecision.value || '').trim().toLowerCase();
                const requiresNote = selectedDecision.indexOf('catatan') !== -1;
                candidateScoreCardDecisionNote.required = requiresNote;
                candidateScoreCardDecisionNote.placeholder = requiresNote
                    ? t('wawancara_decision_note_required', 'Catatan wajib diisi untuk keputusan ini')
                    : t('wawancara_decision_note_placeholder', 'Isi catatan jika diperlukan');
            }

            function setScoreCardFormReadOnly(readOnly, isSubmitted, hasSubmission) {
                activeScoreCardReadOnly = !!readOnly;

                if (candidateScoreCardTitle) {
                    if (activeScoreCardReadOnly) {
                        candidateScoreCardTitle.textContent = t('wawancara_view_scorecard', 'Lihat Score Card');
                    } else if (hasSubmission) {
                        candidateScoreCardTitle.textContent = t('wawancara_edit_scorecard', 'Edit Score Card');
                    } else {
                        candidateScoreCardTitle.textContent = t('wawancara_input_scorecard', 'Input Score Card');
                    }
                }

                if (candidateScoreCardForm) {
                    const controls = candidateScoreCardForm.querySelectorAll('input:not([type="hidden"]), select, textarea');
                    controls.forEach(function (control) {
                        control.disabled = activeScoreCardReadOnly;
                    });
                }

                if (candidateScoreCardSubmit) {
                    candidateScoreCardSubmit.disabled = activeScoreCardReadOnly;
                    candidateScoreCardSubmit.style.display = activeScoreCardReadOnly ? 'none' : '';
                    candidateScoreCardSubmit.textContent = hasSubmission ? t('wawancara_save_changes', 'Simpan Perubahan') : t('wawancara_save_scorecard', 'Simpan Score Card');
                }

                if (candidateScoreCardTemplateState) {
                    if (activeScoreCardReadOnly) {
                        candidateScoreCardTemplateState.textContent = isSubmitted
                            ? t('wawancara_scorecard_readonly_submitted', 'Score card sudah disubmit dan hanya dapat dilihat.')
                            : t('wawancara_scorecard_readonly', 'Score card hanya dapat dilihat.');
                        candidateScoreCardTemplateState.classList.remove('scorecard-hidden', 'error');
                    } else {
                        candidateScoreCardTemplateState.textContent = t('wawancara_scorecard_template_missing', 'Template score card belum tersedia untuk bidang ini.');
                        candidateScoreCardTemplateState.classList.add('scorecard-hidden');
                        candidateScoreCardTemplateState.classList.remove('error');
                    }
                }
            }

            function updateScoreCardSummary() {
                if (!candidateScoreCardForm || !activeScoreCardTemplate || !Array.isArray(activeScoreCardTemplate.sections)) {
                    return;
                }

                let finalScore = 0;
                let allAnswered = true;

                activeScoreCardTemplate.sections.forEach(function (section) {
                    const sectionId = String(section && section.id ? section.id : '').trim();
                    const questions = Array.isArray(section && section.questions) ? section.questions : [];
                    let sectionTotal = 0;
                    let answeredCount = 0;

                    questions.forEach(function (question) {
                        const questionId = String(question && question.id ? question.id : '').trim();
                        if (questionId === '') {
                            return;
                        }
                        const checked = candidateScoreCardForm.querySelector('input[name="scorecard_answers[' + questionId + ']"]:checked');
                        if (!checked) {
                            allAnswered = false;
                            return;
                        }
                        const score = Number(checked.value || 0);
                        if (Number.isFinite(score)) {
                            sectionTotal += score;
                            answeredCount++;
                        }
                    });

                    const questionCount = questions.length;
                    const sectionAverage = questionCount > 0 ? (sectionTotal / questionCount) : 0;
                    const sectionWeight = Number(section && section.weight ? section.weight : 0);
                    const weightedScore = sectionAverage * sectionWeight;
                    finalScore += weightedScore;

                    const totalEl = candidateScoreCardForm.querySelector('[data-section-total="' + sectionId + '"]');
                    const avgEl = candidateScoreCardForm.querySelector('[data-section-average="' + sectionId + '"]');
                    const weightedEl = candidateScoreCardForm.querySelector('[data-section-weighted="' + sectionId + '"]');
                    const answeredEl = candidateScoreCardForm.querySelector('[data-section-answered="' + sectionId + '"]');

                    if (totalEl) {
                        totalEl.textContent = formatScoreCardNumber(sectionTotal);
                    }
                    if (avgEl) {
                        avgEl.textContent = formatScoreCardNumber(sectionAverage);
                    }
                    if (weightedEl) {
                        weightedEl.textContent = formatScoreCardNumber(weightedScore);
                    }
                    if (answeredEl) {
                        answeredEl.textContent = String(answeredCount) + '/' + String(questionCount);
                    }
                });

                const roundedFinal = Math.round(finalScore * 100) / 100;
                if (candidateScoreCardFinalScore) {
                    candidateScoreCardFinalScore.textContent = formatScoreCardNumber(roundedFinal);
                }
                if (candidateScoreCardRecommendation) {
                    candidateScoreCardRecommendation.textContent = allAnswered
                        ? (getScoreCardRecommendation(activeScoreCardTemplate, roundedFinal) || '-')
                        : t('wawancara_complete_scores', 'Lengkapi semua skor');
                }
                renderScoreCardRanges(activeScoreCardTemplate, roundedFinal, allAnswered);
            }

            function resetScoreCardModal() {
                activeScoreCardTemplate = null;
                activeScoreCardReadOnly = false;
                if (candidateScoreCardForm) {
                    candidateScoreCardForm.reset();
                }
                if (candidateScoreCardSections) {
                    candidateScoreCardSections.innerHTML = '';
                }
                if (candidateScoreCardRangeList) {
                    candidateScoreCardRangeList.innerHTML = '';
                }
                if (candidateScoreCardTemplateTitle) {
                    candidateScoreCardTemplateTitle.textContent = '-';
                }
                if (candidateScoreCardUpdatedAt) {
                    candidateScoreCardUpdatedAt.textContent = t('wawancara_never_saved', 'Belum pernah disimpan');
                }
                if (candidateScoreCardFinalScore) {
                    candidateScoreCardFinalScore.textContent = '0.00';
                }
                if (candidateScoreCardRecommendation) {
                    candidateScoreCardRecommendation.textContent = t('wawancara_complete_scores', 'Lengkapi semua skor');
                }
                if (candidateScoreCardDecision) {
                    candidateScoreCardDecision.innerHTML = '<option value="">' + escapeHtml(t('wawancara_choose_decision', 'Pilih keputusan')) + '</option>';
                }
                if (candidateScoreCardDecisionNote) {
                    candidateScoreCardDecisionNote.value = '';
                    candidateScoreCardDecisionNote.required = false;
                }
                setScoreCardFormReadOnly(false, false, false);
            }

            function showScoreCardModal(buttonElement) {
                if (!buttonElement || !candidateScoreCardModal || !candidateScoreCardName || !candidateScoreCardForm) {
                    return;
                }

                const candidateBidang = (buttonElement.dataset.candidateBidang || '').trim();
                const candidateName = (buttonElement.dataset.candidateName || '').trim();
                const candidateCabang = (buttonElement.dataset.candidateCabang || '').trim();
                const isReadOnly = String(buttonElement.dataset.scorecardReadonly || '').trim() === '1';
                const isSubmitted = String(buttonElement.dataset.scorecardSubmitted || '').trim() === '1';
                const template = getScoreCardTemplateForBidang(candidateBidang);
                const submission = parseScoreCardSubmission(buttonElement);
                const hasSubmission = submission && typeof submission === 'object' && Object.keys(submission).length > 0;

                resetScoreCardModal();

                if (candidateScoreCardBidangInput) {
                    candidateScoreCardBidangInput.value = candidateBidang;
                }
                if (candidateScoreCardNamaInput) {
                    candidateScoreCardNamaInput.value = candidateName;
                }
                if (candidateScoreCardCabangInput) {
                    candidateScoreCardCabangInput.value = candidateCabang;
                }
                if (candidateScoreCardName) {
                    candidateScoreCardName.textContent = candidateName !== '' ? displayNameText(candidateName) : '-';
                }
                if (candidateScoreCardBidangName) {
                    candidateScoreCardBidangName.textContent = candidateBidang !== '' ? candidateBidang : '-';
                }
                if (candidateScoreCardTitle) {
                    candidateScoreCardTitle.textContent = isReadOnly ? t('wawancara_view_scorecard', 'Lihat Score Card') : (hasSubmission ? t('wawancara_edit_scorecard', 'Edit Score Card') : t('wawancara_input_scorecard', 'Input Score Card'));
                }

                if (!template || !Array.isArray(template.sections) || template.sections.length === 0) {
                    if (candidateScoreCardTemplateState) {
                        candidateScoreCardTemplateState.textContent = t('wawancara_scorecard_template_missing', 'Template score card belum tersedia untuk bidang ini.');
                        candidateScoreCardTemplateState.classList.remove('scorecard-hidden');
                        candidateScoreCardTemplateState.classList.add('error');
                    }
                    if (candidateScoreCardSubmit) {
                        candidateScoreCardSubmit.disabled = true;
                    }
                    candidateScoreCardModal.classList.add('open');
                    syncBodyScrollState();
                    return;
                }

                activeScoreCardTemplate = template;
                if (candidateScoreCardTemplateTitle) {
                    candidateScoreCardTemplateTitle.textContent = String(template.title || '-');
                }
                if (candidateScoreCardInterviewDate) {
                    candidateScoreCardInterviewDate.value = String(submission && submission.interview_date ? submission.interview_date : currentDateInputValue());
                }
                if (candidateScoreCardLocation) {
                    candidateScoreCardLocation.value = String(submission && submission.location ? submission.location : candidateCabang);
                }
                if (candidateScoreCardUpdatedAt) {
                    const updatedAt = String(submission && submission.updated_at ? submission.updated_at : '').trim();
                    candidateScoreCardUpdatedAt.textContent = updatedAt !== '' ? updatedAt : t('wawancara_never_saved', 'Belum pernah disimpan');
                }

                renderScoreCardDecisionOptions(template, String(submission && submission.interviewer_decision ? submission.interviewer_decision : ''));
                if (candidateScoreCardDecisionNote) {
                    candidateScoreCardDecisionNote.value = String(submission && submission.decision_note ? submission.decision_note : '');
                }
                renderScoreCardSections(template, submission);
                syncScoreCardDecisionNoteRequirement();
                updateScoreCardSummary();
                setScoreCardFormReadOnly(isReadOnly, isSubmitted, hasSubmission);

                candidateScoreCardModal.classList.add('open');
                syncBodyScrollState();
            }

            function closeScoreCardModal() {
                if (!candidateScoreCardModal) {
                    return;
                }
                candidateScoreCardModal.classList.remove('open');
                syncBodyScrollState();
            }

            if (candidateDocModal) {
                candidateDocModal.addEventListener('click', function (event) {
                    if (event.target === candidateDocModal) {
                        closeTemporaryCandidatePopup();
                    }
                });
            }

            document.addEventListener('keydown', function (event) {
                if (event.key === 'Escape' && candidateDocModal && candidateDocModal.classList.contains('open')) {
                    closeTemporaryCandidatePopup();
                }
                if (event.key === 'Escape' && candidateViewModal && candidateViewModal.classList.contains('open')) {
                    closeExistingKesediaanFormModal();
                }
                if (event.key === 'Escape' && candidateScoreCardModal && candidateScoreCardModal.classList.contains('open')) {
                    closeScoreCardModal();
                }
            });

            const candidateDocPanel = document.querySelector('#candidateDocModal .doc-modal-panel');
            if (candidateDocPanel) {
                candidateDocPanel.addEventListener('click', function (event) {
                    event.stopPropagation();
                });
            }

            if (candidateViewModal) {
                candidateViewModal.addEventListener('click', function (event) {
                    if (event.target === candidateViewModal) {
                        closeExistingKesediaanFormModal();
                    }
                });
            }

            const candidateViewPanel = document.querySelector('#candidateViewModal .doc-modal-panel');
            if (candidateViewPanel) {
                candidateViewPanel.addEventListener('click', function (event) {
                    event.stopPropagation();
                });
            }

            if (candidateScoreCardModal) {
                candidateScoreCardModal.addEventListener('click', function (event) {
                    if (event.target === candidateScoreCardModal) {
                        closeScoreCardModal();
                    }
                });
            }

            const candidateScoreCardPanel = document.querySelector('#candidateScoreCardModal .doc-modal-panel');
            if (candidateScoreCardPanel) {
                candidateScoreCardPanel.addEventListener('click', function (event) {
                    event.stopPropagation();
                });
            }

            if (candidateScoreCardForm) {
                candidateScoreCardForm.addEventListener('change', function (event) {
                    const target = event.target;
                    if (!target) {
                        return;
                    }

                    const targetName = String(target.name || '');
                    if (targetName.indexOf('scorecard_answers[') === 0) {
                        updateScoreCardSummary();
                    }
                    if (target === candidateScoreCardDecision) {
                        syncScoreCardDecisionNoteRequirement();
                    }
                });
            }

            if (candidateDocPihakSelect) {
                candidateDocPihakSelect.addEventListener('change', syncNamaPihakInputState);
            }

            function applyWawancaraProcessFilter() {
                if (!wawancaraProcessFilter) {
                    return;
                }

                const selectedFilter = String(wawancaraProcessFilter.value || 'all').trim();
                const candidateItems = document.querySelectorAll('.candidate-item[data-process-lanjut]');
                const wawancaraCards = document.querySelectorAll('.rekap-card[data-wawancara-card]');
                let visibleCandidateCount = 0;

                candidateItems.forEach(function (item) {
                    const isLanjut = item.getAttribute('data-process-lanjut') === '1';
                    const isScreening = item.getAttribute('data-process-screening') === '1';
                    const isScorecardSubmitted = item.getAttribute('data-process-scorecard-submitted') === '1';
                    let shouldShow = true;

                    if (selectedFilter === 'belum_lanjut') {
                        shouldShow = !isLanjut;
                    } else if (selectedFilter === 'lanjut') {
                        shouldShow = isLanjut && !isScreening;
                    } else if (selectedFilter === 'screening') {
                        shouldShow = isScreening && !isScorecardSubmitted;
                    } else if (selectedFilter === 'scorecard_submitted') {
                        shouldShow = isScorecardSubmitted;
                    }

                    item.style.display = shouldShow ? '' : 'none';
                    if (shouldShow) {
                        visibleCandidateCount++;
                    }
                });

                wawancaraCards.forEach(function (card) {
                    const cardItems = card.querySelectorAll('.candidate-item[data-process-lanjut]');
                    let hasVisibleItem = false;
                    cardItems.forEach(function (item) {
                        if (item.style.display !== 'none') {
                            hasVisibleItem = true;
                        }
                    });
                    card.style.display = hasVisibleItem ? '' : 'none';
                });

                if (wawancaraFilterEmpty) {
                    wawancaraFilterEmpty.style.display = visibleCandidateCount > 0 ? 'none' : 'block';
                }
            }

            if (wawancaraProcessFilter) {
                wawancaraProcessFilter.addEventListener('change', function () {
                    const selectedFilter = String(wawancaraProcessFilter.value || 'all').trim();
                    window.location.href = buildWawancaraFilterUrl(selectedFilter);
                });
                applyWawancaraProcessFilter();
            }

            function sanitizeSafeUrl(value) {
                const raw = String(value || '').trim();
                if (raw === '') {
                    return '';
                }
                const lower = raw.toLowerCase();
                if (lower.startsWith('javascript:') || lower.startsWith('data:')) {
                    return '';
                }
                return raw;
            }

            function escapeHtml(value) {
                return String(value)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/\"/g, '&quot;')
                    .replace(/'/g, '&#039;');
            }
        </script>
        <?php render_language_switcher(); ?>
        <?php render_language_script([
            'wawancara_title' => ['id' => 'Halaman Wawancara', 'en' => 'Interview Page'],
            'wawancara_back' => ['id' => 'Kembali ke Halaman Bidang', 'en' => 'Back to Positions'],
            'wawancara_filter_label' => ['id' => 'Filter proses kandidat', 'en' => 'Candidate process filter'],
            'filter_all' => ['id' => 'Semua', 'en' => 'All'],
            'filter_not_advanced' => ['id' => 'Belum Lanjut Proses', 'en' => 'Not advanced yet'],
            'filter_advanced' => ['id' => 'Lanjut Proses', 'en' => 'Advanced'],
            'filter_screening' => ['id' => 'Lolos Screening', 'en' => 'Passed Screening'],
            'filter_scorecard_submitted' => ['id' => 'Sudah Submit Score Card', 'en' => 'Score Card Submitted'],
            'wawancara_filter_empty' => ['id' => 'Tidak ada kandidat yang cocok dengan filter proses yang dipilih.', 'en' => 'No candidates match the selected process filter.'],
            'wawancara_empty_candidates' => ['id' => 'Belum ada kandidat pada bidang ini.', 'en' => 'There are no candidates for this position yet.'],
            'wawancara_votes_count' => ['id' => '{count} suara', 'en' => '{count} votes'],
            'wawancara_form_consent' => ['id' => 'Form Kesediaan', 'en' => 'Consent Form'],
            'wawancara_view_form' => ['id' => 'Lihat Form', 'en' => 'View Form'],
            'wawancara_submit_confirm' => ['id' => 'Setelah submit, score card tidak dapat diubah lagi. Lanjutkan?', 'en' => 'After submission, the score card cannot be changed anymore. Continue?'],
            'wawancara_consent_title' => ['id' => 'Form Kesediaan', 'en' => 'Consent Form'],
            'wawancara_candidate_doc_label' => ['id' => 'Kandidat: <strong id="candidateDocName">-</strong>', 'en' => 'Candidate: <strong id="candidateDocName">-</strong>'],
            'wawancara_candidate_view_label' => ['id' => 'Kandidat: <strong id="candidateViewName">-</strong>', 'en' => 'Candidate: <strong id="candidateViewName">-</strong>'],
            'wawancara_candidate_scorecard_label' => ['id' => 'Kandidat: <strong id="candidateScoreCardName">-</strong>', 'en' => 'Candidate: <strong id="candidateScoreCardName">-</strong>'],
            'wawancara_position_label' => ['id' => 'Bidang: <strong id="candidateScoreCardBidangName">-</strong>', 'en' => 'Position: <strong id="candidateScoreCardBidangName">-</strong>'],
            'wawancara_consent_party_label' => ['id' => 'Pihak yang Menyatakan Kesediaan', 'en' => 'Party Declaring Willingness'],
            'wawancara_select_party' => ['id' => 'Pilih pihak', 'en' => 'Choose party'],
            'wawancara_party_name_label' => ['id' => 'Nama Lengkap Pihak', 'en' => 'Party Full Name'],
            'wawancara_party_name_placeholder_select' => ['id' => 'Pilih pihak terlebih dahulu', 'en' => 'Choose a party first'],
            'wawancara_party_name_placeholder_input' => ['id' => 'Masukkan nama lengkap', 'en' => 'Enter full name'],
            'wawancara_meeting_photo_label' => ['id' => 'Bukti Foto Pertemuan', 'en' => 'Meeting Photo Evidence'],
            'wawancara_willingness_label' => ['id' => 'Kesediaan', 'en' => 'Willingness'],
            'wawancara_willing' => ['id' => 'Bersedia', 'en' => 'Willing'],
            'wawancara_not_willing' => ['id' => 'Tidak Bersedia', 'en' => 'Not Willing'],
            'wawancara_reason_optional' => ['id' => 'Alasan (Opsional)', 'en' => 'Reason (Optional)'],
            'wawancara_reason_placeholder' => ['id' => 'Tambahkan alasan jika diperlukan', 'en' => 'Add a reason if needed'],
            'wawancara_cancel' => ['id' => 'Batal', 'en' => 'Cancel'],
            'wawancara_save' => ['id' => 'Simpan', 'en' => 'Save'],
            'wawancara_view_consent_title' => ['id' => 'Lihat Form Kesediaan', 'en' => 'View Consent Form'],
            'wawancara_consent_recap_title' => ['id' => 'Rekap Pengisi Form', 'en' => 'Form Submitter Recap'],
            'wawancara_party' => ['id' => 'Pihak', 'en' => 'Party'],
            'wawancara_party_name' => ['id' => 'Nama Pihak', 'en' => 'Party Name'],
            'wawancara_reason' => ['id' => 'Alasan', 'en' => 'Reason'],
            'wawancara_document' => ['id' => 'Dokumen', 'en' => 'Document'],
            'wawancara_saved_at' => ['id' => 'Waktu Simpan', 'en' => 'Saved At'],
            'wawancara_view_empty' => ['id' => 'Belum ada form kesediaan yang disimpan untuk kandidat ini.', 'en' => 'There are no saved consent forms for this candidate yet.'],
            'wawancara_close' => ['id' => 'Tutup', 'en' => 'Close'],
            'wawancara_input_scorecard' => ['id' => 'Input Score Card', 'en' => 'Input Score Card'],
            'wawancara_score_scale_title' => ['id' => 'Skala Penilaian', 'en' => 'Scoring Scale'],
            'wawancara_scorecard_template_missing' => ['id' => 'Template score card belum tersedia untuk bidang ini.', 'en' => 'The score card template is not available for this position yet.'],
            'wawancara_interview_date' => ['id' => 'Tanggal Wawancara', 'en' => 'Interview Date'],
            'wawancara_location' => ['id' => 'Lokasi', 'en' => 'Location'],
            'wawancara_final_score' => ['id' => 'Total Score Akhir', 'en' => 'Final Total Score'],
            'wawancara_auto_result' => ['id' => 'Hasil Otomatis', 'en' => 'Automatic Result'],
            'wawancara_complete_scores' => ['id' => 'Lengkapi semua skor', 'en' => 'Complete all scores'],
            'wawancara_last_saved' => ['id' => 'Terakhir Disimpan', 'en' => 'Last Saved'],
            'wawancara_never_saved' => ['id' => 'Belum pernah disimpan', 'en' => 'Never saved'],
            'wawancara_score_criteria' => ['id' => 'Kriteria Total Score Akhir', 'en' => 'Final Total Score Criteria'],
            'wawancara_interviewer_decision' => ['id' => 'Keputusan Pewawancara', 'en' => 'Interviewer Decision'],
            'wawancara_decision_note' => ['id' => 'Catatan Keputusan', 'en' => 'Decision Note'],
            'wawancara_decision_note_placeholder' => ['id' => 'Isi catatan jika diperlukan', 'en' => 'Fill in a note if needed'],
            'wawancara_decision_note_required' => ['id' => 'Catatan wajib diisi untuk keputusan ini', 'en' => 'A note is required for this decision'],
            'wawancara_scorecard_note' => ['id' => 'Nilai bobot dan hasil akhir dihitung otomatis berdasarkan skor tiap pertanyaan.', 'en' => 'Weighted values and final results are calculated automatically based on each question score.'],
            'wawancara_save_scorecard' => ['id' => 'Simpan Score Card', 'en' => 'Save Score Card'],
            'wawancara_view' => ['id' => 'Lihat', 'en' => 'View'],
            'wawancara_no_consent_data' => ['id' => 'Belum ada data form kesediaan.', 'en' => 'There is no consent form data yet.'],
            'wawancara_choose_decision' => ['id' => 'Pilih keputusan', 'en' => 'Choose decision'],
            'wawancara_view_scorecard' => ['id' => 'Lihat Score Card', 'en' => 'View Score Card'],
            'wawancara_edit_scorecard' => ['id' => 'Edit Score Card', 'en' => 'Edit Score Card'],
            'wawancara_save_changes' => ['id' => 'Simpan Perubahan', 'en' => 'Save Changes'],
            'wawancara_scorecard_readonly_submitted' => ['id' => 'Score card sudah disubmit dan hanya dapat dilihat.', 'en' => 'This score card has been submitted and can only be viewed.'],
            'wawancara_scorecard_readonly' => ['id' => 'Score card hanya dapat dilihat.', 'en' => 'This score card can only be viewed.'],
        ]); ?>
    </body>
    </html>
    <?php
    exit;
}

if ($page === 'pemilihan') {
    $authUser = current_authenticated_user($usersForLogin);
    if ($authUser === null) {
        clear_auth_session();
        redirect_to_page('login');
    }
    if ($electionClosed) {
        redirect_to_page('bidang', ['info' => 'masa-berakhir']);
    }

    $username = (string)$authUser['username'];
    $asalCabangUser = (string)$authUser['asal_cabang'];
    sync_session_roles($authUser);

    $bidangList = personalize_bidang_list_for_cabang(load_bidang_data(), $asalCabangUser);
    $bidangTitle = trim((string)($_GET['bidang'] ?? ''));
    $bidangTitle = bidang_title_for_cabang($bidangTitle, $asalCabangUser);
    $selectedBidang = null;
    foreach ($bidangList as $bidangItem) {
        if ((string)($bidangItem['title'] ?? '') === $bidangTitle) {
            $selectedBidang = $bidangItem;
            break;
        }
    }

    if ($bidangTitle === '' || $selectedBidang === null) {
        redirect_to_page('bidang');
    }

    $selectedBidangTitle = (string)$selectedBidang['title'];
    $selectedBidangParts = bidang_title_parts($selectedBidangTitle);
    $selectedBidangMainTitle = (string)($selectedBidangParts['main'] ?? $selectedBidangTitle);
    if ($selectedBidangMainTitle === '') {
        $selectedBidangMainTitle = $selectedBidangTitle;
    }
    $selectedBidangCabangTitle = (string)($selectedBidangParts['cabang'] ?? '');
    $selectedBidangLabelModal = $selectedBidangMainTitle;
    if ($selectedBidangCabangTitle !== '') {
        $selectedBidangLabelModal .= ' ' . $selectedBidangCabangTitle;
    }
    if (latest_pemilihan_for($username, $selectedBidangTitle) !== null) {
        redirect_to_page('bidang', ['info' => 'sudah-vote', 'bidang' => $selectedBidangTitle]);
    }

    $kandidatList = [];
    foreach (load_kandidat_data() as $kandidat) {
        $kandidatCabang = trim((string)($kandidat['asal_cabang'] ?? ''));
        if ($kandidatCabang === $asalCabangUser && kandidat_bisa_dipilih_untuk_bidang($kandidat, $selectedBidangTitle)) {
            $kandidatList[] = $kandidat;
        }
    }

    $selectedKandidatId = substr(trim((string)($_POST['kandidat_id'] ?? '')), 0, 120);
    $selectedKandidatSearch = substr(trim((string)($_POST['kandidat_search'] ?? '')), 0, 180);
    $saveError = '';
    $pemilihanCsrfToken = csrf_token();

    if ($method === 'POST') {
        $postedCsrfToken = trim((string)($_POST['csrf_token'] ?? ''));
        if (!is_valid_csrf_token($postedCsrfToken)) {
            $saveError = 'Sesi tidak valid. Muat ulang halaman lalu coba lagi.';
        } elseif ($electionClosed) {
            $saveError = 'Masa pemilihan sudah berakhir pada ' . ELECTION_DEADLINE_LABEL . '.';
        } elseif ($kandidatList === []) {
            $saveError = 'Tidak ada kandidat yang tersedia untuk bidang ini di cabang Anda.';
        }

        if ($saveError === '' && $selectedKandidatId === '' && $selectedKandidatSearch !== '') {
            $foundByLabel = find_kandidat_by_option_label($kandidatList, $selectedKandidatSearch);
            if ($foundByLabel !== null) {
                $selectedKandidatId = (string)$foundByLabel['id'];
            }
        }

        if ($saveError === '' && $selectedKandidatId === '') {
            $saveError = 'Silakan pilih kandidat terlebih dahulu.';
        }

        if ($saveError === '') {
            $selectedKandidat = find_kandidat_by_id($kandidatList, $selectedKandidatId);
            if ($selectedKandidat === null) {
                $saveError = 'Kandidat yang dipilih tidak valid, tidak tersedia untuk bidang ini, atau bukan dari cabang Anda.';
            } else {
                $selectedKandidatSearch = kandidat_option_label($selectedKandidat);
                $detail = [
                    'id' => generate_id('pemilihan_'),
                    'username' => $username,
                    'asal_cabang_user' => $asalCabangUser,
                    'bidang' => $selectedBidangTitle,
                    'kandidat' => [
                        'id' => (string)$selectedKandidat['id'],
                        'nama_lengkap' => (string)$selectedKandidat['nama_lengkap'],
                        'asal_cabang' => (string)$selectedKandidat['asal_cabang'],
                    ],
                    'waktu_pemilihan' => date('Y-m-d H:i:s', current_time()),
                ];

                if (save_pemilihan_detail($detail)) {
                    redirect_to_page('bidang', ['info' => 'vote-berhasil', 'bidang' => $selectedBidangTitle]);
                } else {
                    $saveError = 'Bidang ini sudah pernah Anda vote atau data gagal disimpan.';
                }
            }
        }
    }
    ?>
    <!doctype html>
    <html lang="id">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>PeMa REC Indonesia</title>
        <link rel="icon" type="image/png" href="logo.png">
        <style>
            * { box-sizing: border-box; }
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #f3f4f6;
                color: #111827;
                min-height: 100vh;
                min-height: 100dvh;
                display: grid;
                place-items: center;
                padding: 20px;
            }
            .card {
                width: 100%;
                max-width: 560px;
                background: #fff;
                border-radius: 14px;
                padding: 24px;
                border: 1px solid #e5e7eb;
                box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
                text-align: center;
            }
            h1 {
                margin: 0 0 16px;
                font-size: 28px;
            }
            .title-cabang {
                margin: -8px 0 14px;
                font-size: 14px;
                font-weight: 700;
                color: #475569;
                text-align: center;
            }
            .desc {
                margin: 0 0 16px;
                line-height: 1.6;
                color: #4b5563;
                text-align: center;
            }
            .form-box {
                margin-top: 18px;
                padding: 16px;
                border: 1px solid #e5e7eb;
                border-radius: 10px;
                background: #f9fafb;
                text-align: left;
            }
            .form-box label {
                display: block;
                margin-bottom: 6px;
                font-size: 14px;
                color: #111827;
                font-weight: 600;
            }
            .kandidat-combobox {
                position: relative;
                margin-bottom: 12px;
            }
            .input-kandidat {
                width: 100%;
                border: 1px solid #d1d5db;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
                margin-bottom: 0;
                background: #fff;
                padding-right: 48px;
            }
            .name-display-uppercase {
                text-transform: uppercase;
            }
            .kandidat-toggle {
                position: absolute;
                top: 50%;
                right: 8px;
                transform: translateY(-50%);
                width: 34px;
                height: 34px;
                border: 0;
                border-radius: 8px;
                background: transparent;
                color: #111827;
                cursor: pointer;
                display: inline-flex;
                align-items: center;
                justify-content: center;
            }
            .kandidat-toggle:hover {
                background: #f3f4f6;
            }
            .kandidat-toggle:focus-visible {
                outline: 3px solid #93c5fd;
                outline-offset: 2px;
            }
            .kandidat-toggle[disabled] {
                cursor: not-allowed;
                color: #9ca3af;
            }
            .kandidat-toggle-icon {
                display: inline-block;
                font-size: 12px;
                line-height: 1;
                transition: transform 0.18s ease;
            }
            .kandidat-combobox.open .kandidat-toggle-icon {
                transform: rotate(180deg);
            }
            .kandidat-dropdown {
                position: absolute;
                left: 0;
                right: 0;
                top: calc(100% + 8px);
                z-index: 30;
                border: 1px solid #d1d5db;
                border-radius: 10px;
                background: #fff;
                box-shadow: 0 18px 36px rgba(15, 23, 42, 0.16);
                overflow: auto;
                overscroll-behavior: contain;
                -webkit-overflow-scrolling: touch;
                max-height: 240px;
            }
            .kandidat-dropdown[hidden] {
                display: none;
            }
            .kandidat-combobox.drop-up .kandidat-dropdown {
                top: auto;
                bottom: calc(100% + 8px);
            }
            .kandidat-option,
            .kandidat-empty {
                width: 100%;
                padding: 12px 14px;
                font-size: 14px;
                line-height: 1.5;
                text-align: left;
            }
            .kandidat-option {
                border: 0;
                border-bottom: 1px solid #e5e7eb;
                background: #fff;
                color: #111827;
                cursor: pointer;
            }
            .kandidat-option:last-of-type {
                border-bottom: 0;
            }
            .kandidat-option:hover,
            .kandidat-option.is-active {
                background: #eff6ff;
                color: #1d4ed8;
            }
            .kandidat-option[hidden] {
                display: none;
            }
            .kandidat-empty {
                color: #6b7280;
            }
            .btn-submit {
                width: 100%;
                border: 0;
                background: #2563eb;
                color: #fff;
                padding: 10px 12px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
            }
            .btn-submit:disabled {
                background: #94a3b8;
                cursor: not-allowed;
            }
            .alert {
                margin-top: 14px;
                padding: 10px;
                border-radius: 8px;
                font-size: 14px;
                text-align: left;
            }
            .alert.success {
                background: #dcfce7;
                color: #166534;
            }
            .alert.error {
                background: #fee2e2;
                color: #b91c1c;
            }
            .vote-note {
                margin-top: 10px;
                padding: 10px 12px;
                border-radius: 8px;
                background: #fffbeb;
                color: #92400e;
                border: 1px solid #fde68a;
                font-size: 13px;
                line-height: 1.5;
            }
            body.modal-open {
                overflow: hidden;
            }
            .confirm-modal {
                position: fixed;
                inset: 0;
                z-index: 50;
                display: grid;
                place-items: center;
                padding: 20px;
                background: rgba(15, 23, 42, 0.55);
            }
            .confirm-modal[hidden] {
                display: none;
            }
            .confirm-dialog {
                width: 100%;
                max-width: 420px;
                background: #fff;
                border-radius: 12px;
                border: 1px solid #e5e7eb;
                box-shadow: 0 24px 60px rgba(15, 23, 42, 0.3);
                padding: 18px;
                text-align: left;
                animation: popup-in 0.18s ease-out;
            }
            .confirm-title {
                margin: 0 0 8px;
                font-size: 20px;
                color: #111827;
            }
            .confirm-text {
                margin: 0 0 14px;
                color: #374151;
                line-height: 1.5;
            }
            .confirm-selected {
                font-weight: 700;
                color: #111827;
            }
            .confirm-bidang {
                font-weight: 700;
                color: #000000;
            }
            .confirm-actions {
                display: flex;
                gap: 10px;
                justify-content: flex-end;
            }
            .confirm-btn {
                border: 0;
                border-radius: 8px;
                padding: 9px 14px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
            }
            .confirm-btn.cancel {
                background: #e5e7eb;
                color: #111827;
            }
            .confirm-btn.ok {
                background: #2563eb;
                color: #fff;
            }
            .confirm-btn.cancel:hover {
                background: #d1d5db;
            }
            .confirm-btn.ok:hover {
                background: #1d4ed8;
            }
            @keyframes popup-in {
                from {
                    opacity: 0;
                    transform: translateY(10px) scale(0.98);
                }
                to {
                    opacity: 1;
                    transform: translateY(0) scale(1);
                }
            }
            .actions {
                margin-top: 14px;
                display: flex;
                justify-content: center;
            }
            .btn-back {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                text-decoration: none;
                background: #fff;
                color: #1f2937;
                padding: 10px 14px;
                border-radius: 10px;
                border: 1px solid #d1d5db;
                font-size: 14px;
                font-weight: 600;
                transition: transform 0.15s ease, border-color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease;
            }
            .btn-back:hover {
                background: #f9fafb;
                border-color: #9ca3af;
                transform: translateY(-1px);
                box-shadow: 0 8px 16px rgba(15, 23, 42, 0.12);
            }
            .btn-back:focus-visible {
                outline: 3px solid #93c5fd;
                outline-offset: 2px;
            }
            .btn-back:active {
                transform: translateY(0);
            }
            .btn-back-arrow {
                display: inline-block;
                font-size: 16px;
                line-height: 1;
            }
            @media (max-width: 640px) {
                body {
                    display: block;
                    padding: 14px;
                }
                .card {
                    margin: 0 auto;
                    padding: 20px 16px;
                }
            }
        </style>
        <?php render_language_switcher_head(); ?>
    </head>
    <body>
        <section class="card">
            <h1 data-lang-text-id="<?= h($selectedBidangMainTitle) ?>" data-lang-text-en="<?= h(bidang_translate_main_title($selectedBidangMainTitle, 'en')) ?>"><?= h($selectedBidangMainTitle) ?></h1>
            <?php if ($selectedBidangCabangTitle !== ''): ?>
                <p class="title-cabang"><?= h($selectedBidangCabangTitle) ?></p>
            <?php endif; ?>
            <p class="desc" data-lang-text-id="<?= h(bidang_display_description($selectedBidang, 'id')) ?>" data-lang-text-en="<?= h(bidang_display_description($selectedBidang, 'en')) ?>"><?= h(bidang_display_description($selectedBidang, 'id')) ?></p>

            <form class="form-box" method="post" action="<?= h(app_index_url(['page' => 'pemilihan', 'bidang' => (string)$selectedBidang['title']])) ?>">
                <input type="hidden" name="csrf_token" value="<?= h($pemilihanCsrfToken) ?>">
                <label for="kandidat_search" data-i18n="pemilihan_candidate_label">Cari & pilih kandidat majelis</label>
                <div class="kandidat-combobox" id="kandidat_combobox">
                    <input
                        class="input-kandidat name-display-uppercase"
                        id="kandidat_search"
                        name="kandidat_search"
                        type="text"
                        placeholder="Ketik nama kandidat..."
                        data-i18n-placeholder="pemilihan_candidate_placeholder"
                        autocomplete="off"
                        inputmode="search"
                        role="combobox"
                        aria-autocomplete="list"
                        aria-expanded="false"
                        aria-controls="kandidat_dropdown"
                        value="<?= h($selectedKandidatSearch) ?>"
                        <?= $kandidatList === [] ? 'disabled' : '' ?>
                        required
                    >
                    <button
                        class="kandidat-toggle"
                        id="kandidat_toggle"
                        type="button"
                        aria-label="Tampilkan daftar kandidat"
                        data-i18n-aria-label="pemilihan_toggle_label"
                        aria-haspopup="listbox"
                        aria-controls="kandidat_dropdown"
                        aria-expanded="false"
                        <?= $kandidatList === [] ? 'disabled' : '' ?>
                    >
                        <span class="kandidat-toggle-icon" aria-hidden="true">&#9662;</span>
                    </button>
                    <div class="kandidat-dropdown" id="kandidat_dropdown" role="listbox" hidden>
                        <?php foreach ($kandidatList as $index => $kandidat): ?>
                            <?php
                            $kandidatId = (string)$kandidat['id'];
                            $optionLabel = kandidat_option_label($kandidat);
                            ?>
                            <button
                                class="kandidat-option"
                                id="kandidat_option_<?= $index + 1 ?>"
                                type="button"
                                role="option"
                                tabindex="-1"
                                data-id="<?= h($kandidatId) ?>"
                                data-label="<?= h($optionLabel) ?>"
                            ><?= h($optionLabel) ?></button>
                        <?php endforeach; ?>
                        <div class="kandidat-empty" id="kandidat_empty" hidden data-i18n="pemilihan_no_candidate_match">Tidak ada kandidat yang cocok.</div>
                    </div>
                </div>
                <input type="hidden" id="kandidat_id" name="kandidat_id" value="<?= h($selectedKandidatId) ?>">

                <button class="btn-submit" type="submit" <?= $kandidatList === [] ? 'disabled' : '' ?> data-i18n="pemilihan_submit">Simpan Pemilihan</button>
                <p class="vote-note" data-i18n="pemilihan_vote_note">Perhatian: setelah vote disimpan, pilihan kandidat pada bidang ini tidak dapat diubah.</p>
            </form>

            <?php if ($saveError !== ''): ?>
                <div class="alert error"><?= h($saveError) ?></div>
            <?php endif; ?>

            <div class="actions">
                <a class="btn-back" href="<?= h(app_index_url(['page' => 'bidang'])) ?>">
                    <span class="btn-back-arrow" aria-hidden="true">&larr;</span>
                    <span data-i18n="pemilihan_back">Kembali ke Bidang</span>
                </a>
            </div>
        </section>
        <div class="confirm-modal" id="confirm-modal" hidden>
            <div class="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
                <h2 class="confirm-title" id="confirm-title" data-i18n="pemilihan_confirm_title">Konfirmasi Pemilihan</h2>
                <p class="confirm-text">
                    <span data-i18n="pemilihan_confirm_prefix">Anda akan memilih</span>
                    <span class="confirm-selected" id="confirm-selected">-</span>
                    <span data-i18n="pemilihan_confirm_middle">sebagai Kandidat</span>
                    <span class="confirm-bidang" data-lang-text-id="<?= h($selectedBidangLabelModal) ?>" data-lang-text-en="<?= h(bidang_display_title($selectedBidangTitle, 'en')) ?>"><?= h($selectedBidangLabelModal) ?></span>.
                    <span data-i18n="pemilihan_confirm_suffix">Setelah disimpan, pilihan pada bidang ini tidak dapat diubah.</span>
                </p>
                <div class="confirm-actions">
                    <button class="confirm-btn cancel" type="button" id="confirm-cancel" data-i18n="pemilihan_confirm_cancel">Batal</button>
                    <button class="confirm-btn ok" type="button" id="confirm-ok" data-i18n="pemilihan_confirm_ok">Ya, Simpan</button>
                </div>
            </div>
        </div>

        <?php render_language_switcher(); ?>

        <script>
            (function () {
                const kandidatInput = document.getElementById('kandidat_search');
                const kandidatIdInput = document.getElementById('kandidat_id');
                const kandidatCombobox = document.getElementById('kandidat_combobox');
                const kandidatDropdown = document.getElementById('kandidat_dropdown');
                const kandidatToggle = document.getElementById('kandidat_toggle');
                const kandidatEmpty = document.getElementById('kandidat_empty');
                const form = document.querySelector('.form-box');
                const confirmModal = document.getElementById('confirm-modal');
                const confirmSelected = document.getElementById('confirm-selected');
                const confirmCancel = document.getElementById('confirm-cancel');
                const confirmOk = document.getElementById('confirm-ok');
                if (!kandidatInput || !kandidatIdInput || !kandidatCombobox || !kandidatDropdown || !kandidatToggle || !kandidatEmpty || !form || !confirmModal || !confirmSelected || !confirmCancel || !confirmOk) {
                    return;
                }

                const optionMap = new Map();
                const optionItems = Array.from(kandidatDropdown.querySelectorAll('.kandidat-option')).map(function (button) {
                    const label = (button.dataset.label || button.textContent || '').trim();
                    const id = (button.dataset.id || '').trim();
                    const labelKey = label.toLowerCase();
                    if (labelKey !== '' && id !== '') {
                        optionMap.set(labelKey, id);
                    }
                    return {
                        button: button,
                        label: label,
                        labelKey: labelKey,
                        id: id,
                    };
                });
                const optionItemMap = new Map(optionItems.map(function (item) {
                    return [item.button, item];
                }));
                let submitConfirmed = false;
                let previousFocus = null;
                let filteredItems = optionItems.slice();
                let activeIndex = -1;

                function displayNameText(value) {
                    const raw = String(value || '').trim();
                    if (raw === '') {
                        return '';
                    }
                    return typeof raw.toLocaleUpperCase === 'function'
                        ? raw.toLocaleUpperCase('id-ID')
                        : raw.toUpperCase();
                }

                function syncSelectedKandidat() {
                    const key = kandidatInput.value.trim().toLowerCase();
                    const matchedId = optionMap.get(key) || '';
                    kandidatIdInput.value = matchedId;
                    kandidatInput.setCustomValidity('');
                }

                function setComboboxExpanded(isExpanded) {
                    kandidatCombobox.classList.toggle('open', isExpanded);
                    kandidatInput.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
                    kandidatToggle.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
                    kandidatDropdown.hidden = !isExpanded;
                    if (!isExpanded) {
                        kandidatCombobox.classList.remove('drop-up');
                        kandidatDropdown.style.maxHeight = '';
                        kandidatInput.removeAttribute('aria-activedescendant');
                    }
                }

                function clearActiveOption() {
                    activeIndex = -1;
                    kandidatInput.removeAttribute('aria-activedescendant');
                    optionItems.forEach(function (item) {
                        item.button.classList.remove('is-active');
                        item.button.setAttribute('aria-selected', 'false');
                    });
                }

                function updateActiveOption(nextIndex) {
                    clearActiveOption();
                    if (nextIndex < 0 || nextIndex >= filteredItems.length) {
                        return;
                    }
                    activeIndex = nextIndex;
                    const activeItem = filteredItems[activeIndex];
                    activeItem.button.classList.add('is-active');
                    activeItem.button.setAttribute('aria-selected', 'true');
                    kandidatInput.setAttribute('aria-activedescendant', activeItem.button.id);
                    activeItem.button.scrollIntoView({ block: 'nearest' });
                }

                function updateDropdownLayout() {
                    if (kandidatDropdown.hidden) {
                        return;
                    }
                    const viewport = window.visualViewport;
                    const inputRect = kandidatInput.getBoundingClientRect();
                    const viewportTop = viewport ? viewport.offsetTop : 0;
                    const viewportBottom = viewport ? (viewport.offsetTop + viewport.height) : window.innerHeight;
                    const rawSpaceBelow = viewportBottom - inputRect.bottom - 12;
                    const rawSpaceAbove = inputRect.top - viewportTop - 12;
                    const openUp = rawSpaceBelow < 180 && rawSpaceAbove > rawSpaceBelow;
                    const availableSpace = openUp ? rawSpaceAbove : rawSpaceBelow;
                    kandidatCombobox.classList.toggle('drop-up', openUp);
                    kandidatDropdown.style.maxHeight = Math.max(96, Math.min(280, Math.floor(availableSpace))) + 'px';
                }

                function filterOptions() {
                    const query = kandidatInput.value.trim().toLowerCase();
                    filteredItems = [];
                    optionItems.forEach(function (item) {
                        const matches = query === '' || item.labelKey.indexOf(query) !== -1;
                        item.button.hidden = !matches;
                        item.button.classList.remove('is-active');
                        item.button.setAttribute('aria-selected', 'false');
                        if (matches) {
                            filteredItems.push(item);
                        }
                    });
                    kandidatEmpty.hidden = filteredItems.length !== 0;
                    kandidatDropdown.scrollTop = 0;
                    clearActiveOption();
                }

                function openDropdown() {
                    if (optionItems.length === 0) {
                        return;
                    }
                    filterOptions();
                    setComboboxExpanded(true);
                    updateDropdownLayout();
                }

                function closeDropdown() {
                    setComboboxExpanded(false);
                    clearActiveOption();
                }

                function selectKandidat(item) {
                    if (!item) {
                        return;
                    }
                    kandidatInput.value = item.label;
                    kandidatIdInput.value = item.id;
                    kandidatInput.setCustomValidity('');
                    closeDropdown();
                }

                function openConfirmModal(kandidatTerpilih) {
                    previousFocus = document.activeElement;
                    confirmSelected.textContent = displayNameText(kandidatTerpilih);
                    confirmModal.hidden = false;
                    document.body.classList.add('modal-open');
                    confirmOk.focus();
                }

                function closeConfirmModal() {
                    confirmModal.hidden = true;
                    document.body.classList.remove('modal-open');
                    if (previousFocus && typeof previousFocus.focus === 'function') {
                        previousFocus.focus();
                    }
                }

                kandidatInput.addEventListener('focus', function () {
                    openDropdown();
                    if (window.matchMedia('(max-width: 640px)').matches) {
                        window.setTimeout(function () {
                            kandidatInput.scrollIntoView({ block: 'nearest', inline: 'nearest' });
                            updateDropdownLayout();
                        }, 120);
                    }
                });

                kandidatInput.addEventListener('click', openDropdown);

                kandidatInput.addEventListener('input', function () {
                    submitConfirmed = false;
                    syncSelectedKandidat();
                    openDropdown();
                });

                kandidatInput.addEventListener('change', syncSelectedKandidat);

                kandidatInput.addEventListener('keydown', function (event) {
                    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                        if (kandidatDropdown.hidden) {
                            openDropdown();
                        }
                        if (filteredItems.length === 0) {
                            return;
                        }
                        event.preventDefault();
                        let nextIndex = activeIndex;
                        if (event.key === 'ArrowDown') {
                            nextIndex = activeIndex < 0 ? 0 : activeIndex + 1;
                            if (nextIndex >= filteredItems.length) {
                                nextIndex = 0;
                            }
                        } else {
                            nextIndex = activeIndex < 0 ? filteredItems.length - 1 : activeIndex - 1;
                            if (nextIndex < 0) {
                                nextIndex = filteredItems.length - 1;
                            }
                        }
                        updateActiveOption(nextIndex);
                        return;
                    }
                    if (event.key === 'Enter' && !kandidatDropdown.hidden && activeIndex >= 0) {
                        event.preventDefault();
                        selectKandidat(filteredItems[activeIndex]);
                        return;
                    }
                    if (event.key === 'Escape' && !kandidatDropdown.hidden) {
                        event.preventDefault();
                        closeDropdown();
                    }
                });

                kandidatToggle.addEventListener('click', function () {
                    if (kandidatDropdown.hidden) {
                        openDropdown();
                        kandidatInput.focus();
                    } else {
                        closeDropdown();
                    }
                });

                kandidatDropdown.addEventListener('mousedown', function (event) {
                    event.preventDefault();
                });

                kandidatDropdown.addEventListener('click', function (event) {
                    const optionButton = event.target.closest('.kandidat-option');
                    if (!optionButton) {
                        return;
                    }
                    selectKandidat(optionItemMap.get(optionButton) || null);
                });

                form.addEventListener('submit', function (event) {
                    syncSelectedKandidat();
                    if (!kandidatIdInput.value) {
                        event.preventDefault();
                        kandidatInput.setCustomValidity(window.majelisLang && typeof window.majelisLang.t === 'function'
                            ? window.majelisLang.t('pemilihan_invalid_candidate', {}, 'Pilih kandidat dari daftar yang tersedia.')
                            : 'Pilih kandidat dari daftar yang tersedia.');
                        kandidatInput.reportValidity();
                        return;
                    }

                    if (!submitConfirmed) {
                        event.preventDefault();
                        const kandidatTerpilih = kandidatInput.value.trim();
                        const kandidatNama = kandidatTerpilih.split(' - ')[0].trim();
                        openConfirmModal(kandidatNama || kandidatTerpilih);
                    }
                });

                document.addEventListener('click', function (event) {
                    if (!kandidatCombobox.contains(event.target)) {
                        closeDropdown();
                    }
                });

                document.addEventListener('focusin', function (event) {
                    if (!kandidatCombobox.contains(event.target)) {
                        closeDropdown();
                    }
                });

                confirmCancel.addEventListener('click', function () {
                    closeConfirmModal();
                });

                confirmOk.addEventListener('click', function () {
                    submitConfirmed = true;
                    closeConfirmModal();
                    if (typeof form.requestSubmit === 'function') {
                        form.requestSubmit();
                    } else {
                        form.submit();
                    }
                });

                confirmModal.addEventListener('click', function (event) {
                    if (event.target === confirmModal) {
                        closeConfirmModal();
                    }
                });

                document.addEventListener('keydown', function (event) {
                    if (event.key === 'Escape' && !kandidatDropdown.hidden) {
                        closeDropdown();
                    }
                    if (event.key === 'Escape' && !confirmModal.hidden) {
                        closeConfirmModal();
                    }
                });

                window.addEventListener('resize', updateDropdownLayout);
                window.addEventListener('scroll', updateDropdownLayout, true);
                if (window.visualViewport) {
                    window.visualViewport.addEventListener('resize', updateDropdownLayout);
                    window.visualViewport.addEventListener('scroll', updateDropdownLayout);
                }

                syncSelectedKandidat();
                filterOptions();
            })();
        </script>
        <?php render_language_script([
            'pemilihan_candidate_label' => ['id' => 'Cari & pilih kandidat majelis', 'en' => 'Search & choose an assembly candidate'],
            'pemilihan_candidate_placeholder' => ['id' => 'Ketik nama kandidat...', 'en' => 'Type a candidate name...'],
            'pemilihan_toggle_label' => ['id' => 'Tampilkan daftar kandidat', 'en' => 'Show candidate list'],
            'pemilihan_no_candidate_match' => ['id' => 'Tidak ada kandidat yang cocok.', 'en' => 'No matching candidates found.'],
            'pemilihan_submit' => ['id' => 'Simpan Pemilihan', 'en' => 'Save Vote'],
            'pemilihan_vote_note' => ['id' => 'Perhatian: setelah vote disimpan, pilihan kandidat pada bidang ini tidak dapat diubah.', 'en' => 'Note: once the vote is saved, the candidate choice for this position cannot be changed.'],
            'pemilihan_back' => ['id' => 'Kembali ke Bidang', 'en' => 'Back to Positions'],
            'pemilihan_confirm_title' => ['id' => 'Konfirmasi Pemilihan', 'en' => 'Confirm Vote'],
            'pemilihan_confirm_prefix' => ['id' => 'Anda akan memilih', 'en' => 'You are about to choose'],
            'pemilihan_confirm_middle' => ['id' => 'sebagai Kandidat', 'en' => 'as the candidate for'],
            'pemilihan_confirm_suffix' => ['id' => 'Setelah disimpan, pilihan pada bidang ini tidak dapat diubah.', 'en' => 'Once saved, the choice for this position cannot be changed.'],
            'pemilihan_confirm_cancel' => ['id' => 'Batal', 'en' => 'Cancel'],
            'pemilihan_confirm_ok' => ['id' => 'Ya, Simpan', 'en' => 'Yes, Save'],
            'pemilihan_invalid_candidate' => ['id' => 'Pilih kandidat dari daftar yang tersedia.', 'en' => 'Choose a candidate from the available list.'],
        ]); ?>
    </body>
    </html>
    <?php
    exit;
}

if ($page !== 'login') {
    http_response_code(404);
    echo '404 - Halaman tidak ditemukan.';
    exit;
}
?>
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PeMa REC Indonesia</title>
    <link rel="icon" type="image/png" href="logo.png">
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f3f4f6;
            color: #111827;
            min-height: 100vh;
            display: grid;
            place-items: center;
            padding: 20px 14px;
        }
        .card {
            width: 100%;
            max-width: 380px;
            background: #fff;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
        }
        h1 {
            margin: 0 0 16px;
            font-size: 24px;
        }
        .error {
            margin-bottom: 12px;
            padding: 10px;
            border-radius: 8px;
            background: #fee2e2;
            color: #b91c1c;
            font-size: 14px;
        }
        .notice {
            margin-bottom: 12px;
            padding: 10px;
            border-radius: 8px;
            font-size: 13px;
            line-height: 1.5;
        }
        .notice.info {
            background: #eff6ff;
            color: #1e3a8a;
            border: 1px solid #bfdbfe;
        }
        .notice.warning {
            background: #fee2e2;
            color: #b91c1c;
            border: 1px solid #fecaca;
        }
        label {
            display: block;
            margin-bottom: 6px;
            font-size: 14px;
        }
        input, select {
            width: 100%;
            padding: 10px;
            margin-bottom: 12px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            background: #fff;
        }
        button {
            width: 100%;
            border: 0;
            background: #111827;
            color: #fff;
            padding: 11px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
        }
        .hint {
            margin-top: 12px;
            font-size: 12px;
            color: #4b5563;
        }
        code {
            background: #f3f4f6;
            padding: 2px 5px;
            border-radius: 5px;
        }
        body.modal-open {
            overflow: hidden;
        }
        .welcome-modal {
            position: fixed;
            inset: 0;
            z-index: 60;
            display: grid;
            place-items: center;
            padding: 18px;
            background: rgba(15, 23, 42, 0.55);
        }
        .welcome-modal[hidden] {
            display: none;
        }
        .welcome-dialog {
            position: relative;
            width: 100%;
            max-width: 560px;
            background: #fff;
            border: 1px solid #d1d5db;
            border-radius: 14px;
            box-shadow: 0 24px 60px rgba(15, 23, 42, 0.26);
            padding: 20px;
            text-align: left;
        }
        .welcome-close {
            position: absolute;
            top: 10px;
            right: 10px;
            width: 34px;
            height: 34px;
            padding: 0;
            border: 2px solid #111827;
            border-radius: 999px;
            background: #e5e7eb;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }
        .welcome-close::before,
        .welcome-close::after {
            content: "";
            position: absolute;
            top: 50%;
            left: 50%;
            width: 14px;
            height: 2px;
            background: #111827;
            border-radius: 999px;
            transform-origin: center;
        }
        .welcome-close::before {
            transform: translate(-50%, -50%) rotate(45deg);
        }
        .welcome-close::after {
            transform: translate(-50%, -50%) rotate(-45deg);
        }
        .welcome-close:hover {
            background: #d1d5db;
        }
        .welcome-close:focus-visible {
            outline: 3px solid #93c5fd;
            outline-offset: 2px;
        }
        .welcome-title {
            margin: 0 0 10px;
            font-size: 24px;
            color: #111827;
            line-height: 1.25;
        }
        .welcome-text {
            margin: 0;
            color: #374151;
            line-height: 1.65;
            font-size: 15px;
        }
    </style>
    <?php render_language_switcher_head(); ?>
</head>
<body>
    <section class="card">
        <h1 data-i18n="login_title">Login</h1>
        <?php if ($error !== ''): ?>
            <div class="error"><?= h($error) ?></div>
        <?php endif; ?>
        <div
            class="notice info"
            data-i18n-html="login_deadline_notice"
            data-i18n-vars="<?= h((string)json_encode(['date' => ELECTION_DEADLINE_LABEL], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"
        >
            Deadline pemilihan: <strong><?= h(ELECTION_DEADLINE_LABEL) ?></strong>.
        </div>
        <?php if ($electionClosed): ?>
            <div
                class="notice warning"
                data-i18n-html="login_deadline_closed"
                data-i18n-vars="<?= h((string)json_encode(['date' => ELECTION_DEADLINE_LABEL], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"
            >
                Masa pemilihan sudah berakhir pada <strong><?= h(ELECTION_DEADLINE_LABEL) ?></strong>.
            </div>
        <?php endif; ?>

        <form method="post" action="<?= h(app_index_url(['page' => 'login'])) ?>">
            <input type="hidden" name="csrf_token" value="<?= h($csrfFormToken) ?>">
            <label for="username" data-i18n="login_username_label">Username</label>
            <input
                id="username"
                name="username"
                type="text"
                placeholder="masukkan username akun"
                data-i18n-placeholder="login_username_placeholder"
                value="<?= h($loginSelectedUsername) ?>"
                autocomplete="username"
                required
                autofocus
            >

            <label for="password" data-i18n="login_password_label">Password</label>
            <input id="password" name="password" type="password" placeholder="masukkan password akun" data-i18n-placeholder="login_password_placeholder" autocomplete="current-password" required>

            <button type="submit" data-i18n="login_submit">Masuk</button>
        </form>
    </section>

    <div class="welcome-modal" id="welcome-modal" hidden>
        <div class="welcome-dialog" role="dialog" aria-modal="true" aria-labelledby="welcome-title">
            <button class="welcome-close" type="button" id="welcome-close" aria-label="Tutup popup" data-i18n-aria-label="welcome_close_label"></button>
            <h2 class="welcome-title" id="welcome-title" data-i18n-html="welcome_title"><strong>Shalom REC Indonesia!</strong></h2>
            <p class="welcome-text" data-i18n="welcome_text">
                Terima kasih atas partisipasi Anda dalam pemilihan kandidat Majelis REC Indonesia periode 2026-2029.
                Suara Anda adalah wujud kasih yang nyata bagi pembangunan Tubuh Kristus. Mari nyatakan kehendak-Nya
                melalui pilihan Anda hari ini. Selamat memilih dengan sukacita!
            </p>
        </div>
    </div>

    <?php render_language_switcher(); ?>

    <script>
        (function () {
            const SESSION_KEY = 'majelis_welcome_seen';
            const modal = document.getElementById('welcome-modal');
            const closeButton = document.getElementById('welcome-close');
            if (!modal || !closeButton) {
                return;
            }

            let shouldShow = true;
            try {
                shouldShow = sessionStorage.getItem(SESSION_KEY) !== '1';
            } catch (error) {
                shouldShow = true;
            }
            if (!shouldShow) {
                return;
            }

            function closeModal() {
                modal.hidden = true;
                document.body.classList.remove('modal-open');
                try {
                    sessionStorage.setItem(SESSION_KEY, '1');
                } catch (error) {
                    // Ignore storage errors; popup will show again.
                }
            }

            modal.hidden = false;
            document.body.classList.add('modal-open');
            closeButton.focus();

            closeButton.addEventListener('click', closeModal);
            modal.addEventListener('click', function (event) {
                if (event.target === modal) {
                    closeModal();
                }
            });
            document.addEventListener('keydown', function (event) {
                if (event.key === 'Escape' && !modal.hidden) {
                    closeModal();
                }
            });
        })();
    </script>
    <?php render_language_script([
        'login_title' => ['id' => 'Login', 'en' => 'Login'],
        'login_deadline_notice' => ['id' => 'Deadline pemilihan: <strong>{date}</strong>.', 'en' => 'Voting deadline: <strong>{date}</strong>.'],
        'login_deadline_closed' => ['id' => 'Masa pemilihan sudah berakhir pada <strong>{date}</strong>.', 'en' => 'The voting period ended on <strong>{date}</strong>.'],
        'login_username_label' => ['id' => 'Username', 'en' => 'Username'],
        'login_username_placeholder' => ['id' => 'masukkan username akun', 'en' => 'enter your account username'],
        'login_password_label' => ['id' => 'Password', 'en' => 'Password'],
        'login_password_placeholder' => ['id' => 'masukkan password akun', 'en' => 'enter your account password'],
        'login_submit' => ['id' => 'Masuk', 'en' => 'Sign In'],
        'welcome_close_label' => ['id' => 'Tutup popup', 'en' => 'Close popup'],
        'welcome_title' => ['id' => '<strong>Shalom REC Indonesia!</strong>', 'en' => '<strong>Shalom REC Indonesia!</strong>'],
        'welcome_text' => [
            'id' => 'Terima kasih atas partisipasi Anda dalam pemilihan kandidat Majelis REC Indonesia periode 2026-2029. Suara Anda adalah wujud kasih yang nyata bagi pembangunan Tubuh Kristus. Mari nyatakan kehendak-Nya melalui pilihan Anda hari ini. Selamat memilih dengan sukacita!',
            'en' => 'Thank you for your participation in the election of REC Indonesia elder candidates for the 2026-2029 term. Your vote is a tangible expression of love for building the Body of Christ. Let us express His will through your choice today. Vote with joy.'
        ],
    ]); ?>
</body>
</html>
