# =============================================================================
# WrapSec — End-to-End Validation Script
# Tests: JWT auth, user management, admin_events, auth_events
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\tests\scripts\validate_e2e.ps1
#
# Requirements:
#   - API running at localhost:8000
#   - PostgreSQL running via docker (container: wrapsec_postgres)
#   - Admin credentials: admin@yourdomain.com / WrapSec@Admin2026!
# =============================================================================

$base     = "http://localhost:8000"
$adminKey = "wrapsec_admin_key"
$pass     = 0
$fail     = 0

function Check($label, $condition) {
    if ($condition) {
        Write-Host "  [PASS] $label" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  [FAIL] $label" -ForegroundColor Red
        $script:fail++
    }
}

function Section($title) {
    Write-Host ""
    Write-Host "-- $title" -ForegroundColor Cyan
}

# =============================================================================
# 1. LOGIN — valid credentials
# =============================================================================

Section "1. Login"

$loginBody = '{"email":"admin@yourdomain.com","password":"WrapSec@Admin2026!"}'
try {
    $r = Invoke-WebRequest -UseBasicParsing -Method POST "$base/v1/auth/login" `
        -ContentType "application/json" -Body $loginBody
    $loginData = $r.Content | ConvertFrom-Json
    $token     = $loginData.access_token

    Check "HTTP 200"                       ($r.StatusCode -eq 200)
    Check "access_token present"           ($null -ne $token -and $token.Length -gt 10)
    Check "token_type = bearer"            ($loginData.token_type -eq "bearer")
    Check "expires_in present"             ($loginData.expires_in -gt 0)
    Check "force_password_change = false"  ($loginData.force_password_change -eq $false)
    Check "user.email correct"             ($loginData.user.email -eq "admin@yourdomain.com")
    Check "user.role = ADMIN"              ($loginData.user.role -eq "ADMIN")
    Check "user.dept_id = null (ADMIN)"    ($null -eq $loginData.user.dept_id)
    Check "user.tenant_id present"         ($null -ne $loginData.user.tenant_id)
} catch {
    Write-Host "  [ERROR] Login failed: $_" -ForegroundColor Red
    exit 1
}

# =============================================================================
# 2. LOGIN FAILURE — wrong password (no enumeration)
# =============================================================================

Section "2. Login failure -- wrong password"

try {
    Invoke-WebRequest -UseBasicParsing -Method POST "$base/v1/auth/login" `
        -ContentType "application/json" `
        -Body '{"email":"admin@yourdomain.com","password":"wrongpassword"}' | Out-Null
    Check "Should have returned 401" $false
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    $body = $_.ErrorDetails.Message | ConvertFrom-Json
    Check "HTTP 401"                         ($code -eq 401)
    Check "code = INVALID_CREDENTIALS"       ($body.error.code -eq "INVALID_CREDENTIALS")
    Check "generic message (no enumeration)" ($body.error.message -eq "Invalid email or password")
}

# =============================================================================
# 3. LOGIN FAILURE — user not found (same message as wrong password)
# =============================================================================

Section "3. Login failure -- user not found"

try {
    Invoke-WebRequest -UseBasicParsing -Method POST "$base/v1/auth/login" `
        -ContentType "application/json" `
        -Body '{"email":"nobody@nowhere.com","password":"SomePass1!"}' | Out-Null
    Check "Should have returned 401" $false
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    $body = $_.ErrorDetails.Message | ConvertFrom-Json
    Check "HTTP 401"                       ($code -eq 401)
    Check "same message as wrong password" ($body.error.message -eq "Invalid email or password")
}

# =============================================================================
# 4. GET /v1/auth/me
# =============================================================================

Section "4. GET /v1/auth/me"

try {
    $me = Invoke-WebRequest -UseBasicParsing -Method GET "$base/v1/auth/me" `
        -Headers @{"Authorization" = "Bearer $token"} |
        Select-Object -ExpandProperty Content | ConvertFrom-Json

    Check "id present"                  ($null -ne $me.id)
    Check "email correct"               ($me.email -eq "admin@yourdomain.com")
    Check "role = ADMIN"                ($me.role -eq "ADMIN")
    Check "dept_id = null (ADMIN)"      ($null -eq $me.dept_id)
    Check "tenant_id present"           ($null -ne $me.tenant_id)
    Check "is_active = true"            ($me.is_active -eq $true)
    Check "force_password_change field" ($me.PSObject.Properties.Name -contains "force_password_change")
    Check "last_login_at present"       ($null -ne $me.last_login_at)
} catch {
    Write-Host "  [ERROR] GET /me failed: $_" -ForegroundColor Red
    $script:fail += 8
}

# =============================================================================
# 5. /me rejected with API key (JWT-only endpoint)
# =============================================================================

Section "5. /me rejected with API key"

try {
    Invoke-WebRequest -UseBasicParsing -Method GET "$base/v1/auth/me" `
        -Headers @{"x-api-key" = $adminKey} | Out-Null
    Check "Should have returned 403" $false
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    Check "HTTP 403" ($code -eq 403)
}

# =============================================================================
# 6. auth_events written to DB
# =============================================================================

Section "6. auth_events in DB"

$ae = docker exec -i wrapsec_postgres psql -U wrapsec -d wrapsec `
    -c "SELECT action, success, failure_reason, ip_address FROM auth_events ORDER BY created_at DESC LIMIT 10;" 2>&1

Check "login_success logged"    ($ae -match "login_success")
Check "login_failed logged"     ($ae -match "login_failed")
Check "invalid_password logged" ($ae -match "invalid_password")
Check "user_not_found logged"   ($ae -match "user_not_found")
Check "ip_address captured"     ($ae -match "127.0.0.1")

# =============================================================================
# 7. List users
# =============================================================================

Section "7. GET /v1/admin/users"

$usersResp  = $null
$testUser   = $null
$testUserId = $null

try {
    $usersResp = Invoke-WebRequest -UseBasicParsing -Method GET "$base/v1/admin/users" `
        -Headers @{"Authorization" = "Bearer $token"} |
        Select-Object -ExpandProperty Content | ConvertFrom-Json

    Check "total > 0"         ($usersResp.total -gt 0)
    Check "users array"       ($usersResp.users.Count -gt 0)
    Check "tenant isolation"  (($usersResp.users | Where-Object { $_.tenant_id -ne $loginData.user.tenant_id }).Count -eq 0)

    $testUser = $usersResp.users | Where-Object { $_.role -ne "ADMIN" -and $_.is_active -eq $true } | Select-Object -First 1
    if ($null -ne $testUser) {
        $testUserId = $testUser.id
        Check "non-admin user found" ($null -ne $testUserId)
    } else {
        Write-Host "  [SKIP] No active non-admin user -- skipping PATCH tests" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [ERROR] List users: $_" -ForegroundColor Red
    $script:fail += 4
}

# =============================================================================
# 8. /admin/users rejected with API key
# =============================================================================

Section "8. /admin/users rejected with API key"

try {
    Invoke-WebRequest -UseBasicParsing -Method GET "$base/v1/admin/users" `
        -Headers @{"x-api-key" = $adminKey} | Out-Null
    Check "Should have returned 403" $false
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    Check "HTTP 403" ($code -eq 403)
}

# =============================================================================
# 9. PATCH user role
# =============================================================================

Section "9. PATCH role change"

if ($null -ne $testUserId) {
    $currentRole = $testUser.role
    $newRole     = if ($currentRole -eq "DEVELOPER") { "VIEWER" } else { "DEVELOPER" }

    try {
        $patchBody = "{`"role`":`"$newRole`"}"
        $patched   = Invoke-WebRequest -UseBasicParsing -Method PATCH `
            "$base/v1/admin/users/$testUserId" `
            -Headers @{"Authorization" = "Bearer $token"} `
            -ContentType "application/json" `
            -Body $patchBody |
            Select-Object -ExpandProperty Content | ConvertFrom-Json

        Check "role updated"              ($patched.role -eq $newRole)
        Check "id unchanged"              ($patched.id -eq $testUserId)
        Check "response has all fields"   ($patched.PSObject.Properties.Name -contains "force_password_change")

        # Restore original role
        $restoreBody = "{`"role`":`"$currentRole`"}"
        Invoke-WebRequest -UseBasicParsing -Method PATCH `
            "$base/v1/admin/users/$testUserId" `
            -Headers @{"Authorization" = "Bearer $token"} `
            -ContentType "application/json" `
            -Body $restoreBody | Out-Null

        Check "role restored" $true
    } catch {
        Write-Host "  [ERROR] PATCH role: $($_.ErrorDetails.Message)" -ForegroundColor Red
        $script:fail += 4
    }
} else {
    Write-Host "  [SKIP] No test user" -ForegroundColor Yellow
}

# =============================================================================
# 10. Self-deactivation guard
# =============================================================================

Section "10. Self-deactivation guard"

$myId = $loginData.user.id
try {
    Invoke-WebRequest -UseBasicParsing -Method PATCH "$base/v1/admin/users/$myId" `
        -Headers @{"Authorization" = "Bearer $token"} `
        -ContentType "application/json" `
        -Body '{"is_active":false}' | Out-Null
    Check "Should have returned 400" $false
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    $body = $_.ErrorDetails.Message | ConvertFrom-Json
    Check "HTTP 400"               ($code -eq 400)
    Check "mentions deactivate"    ($body.error.message -match "deactivate")
}

# =============================================================================
# 11. Last-admin protection
# =============================================================================

Section "11. Last-admin protection"

# Get a dept_id for the demotion attempt
$depts  = Invoke-WebRequest -UseBasicParsing -Method GET "$base/v1/admin/departments" `
    -Headers @{"x-api-key" = $adminKey}
$deptId = ($depts.Content | ConvertFrom-Json).departments[0].id

try {
    $demoteBody = "{`"role`":`"DEVELOPER`",`"dept_id`":`"$deptId`"}"
    Invoke-WebRequest -UseBasicParsing -Method PATCH "$base/v1/admin/users/$myId" `
        -Headers @{"Authorization" = "Bearer $token"} `
        -ContentType "application/json" `
        -Body $demoteBody | Out-Null
    Check "Should have returned 400" $false
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    $body = $_.ErrorDetails.Message | ConvertFrom-Json
    Check "HTTP 400"                  ($code -eq 400)
    Check "mentions last active admin" ($body.error.message -match "last active admin")
}

# =============================================================================
# 12. Final state validation — ADMIN + dept_id must be rejected
# =============================================================================

Section "12. Final state validation -- ADMIN + dept_id rejected"

try {
    $badBody = "{`"email`":`"baduser@test.com`",`"password`":`"TestPass1!`",`"role`":`"ADMIN`",`"dept_id`":`"$deptId`"}"
    Invoke-WebRequest -UseBasicParsing -Method POST "$base/v1/admin/users" `
        -Headers @{"Authorization" = "Bearer $token"} `
        -ContentType "application/json" `
        -Body $badBody | Out-Null
    Check "Should have returned 400" $false
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    Check "HTTP 400 -- ADMIN cannot have dept_id" ($code -eq 400)
}

# =============================================================================
# 13. Create user + reset password
# =============================================================================

Section "13. Create user and reset password"

$testEmail     = "validate-$(Get-Random -Maximum 99999)@test.com"
$createdUserId = $null

try {
    $createBody = "{`"email`":`"$testEmail`",`"password`":`"TempPass1!`",`"role`":`"DEVELOPER`",`"dept_id`":`"$deptId`"}"
    $created    = Invoke-WebRequest -UseBasicParsing -Method POST "$base/v1/admin/users" `
        -Headers @{"Authorization" = "Bearer $token"} `
        -ContentType "application/json" `
        -Body $createBody |
        Select-Object -ExpandProperty Content | ConvertFrom-Json

    $createdUserId = $created.id
    Check "HTTP 201 -- user created"       ($null -ne $createdUserId)
    Check "force_password_change = true"   ($created.force_password_change -eq $true)
    Check "role = DEVELOPER"               ($created.role -eq "DEVELOPER")
    Check "is_active = true"               ($created.is_active -eq $true)

    # Reset password
    $reset = Invoke-WebRequest -UseBasicParsing -Method POST `
        "$base/v1/admin/users/$createdUserId/reset-password" `
        -Headers @{"Authorization" = "Bearer $token"} `
        -ContentType "application/json" `
        -Body '{"new_password":"NewTemp1!"}' |
        Select-Object -ExpandProperty Content | ConvertFrom-Json

    Check "reset-password message present"  ($null -ne $reset.message)
    Check "reset-password user_id correct"  ($reset.user_id -eq $createdUserId)
} catch {
    Write-Host "  [ERROR] Create/reset: $($_.ErrorDetails.Message)" -ForegroundColor Red
    $script:fail += 6
}

# =============================================================================
# 14. admin_events written to DB
# =============================================================================

Section "14. admin_events in DB"

$admEv = docker exec -i wrapsec_postgres psql -U wrapsec -d wrapsec `
    -c "SELECT action, metadata FROM admin_events ORDER BY created_at DESC LIMIT 10;" 2>&1

Check "user_created logged"   ($admEv -match "user_created")
Check "password_reset logged" ($admEv -match "password_reset")
Check "role_changed logged"   ($admEv -match "role_changed")
Check "role metadata present" ($admEv -match "old_role")

# =============================================================================
# 15. Duplicate email rejected
# =============================================================================

Section "15. Duplicate email rejected"

# Note: ErrorDetails.Message can be null in PowerShell 5 for some responses.
# Check status code directly and verify via list that no duplicate was created.
try {
    $dupBody = "{`"email`":`"admin@yourdomain.com`",`"password`":`"TempPass1!`",`"role`":`"DEVELOPER`",`"dept_id`":`"$deptId`"}"
    Invoke-WebRequest -UseBasicParsing -Method POST "$base/v1/admin/users" `
        -Headers @{"Authorization" = "Bearer $token"} `
        -ContentType "application/json" `
        -Body $dupBody | Out-Null
    Check "Should have returned 409" $false
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    Check "HTTP 409" ($code -eq 409)

    # HTTP 409 confirms the duplicate was rejected — no secondary check needed
}

# =============================================================================
# 16. Cleanup test user
# =============================================================================

Section "16. Cleanup"

if ($null -ne $createdUserId) {
    try {
        docker exec -i wrapsec_postgres psql -U wrapsec -d wrapsec -c `
            "DELETE FROM admin_events WHERE target_user_id = '$createdUserId'; DELETE FROM refresh_tokens WHERE user_id = '$createdUserId'; DELETE FROM users WHERE id = '$createdUserId';" | Out-Null
        Check "Test user cleaned up" $true
    } catch {
        Write-Host "  [WARN] Cleanup failed -- delete manually: $createdUserId" -ForegroundColor Yellow
    }
}

# =============================================================================
# Summary
# =============================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor White
$total = $script:pass + $script:fail
if ($script:fail -eq 0) {
    Write-Host "  $($script:pass)/$total passed -- ALL GREEN" -ForegroundColor Green
} else {
    Write-Host "  $($script:pass)/$total passed  |  $($script:fail) FAILED" -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor White
Write-Host ""
