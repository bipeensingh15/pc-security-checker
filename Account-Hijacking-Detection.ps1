# Account Hijacking & Compromise Detection Script
# Checks browser data, credentials, and login history to detect account breaches
# Run as Administrator for best results

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  ACCOUNT HIJACKING DETECTION TOOL" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "यह script आपके account compromise होने के क्या कारण हो सकते हैं, यह check करेगा" -ForegroundColor Yellow
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "WARNING: इस script को Administrator के रूप में चलाएं!" -ForegroundColor Yellow
}

Write-Host ""

# 1. CHECK BROWSER SAVED PASSWORDS
Write-Host "[1] CHECKING SAVED PASSWORDS IN BROWSERS" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green

# Chrome
Write-Host ""
Write-Host "🔍 Google Chrome:" -ForegroundColor Cyan
try {
    $chromeProfilePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    if (Test-Path $chromeProfilePath) {
        Write-Host "✓ Chrome found at: $chromeProfilePath" -ForegroundColor Green
        
        # Check for Login Data file
        $loginDataPath = Join-Path $chromeProfilePath "Login Data"
        if (Test-Path $loginDataPath) {
            Write-Host "⚠ Chrome has saved passwords (Login Data file exists)" -ForegroundColor Yellow
            Write-Host "  ⚠ WARNING: हैकर इन saved passwords को चोरी कर सकता है!" -ForegroundColor Red
            Write-Host "  📍 Location: $loginDataPath" -ForegroundColor White
            Write-Host "  🔧 Fix करो: Chrome Settings → Passwords → Remove all saved passwords" -ForegroundColor Yellow
        } else {
            Write-Host "✓ No saved passwords found in Chrome" -ForegroundColor Green
        }
    } else {
        Write-Host "ℹ Chrome not installed or no user profile" -ForegroundColor Gray
    }
} catch {
    Write-Host "⚠ Error checking Chrome: $_" -ForegroundColor Yellow
}

# Edge
Write-Host ""
Write-Host "🔍 Microsoft Edge:" -ForegroundColor Cyan
try {
    $edgeProfilePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
    if (Test-Path $edgeProfilePath) {
        Write-Host "✓ Edge found at: $edgeProfilePath" -ForegroundColor Green
        
        $loginDataPath = Join-Path $edgeProfilePath "Login Data"
        if (Test-Path $loginDataPath) {
            Write-Host "⚠ Edge has saved passwords" -ForegroundColor Yellow
            Write-Host "  ⚠ WARNING: Saved passwords vulnerable!" -ForegroundColor Red
            Write-Host "  🔧 Fix करो: Edge Settings → Passwords → Remove all" -ForegroundColor Yellow
        }
    } else {
        Write-Host "ℹ Edge not installed" -ForegroundColor Gray
    }
} catch {
    Write-Host "⚠ Error checking Edge: $_" -ForegroundColor Yellow
}

Write-Host ""

# 2. CHECK BROWSER EXTENSIONS (Malicious Extensions)
Write-Host "[2] CHECKING FOR MALICIOUS BROWSER EXTENSIONS" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

Write-Host "🔍 Chrome Extensions:" -ForegroundColor Cyan
try {
    $chromeExtensionsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    if (Test-Path $chromeExtensionsPath) {
        $extensions = Get-ChildItem $chromeExtensionsPath -Directory -ErrorAction SilentlyContinue
        Write-Host "✓ Found $($extensions.Count) Chrome extensions:" -ForegroundColor White
        
        $suspiciousKeywords = @("password", "credential", "login", "steal", "hack", "spy", "monitor", "keylog", "tracker")
        
        foreach ($ext in $extensions) {
            $manifestPath = Join-Path $ext.FullName "manifest.json"
            if (Test-Path $manifestPath) {
                $manifest = Get-Content $manifestPath -Raw
                
                $isSuspicious = $false
                foreach ($keyword in $suspiciousKeywords) {
                    if ($manifest -like "*$keyword*") {
                        $isSuspicious = $true
                        break
                    }
                }
                
                if ($isSuspicious) {
                    Write-Host "  🚨 SUSPICIOUS: $($ext.Name)" -ForegroundColor Red
                    Write-Host "     Extension name या manifest में suspicious keywords मिले!" -ForegroundColor Red
                } else {
                    Write-Host "  ✓ $($ext.Name)" -ForegroundColor Green
                }
            }
        }
    }
} catch {
    Write-Host "⚠ Error checking Chrome extensions: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "⚠️ IMPORTANT: Browser Extensions में से कुछ malicious हो सकते हैं जो:" -ForegroundColor Yellow
Write-Host "  • Passwords चोरी करते हैं" -ForegroundColor White
Write-Host "  • Keystrokes log करते हैं (keylogger)" -ForegroundColor White
Write-Host "  • Form data चोरी करते हैं" -ForegroundColor White
Write-Host "  • Social media session intercept करते हैं" -ForegroundColor White
Write-Host ""

# 3. CHECK BROWSER COOKIES & CACHE
Write-Host "[3] CHECKING BROWSER COOKIES & SESSION DATA" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

Write-Host "🔍 Chrome Cookies:" -ForegroundColor Cyan
try {
    $cookiesPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
    if (Test-Path $cookiesPath) {
        $cookieSize = (Get-Item $cookiesPath).Length / 1KB
        Write-Host "⚠ Chrome cookies found: $([math]::Round($cookieSize, 2)) KB" -ForegroundColor Yellow
        Write-Host "  ⚠️ WARNING: Cookies में session tokens हो सकते हैं!" -ForegroundColor Red
        Write-Host "  Hacker इन cookies को चोरी करके आपके account access कर सकता है!" -ForegroundColor Red
        Write-Host "  🔧 Fix करो: Clear browsing data → Cookies" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠ Error checking cookies: $_" -ForegroundColor Yellow
}

Write-Host ""

# 4. CHECK FOR KEYLOGGER SOFTWARE
Write-Host "[4] CHECKING FOR KEYLOGGER/SPYWARE" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

$keyloggerSignatures = @(
    "keylogger", "spyware", "ratware", "trojan", "stealer", "infostealer",
    "redline", "vidar", "lumma", "asyncrat", "dcrat", "njrat", "quasar",
    "revenge", "ares", "masslogger", "formbook", "lokibot", "agenttesla"
)

Write-Host "🔍 Scanning for known keylogger signatures in running processes..." -ForegroundColor Cyan
try {
    $processes = Get-Process -ErrorAction SilentlyContinue
    $found = $false
    
    foreach ($process in $processes) {
        foreach ($sig in $keyloggerSignatures) {
            if ($process.Name -like "*$sig*") {
                Write-Host "🚨 POTENTIAL KEYLOGGER FOUND: $($process.Name)" -ForegroundColor Red
                Write-Host "   PID: $($process.Id)" -ForegroundColor Red
                Write-Host "   Path: $($process.Path)" -ForegroundColor Red
                $found = $true
            }
        }
    }
    
    if (-not $found) {
        Write-Host "✓ No known keylogger signatures detected" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠ Error scanning for keyloggers: $_" -ForegroundColor Yellow
}

Write-Host ""

# 5. CHECK FOR INSTALLED SOFTWARE THAT CAPTURES KEYSTROKES
Write-Host "[5] CHECKING FOR SUSPICIOUS INSTALLED SOFTWARE" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

$suspiciousApps = @(
    "Optomo", "Adware", "Search", "Toolbar", "Speed", "PC Cleaner", "Driver Updater",
    "Optimizer", "Booster", "Registry Cleaner", "Photo Editor Fake", "PDF Reader Fake"
)

Write-Host "🔍 Scanning installed programs..." -ForegroundColor Cyan
try {
    $installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Select-Object DisplayName
    
    foreach ($app in $installedApps) {
        foreach ($suspicious in $suspiciousApps) {
            if ($app.DisplayName -like "*$suspicious*") {
                Write-Host "⚠️ SUSPICIOUS APP FOUND: $($app.DisplayName)" -ForegroundColor Red
                Write-Host "   यह app malware हो सकता है!" -ForegroundColor Red
            }
        }
    }
    
    Write-Host "✓ Scan complete" -ForegroundColor Green
} catch {
    Write-Host "⚠ Error scanning installed software: $_" -ForegroundColor Yellow
}

Write-Host ""

# 6. CHECK BROWSER AUTOCOMPLETE & FORM DATA
Write-Host "[6] CHECKING FOR STORED FORM DATA" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

Write-Host "🔍 Checking Chrome AutoFill data..." -ForegroundColor Cyan
try {
    $webDataPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Web Data"
    if (Test-Path $webDataPath) {
        $dataSize = (Get-Item $webDataPath).Length / 1KB
        Write-Host "⚠ Chrome Web Data found: $([math]::Round($dataSize, 2)) KB" -ForegroundColor Yellow
        Write-Host "  ⚠️ WARNING: AutoFill data में email, phone, address हो सकते हैं!" -ForegroundColor Red
        Write-Host "  🔧 Fix करो: Chrome Settings → Autofill → Clear all data" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠ Error checking form data: $_" -ForegroundColor Yellow
}

Write-Host ""

# 7. CHECK FOR PROXY SETTINGS (Man-in-the-Middle Attack)
Write-Host "[7] CHECKING FOR PROXY SERVER CONFIGURATION" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

Write-Host "🔍 Checking system proxy settings..." -ForegroundColor Cyan
try {
    $proxyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $proxyEnable = (Get-ItemProperty -Path $proxyPath -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
    $proxyServer = (Get-ItemProperty -Path $proxyPath -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
    
    if ($proxyEnable -eq 1) {
        Write-Host "⚠️ SYSTEM PROXY IS ENABLED!" -ForegroundColor Red
        Write-Host "   Proxy Server: $proxyServer" -ForegroundColor Red
        Write-Host "   ⚠️ WARNING: यह Man-in-the-Middle attack हो सकता है!" -ForegroundColor Red
        Write-Host "   Hacker सभी traffic intercept कर सकता है!" -ForegroundColor Red
        Write-Host "   🔧 Fix करो: Settings → Network → Proxy → Turn off" -ForegroundColor Yellow
    } else {
        Write-Host "✓ No system proxy configured" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠ Error checking proxy: $_" -ForegroundColor Yellow
}

Write-Host ""

# 8. CHECK BROWSER STARTUP PAGES
Write-Host "[8] CHECKING BROWSER HOMEPAGE & STARTUP PAGES" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

Write-Host "🔍 Checking Chrome preferences..." -ForegroundColor Cyan
try {
    $prefsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
    if (Test-Path $prefsPath) {
        $prefs = Get-Content $prefsPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        
        if ($prefs.homepage) {
            Write-Host "Homepage: $($prefs.homepage)" -ForegroundColor White
            if ($prefs.homepage -notlike "*google*" -and $prefs.homepage -notlike "*default*") {
                Write-Host "⚠️ WARNING: Non-standard homepage detected!" -ForegroundColor Red
                Write-Host "   यह malware हो सकता है!" -ForegroundColor Red
            }
        }
        
        if ($prefs.session.restore_on_startup -eq 1) {
            Write-Host "⚠ Chrome restore करेगा previous tabs on startup" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "⚠ Error checking browser preferences: $_" -ForegroundColor Yellow
}

Write-Host ""

# 9. CHECK FOR VPN/PROXY EXTENSIONS
Write-Host "[9] CHECKING FOR VPN/PROXY BROWSER EXTENSIONS" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

Write-Host "🔍 Checking for VPN extensions..." -ForegroundColor Cyan
try {
    $chromeExtensionsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    if (Test-Path $chromeExtensionsPath) {
        $vpnKeywords = @("vpn", "proxy", "hotspot", "tunnel")
        $extensions = Get-ChildItem $chromeExtensionsPath -Directory
        
        foreach ($ext in $extensions) {
            $name = $ext.Name
            foreach ($keyword in $vpnKeywords) {
                if ($name -like "*$keyword*") {
                    Write-Host "⚠️ VPN/Proxy Extension found: $name" -ForegroundColor Yellow
                    Write-Host "   Check करो कि यह legitimate है या suspicious" -ForegroundColor White
                }
            }
        }
    }
} catch {
    Write-Host "⚠ Error checking VPN extensions: $_" -ForegroundColor Yellow
}

Write-Host ""

# 10. CHECK WINDOWS CREDENTIAL MANAGER
Write-Host "[10] CHECKING WINDOWS CREDENTIAL MANAGER" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

Write-Host "🔍 Checking saved Windows credentials..." -ForegroundColor Cyan
try {
    $credentials = cmdkey /list 2>$null
    if ($credentials) {
        Write-Host "⚠ Found stored Windows credentials:" -ForegroundColor Yellow
        $credentials | ForEach-Object {
            Write-Host "  $_" -ForegroundColor White
        }
        Write-Host "  ⚠️ WARNING: हैकर इन credentials चोरी कर सकता है!" -ForegroundColor Red
    } else {
        Write-Host "✓ No stored credentials found" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠ Error checking credentials: $_" -ForegroundColor Yellow
}

Write-Host ""

# 11. CHECK RECENT FILE ACCESS
Write-Host "[11] CHECKING RECENT FILE ACCESS PATTERNS" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

Write-Host "🔍 Checking recently modified files..." -ForegroundColor Cyan
try {
    $recentFiles = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\Recent" -File -ErrorAction SilentlyContinue | 
                   Sort-Object LastWriteTime -Descending | 
                   Select-Object -First 10
    
    if ($recentFiles) {
        Write-Host "Recent files accessed:" -ForegroundColor White
        $recentFiles | ForEach-Object {
            Write-Host "  - $($_.Name) | $($_.LastWriteTime)" -ForegroundColor White
        }
    }
} catch {
    Write-Host "⚠ Error checking recent files: $_" -ForegroundColor Yellow
}

Write-Host ""

# SUMMARY & RECOMMENDATIONS
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  ACCOUNT HIJACKING ANALYSIS COMPLETE" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "🔍 ACCOUNT COMPROMISE के Main कारण:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1️⃣ SAVED PASSWORDS" -ForegroundColor Red
Write-Host "   यदि browser में passwords saved हैं:" -ForegroundColor White
Write-Host "   • Hacker इन्हें आसानी से चोरी कर सकता है" -ForegroundColor White
Write-Host "   • Malware इन्हें export कर सकता है" -ForegroundColor White
Write-Host "   🔧 FIX: Chrome Settings → Passwords → Remove all" -ForegroundColor Yellow
Write-Host ""

Write-Host "2️⃣ MALICIOUS BROWSER EXTENSIONS" -ForegroundColor Red
Write-Host "   Fake extensions जो:" -ForegroundColor White
Write-Host "   • Passwords intercept करते हैं" -ForegroundColor White
Write-Host "   • Session cookies चोरी करते हैं" -ForegroundColor White
Write-Host "   • Form data भेजते हैं" -ForegroundColor White
Write-Host "   🔧 FIX: Chrome Settings → Extensions → Remove all suspicious" -ForegroundColor Yellow
Write-Host ""

Write-Host "3️⃣ KEYLOGGER/SPYWARE" -ForegroundColor Red
Write-Host "   Installed software जो:" -ForegroundColor White
Write-Host "   • हर keystroke को log करता है" -ForegroundColor White
Write-Host "   • Passwords capture करता है" -ForegroundColor White
Write-Host "   🔧 FIX: Add/Remove Programs → Suspicious apps remove करो" -ForegroundColor Yellow
Write-Host ""

Write-Host "4️⃣ BROWSER COOKIES & SESSION THEFT" -ForegroundColor Red
Write-Host "   यदि cookies चोरी हो जाएं:" -ForegroundColor White
Write-Host "   • Hacker आपके account में login हो सकता है" -ForegroundColor White
Write-Host "   • बिना password के access मिल जाता है" -ForegroundColor White
Write-Host "   🔧 FIX: Clear browsing data → Cookies & cache" -ForegroundColor Yellow
Write-Host ""

Write-Host "5️⃣ PROXY/MAN-IN-THE-MIDDLE ATTACK" -ForegroundColor Red
Write-Host "   यदि proxy enable है:" -ForegroundColor White
Write-Host "   • सभी network traffic intercept हो रहा है" -ForegroundColor White
Write-Host "   • Passwords visible हो सकते हैं" -ForegroundColor White
Write-Host "   🔧 FIX: Settings → Network → Proxy → Disable" -ForegroundColor Yellow
Write-Host ""

Write-Host "="*50 -ForegroundColor Cyan
Write-Host "🛡️ अभी क्या करो (IMMEDIATE ACTIONS):" -ForegroundColor Green
Write-Host "="*50 -ForegroundColor Cyan
Write-Host ""

Write-Host "✅ STEP 1: तुरंत सभी social media से logout करो" -ForegroundColor Green
Write-Host "   Facebook, Instagram, Twitter - everywhere" -ForegroundColor White
Write-Host ""

Write-Host "✅ STEP 2: दूसरे device से passwords बदलो" -ForegroundColor Green
Write-Host "   अपने laptop पर नहीं - phone या दूसरे PC से!" -ForegroundColor Red
Write-Host ""

Write-Host "✅ STEP 3: Browser से सभी passwords delete करो" -ForegroundColor Green
Write-Host "   Chrome → Settings → Passwords → Remove all" -ForegroundColor White
Write-Host ""

Write-Host "✅ STEP 4: सभी suspicious extensions remove करो" -ForegroundColor Green
Write-Host "   Chrome → Extensions → Remove unknown/suspicious ones" -ForegroundColor White
Write-Host ""

Write-Host "✅ STEP 5: Cookies clear करो" -ForegroundColor Green
Write-Host "   Chrome → Settings → Clear browsing data → Cookies" -ForegroundColor White
Write-Host ""

Write-Host "✅ STEP 6: Malwarebytes scan चलाओ" -ForegroundColor Green
Write-Host "   Free version से भी full scan कर सकते हो" -ForegroundColor White
Write-Host ""

Write-Host "✅ STEP 7: Windows Defender full scan चलाओ" -ForegroundColor Green
Write-Host "   Settings → Windows Security → Virus & threat protection" -ForegroundColor White
Write-Host ""

Write-Host "✅ STEP 8: सभी social media accounts पर check करो" -ForegroundColor Green
Write-Host "   Settings → Active sessions → Remove unknown devices" -ForegroundColor White
Write-Host ""

Write-Host "="*50 -ForegroundColor Cyan
Write-Host "⚠️ अगर सब कुछ करने के बाद भी problem है:" -ForegroundColor Red
Write-Host "="*50 -ForegroundColor Cyan
Write-Host ""

Write-Host "1. Factory Reset करो (Windows को fresh install करो)" -ForegroundColor Yellow
Write-Host "2. सभी passwords बदलो दूसरे device से" -ForegroundColor Yellow
Write-Host "3. Two-Factor Authentication enable करो हर जगह" -ForegroundColor Yellow
Write-Host ""

Write-Host "⏰ Important Reminder:" -ForegroundColor Cyan
Write-Host "हैकर अगर आपके passwords जानता है, तो:" -ForegroundColor White
Write-Host "• वह आपके email access कर सकता है" -ForegroundColor White
Write-Host "• Email से password reset कर सकता है" -ForegroundColor White
Write-Host "• सभी linked accounts को control कर सकता है" -ForegroundColor White
Write-Host ""
Write-Host "इसलिए EMAIL का password पहले बदलो!" -ForegroundColor Red
Write-Host ""
