param(
    [int]$Count = 20,
    [string]$Prefix = 'ctrl-c-verify'
)

$ErrorActionPreference = 'Stop'
$ahk = "${env:RUNNER_TEMP}\ahk\AutoHotKey64.exe"

for ($i = 1; $i -le $Count; $i++) {
    Write-Host "Verification run $i/$Count"
    $env:LARGE_FILES_DIRECTORY =
        "${env:RUNNER_TEMP}\large-$Prefix-$i"
    $stdout = "$PSScriptRoot\$Prefix-$i.stdout.log"
    $stderr = "$PSScriptRoot\$Prefix-$i.stderr.log"
    $arguments = @(
        '/ErrorStdOut'
        '/force'
        'ctrl-c.ahk'
        "$PSScriptRoot\$Prefix-$i"
    )
    $process = Start-Process -FilePath $ahk `
        -ArgumentList $arguments -PassThru `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr
    if (!$process.WaitForExit(180000)) {
        Stop-Process -Id $process.Id -Force
        throw "Verification run $i timed out"
    }
    Get-Content $stdout -ErrorAction SilentlyContinue
    Get-Content $stderr -ErrorAction SilentlyContinue
    if ($process.ExitCode -ne 0) {
        throw "Verification run $i exited with $($process.ExitCode)"
    }
}
