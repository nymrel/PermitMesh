param(
    [string]$Python = "python",
    [string]$Receipt = "validation/clean-room.json"
)

$ErrorActionPreference = "Stop"
$started = Get-Date
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$tempRoot = Join-Path $tempBase ("permitmesh-clean-room-" + [guid]::NewGuid().ToString("N"))
$clonePath = Join-Path $tempRoot "repo"
$venvPath = Join-Path $tempRoot "venv"
$receiptPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Receipt))
$pushed = $false
$contextKeySet = $false

try {
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    git clone --quiet $repoRoot $clonePath
    if ($LASTEXITCODE -ne 0) { throw "git clone failed" }

    Push-Location $clonePath
    $pushed = $true
    & $Python -m build
    if ($LASTEXITCODE -ne 0) { throw "package build failed" }
    $wheel = Get-ChildItem -LiteralPath (Join-Path $clonePath "dist") `
        -Filter "permitmesh-*.whl" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $wheel) { throw "built wheel not found" }

    & $Python -m venv $venvPath
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
    $venvPythonRelative = if ($env:OS -eq "Windows_NT") {
        "Scripts/python.exe"
    } else {
        "bin/python"
    }
    $venvPython = Join-Path $venvPath $venvPythonRelative
    & $venvPython -m pip install --quiet --disable-pip-version-check `
        --no-index --no-deps $wheel.FullName
    if ($LASTEXITCODE -ne 0) { throw "clean wheel install failed" }

    $cloneReceipt = Join-Path $clonePath "validation/conformance-clean-room.json"
    & $venvPython -m permitmesh conformance examples/conformance-suite.json `
        --receipt $cloneReceipt | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "conformance suite failed" }
    $env:PERMITMESH_BUZZ_CONTEXT_KEY = "permitmesh-public-conformance-key-not-secret"
    $contextKeySet = $true
    & $venvPython -m permitmesh authorize-buzz `
        examples/contract.valid.json `
        examples/request.allowed.json `
        examples/buzz-context.valid.json `
        --context-key-env PERMITMESH_BUZZ_CONTEXT_KEY `
        --expected-community-uri wss://relay.example.com/permitmesh `
        --expected-repository-event-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
        --evaluation-time 2026-07-23T12:00:00Z | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "authenticated Buzz fixture failed" }
    Remove-Item Env:PERMITMESH_BUZZ_CONTEXT_KEY -ErrorAction SilentlyContinue
    $contextKeySet = $false

    $conformance = Get-Content -LiteralPath $cloneReceipt -Raw |
        ConvertFrom-Json
    $sourceCommit = (git rev-parse HEAD).Trim()
    Pop-Location
    $pushed = $false

    $elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds, 3)
    $result = [ordered]@{
        receipt_version = "0.2"
        status = "pass"
        source = if ($env:GITHUB_ACTIONS -eq "true") {
            "GitHub Actions clean clone"
        } else {
            "clean local git clone"
        }
        commit = $sourceCommit
        github_repository = $env:GITHUB_REPOSITORY
        github_run_id = $env:GITHUB_RUN_ID
        github_workflow_ref = $env:GITHUB_WORKFLOW_REF
        python = (& $venvPython --version 2>&1).ToString()
        runner_os = $env:RUNNER_OS
        elapsed_seconds = $elapsed
        threshold_seconds = 600
        package_build = "pass"
        wheel_install = "no-index; no-deps"
        wheel_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $wheel.FullName).Hash.ToLowerInvariant()
        conformance = "$($conformance.summary.passed)/$($conformance.summary.total)"
        conformance_suite_digest = $conformance.suite.digest
        buzz_authenticated_fixture = "allow"
        enforcement_boundary = "policy-decision-only; no tool execution"
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $receiptPath) | Out-Null
    $resultJson = $result | ConvertTo-Json
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText(
        $receiptPath,
        $resultJson + [Environment]::NewLine,
        $utf8NoBom
    )
    $resultJson
}
finally {
    if ($contextKeySet) {
        Remove-Item Env:PERMITMESH_BUZZ_CONTEXT_KEY -ErrorAction SilentlyContinue
    }
    if ($pushed) { Pop-Location }
    $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
    if ($resolvedTemp.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) -and
        $resolvedTemp -like "*permitmesh-clean-room-*") {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
