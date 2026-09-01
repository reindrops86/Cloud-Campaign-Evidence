# PowerShell automated trigger script for Windows Task Scheduler
# Usage: Execute this script manually or schedule it via Windows Task Scheduler.

$WorkspaceDir = "C:\Users\downi\OneDrive\Documents\08metricsdemos_1786575674023\08_metrics_demos\artifacts"
$ProjectDir = "$WorkspaceDir\cloud-campaign-evidence-graph"
$PythonExe = "py" # or specify full virtual environment path e.g., C:\Users\downi\crewai-venv\Scripts\python.exe

Set-Location $WorkspaceDir
$env:PYTHONPATH = $ProjectDir

Write-Host "[*] Running Automated Cloud Campaign Evidence Graph Benchmark Evaluation..." -ForegroundColor Cyan
& $PythonExe "$ProjectDir\eval\evaluate.py" --cases "$ProjectDir\eval\benchmark_cases.json" --output "$ProjectDir\eval\evaluation_report.json"

Write-Host "[*] Running Automated Investigation for sample seed..." -ForegroundColor Cyan
& $PythonExe "$ProjectDir\app\main.py" --seed "AKIAIOSFODNN7EXAMPLE" --output "$ProjectDir\data\investigation_output.json" --export-stix "$ProjectDir\data\sample_stix_bundle.json" --export-markdown "$ProjectDir\data\sample_report.md"

Write-Host "[+] Automated pipeline execution complete." -ForegroundColor Green
