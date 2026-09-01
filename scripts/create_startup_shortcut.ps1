$WScriptShell = New-Object -ComObject WScript.Shell
$StartupDir = [System.Environment]::GetFolderPath('Startup')
$ShortcutPath = Join-Path $StartupDir "CloudCampaignConsole.lnk"

$TargetFile = "powershell.exe"
$Arguments = "-WindowStyle Hidden -Command ""& { Set-Location 'C:\Users\downi\OneDrive\Documents\08metricsdemos_1786575674023\08_metrics_demos\artifacts'; py -m streamlit run 'C:\Users\downi\OneDrive\Documents\08metricsdemos_1786575674023\08_metrics_demos\artifacts\cloud-campaign-evidence-graph\app\dashboard.py' --server.headless true }"""

$Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Arguments = $Arguments
$Shortcut.WorkingDirectory = "C:\Users\downi\OneDrive\Documents\08metricsdemos_1786575674023\08_metrics_demos\artifacts"
$Shortcut.Description = "Auto-start Cloud Campaign Evidence Graph Dashboard"
$Shortcut.Save()

Write-Host "[+] Startup shortcut created successfully at: $ShortcutPath" -ForegroundColor Green
