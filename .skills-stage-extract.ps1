$ErrorActionPreference = 'Stop'
$dl = "C:\Users\Marli\Downloads"
$stage = "C:\Users\Marli\Desktop\Hauptprojekt\.skills-stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null

$zips = Get-ChildItem $dl -Filter *.zip | Where-Object {
  $_.Name -match 'ui-skills|impeccable|awesome-design|stop-slop|superpowers|skills-main|ui-ux-pro-max'
}
foreach ($z in $zips) {
  $dest = Join-Path $stage ($z.BaseName -replace '[^\w\-]','_')
  try { Expand-Archive -Path $z.FullName -DestinationPath $dest -Force; Write-Host "extracted: $($z.Name)" }
  catch { Write-Host "FAIL: $($z.Name) -> $_" }
}

Write-Host "==== SKILL.md Inventar ===="
$skills = Get-ChildItem $stage -Recurse -Filter SKILL.md
Write-Host ("Gefundene SKILL.md: " + $skills.Count)
foreach ($s in $skills) {
  $rel = $s.FullName.Substring($stage.Length + 1)
  Write-Host $rel
}
