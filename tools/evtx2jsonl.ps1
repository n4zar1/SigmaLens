<#
.SYNOPSIS
  Converts .evtx files to flat JSONL (one event per line, no nested objects) for SigmaLens.
.EXAMPLE
  .\evtx2jsonl.ps1 -Path .\Logs\*.evtx -OutDir .\jsonl
.NOTES
  Uses only built-in Windows cmdlets. Field names come from the event XML: System fields
  (EventID, Channel, Computer, EventRecordID, Provider, @timestamp) plus every EventData/UserData value.
#>
param(
  [Parameter(Mandatory)] [string[]] $Path,
  [string] $OutDir = '.'
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)

foreach ($file in Get-ChildItem -Path $Path) {
  $out = Join-Path $OutDir ($file.BaseName + '.jsonl')
  $w = New-Object System.IO.StreamWriter($out, $false, $utf8)
  $n = 0
  try {
    Get-WinEvent -Path $file.FullName -Oldest -ErrorAction SilentlyContinue | ForEach-Object {
      $x = [xml]$_.ToXml()
      $sys = $x.Event.System
      $eid = $sys.EventID
      if ($eid -is [System.Xml.XmlElement]) { $eid = $eid.'#text' }  # EventID with Qualifiers attribute
      $o = [ordered]@{
        '@timestamp'  = $sys.TimeCreated.SystemTime
        EventID       = [int]$eid
        Channel       = $sys.Channel
        Computer      = $sys.Computer
        EventRecordID = [long]$sys.EventRecordID
        Provider      = $sys.Provider.Name
      }
      if ($sys.Security.UserID) { $o.UserSID = $sys.Security.UserID }
      $i = 0
      foreach ($d in $x.Event.EventData.Data) {
        if ($null -eq $d) { continue }
        $name = if ($d.Name) { $d.Name } else { 'Data' + $i }
        $o[$name] = if ($d -is [string]) { $d } else { $d.InnerText }
        $i++
      }
      if ($x.Event.UserData) {
        foreach ($child in $x.Event.UserData.FirstChild.ChildNodes) { $o[$child.LocalName] = $child.InnerText }
      }
      $w.WriteLine(($o | ConvertTo-Json -Compress -Depth 2))
      $n++
    }
  } finally { $w.Close() }
  Write-Host ("{0}: {1} events -> {2}" -f $file.Name, $n, $out)
}
