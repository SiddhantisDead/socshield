rule PowerShell_Downloader_Pattern
{
    meta:
        description = "Detects PowerShell download-and-execute patterns commonly used to fetch second-stage payloads"
        severity = "high"
        mitre_id = "T1105"
        author = "SOCShield"
    strings:
        $iex_webclient = /IEX\s*\(\s*New-Object\s+Net\.WebClient\)/ nocase
        $downloadstring = "DownloadString(" nocase
        $invoke_webrequest = "Invoke-WebRequest" nocase
        $hidden_window = "-WindowStyle Hidden" nocase
    condition:
        $iex_webclient or $downloadstring or ($invoke_webrequest and $hidden_window)
}
