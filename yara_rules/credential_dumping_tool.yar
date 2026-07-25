rule Mimikatz_Strings
{
    meta:
        description = "Detects strings associated with the Mimikatz credential dumping tool"
        severity = "critical"
        mitre_id = "T1003"
        author = "SOCShield"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "gentilkiwi" nocase
        $s3 = "mimikatz" nocase
        $s4 = "Benjamin Delpy" nocase
    condition:
        any of them
}
