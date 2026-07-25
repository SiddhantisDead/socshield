rule EICAR_Antivirus_Test_File
{
    meta:
        description = "Detects the industry-standard EICAR antivirus test string (not real malware - safe to use for testing scanners)"
        severity = "medium"
        mitre_id = ""
        author = "SOCShield"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
