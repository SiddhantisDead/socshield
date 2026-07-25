rule PHP_Webshell_Generic
{
    meta:
        description = "Detects generic PHP webshell patterns: eval of decoded input or shell exec via user-controlled superglobals"
        severity = "critical"
        mitre_id = "T1505.003"
        author = "SOCShield"
    strings:
        $eval_b64 = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $eval_post = /eval\s*\(\s*\$_(POST|GET|REQUEST)\[/ nocase
        $shell_exec = /(system|shell_exec|passthru)\s*\(\s*\$_(POST|GET|REQUEST)\[/ nocase
        $assert_call = /assert\s*\(\s*\$_(POST|GET|REQUEST)\[/ nocase
    condition:
        any of them
}
