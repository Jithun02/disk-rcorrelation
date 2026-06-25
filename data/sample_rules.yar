rule Suspicious_PowerShell
{
    meta:
        author = "CORE"
        description = "Flags encoded command usage"
        severity = "medium"
    strings:
        $a = "powershell -enc" nocase
        $b = "IEX(" nocase
    condition:
        any of them
}

rule Suspicious_Mimikatz_Keyword
{
    meta:
        author = "CORE"
        description = "Simple Mimikatz keyword indicator"
        severity = "high"
    strings:
        $a = "sekurlsa::logonpasswords" nocase
        $b = "mimikatz" nocase
    condition:
        any of them
}
