// A harmless deterministic fixture, not a broad malware intelligence feed.
rule Aegis_Harmless_Self_Test {
    meta:
        description = "Aegis engine integration self-test; no executable code"
    strings:
        $marker = "AEGIS-ENGINE-SELF-TEST"
    condition:
        filesize < 128 and $marker at 0
}
