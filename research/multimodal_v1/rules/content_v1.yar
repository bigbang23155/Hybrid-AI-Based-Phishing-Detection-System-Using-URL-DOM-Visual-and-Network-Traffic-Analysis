/* Lexical co-occurrence signals only. No rule proves execution or phishing. */
rule CF_Decode_And_Eval_v1 : content_signal obfuscation {
    meta:
        version = "1"
        meaning = "Decode and evaluation tokens co-occur; comments and benign code may match"
    strings:
        $decode1 = "atob" ascii nocase fullword
        $decode2 = "fromCharCode" ascii nocase fullword
        $eval = "eval" ascii nocase fullword
    condition:
        any of ($decode*) and $eval
}

rule CF_Packed_JavaScript_v1 : content_signal obfuscation {
    meta:
        version = "1"
        meaning = "Common packer-shaped lexical sequence; legitimate libraries may match"
    strings:
        $packer = /eval[ \t\r\n]*\([ \t\r\n]*function[ \t\r\n]*\([ \t\r\n]*p[ \t]*,[ \t]*a[ \t]*,[ \t]*c[ \t]*,[ \t]*k/ ascii
    condition:
        $packer
}

rule CF_Encoded_HTML_v1 : content_signal encoding {
    meta:
        version = "1"
        meaning = "Data URI declares base64 HTML; may be an embedded benign document"
    strings:
        $data = /data:text\/html[ \t]*;[ \t]*base64[ \t]*,/ ascii nocase
    condition:
        $data
}

rule CF_Decode_And_Write_v1 : content_signal encoding {
    meta:
        version = "1"
        meaning = "Decoder and document.write tokens co-occur; no data-flow claim"
    strings:
        $decode1 = "atob" ascii nocase fullword
        $decode2 = "unescape" ascii nocase fullword
        $write = /document[ \t\r\n]*\.[ \t\r\n]*write[ \t\r\n]*\(/ ascii
    condition:
        any of ($decode*) and $write
}
