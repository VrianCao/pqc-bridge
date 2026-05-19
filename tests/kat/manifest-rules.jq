def present_string:
  type == "string" and length > 0;

def present_object:
  type == "object" and length > 0;

def valid_case:
  (.id | present_string)
  and (.type == "positive" or .type == "negative")
  and (.operation | present_string)
  and (.expected == "success"
       or .expected == "invalid-length"
       or .expected == "verification-failed"
       or .expected == "crypto-failure"
       or .expected == "changed-secret")
  and (.inputs | type == "object")
  and (.outputs | type == "object");

type == "object"
and .schema_version == "1"
and (.algorithm | present_string)
and (.parameter_set | present_string)
and (.upstream | present_object)
and (.upstream.name | present_string)
and (.upstream.repository | present_string)
and (.upstream.version | present_string)
and (.source | present_object)
and (.source.name | present_string)
and (.source.url | present_string)
and (.source.license | present_string)
and (.source.redistribution | present_string)
and (.generation | present_object)
and (.generation.method == "upstream"
     or .generation.method == "nist-acvp"
     or .generation.method == "wycheproof"
     or .generation.method == "project-generated"
     or .generation.method == "manual-negative")
and (.generation.command | present_string)
and (.generation.date | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
and (.checksum | present_object)
and (.checksum.algorithm == "SHA-256")
and (.checksum.value | test("^[0-9a-f]{64}$"))
and (.cases | type == "array" and length > 0)
and all(.cases[]; valid_case)
