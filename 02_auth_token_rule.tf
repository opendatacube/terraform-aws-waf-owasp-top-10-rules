# Regional
####################
## OWASP Top 10 A2
### Blacklist bad/hijacked JWT tokens or session IDs
### Matches the specific values in the cookie or Authorization header for JWT it is sufficient to check the signature
resource "aws_wafregional_byte_match_set" "owasp_02_auth_token_string_set" {
  count = lower(var.target_scope) == "regional" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-02-match-auth-token-${random_id.this.0.hex}"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "example-session-id"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "HEADER"
      data = "cookie"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = ".TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "HEADER"
      data = "authorization"
    }
  }
}

resource "aws_wafregional_rule" "owasp_02_auth_token_rule" {
  depends_on = [aws_wafregional_byte_match_set.owasp_02_auth_token_string_set]

  count = lower(var.target_scope) == "regional" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-02-detect-bad-auth-token-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP02BadAuthToken${random_id.this.0.hex}"

  predicate {
    data_id = aws_wafregional_byte_match_set.owasp_02_auth_token_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }
}

# Global
####################
## OWASP Top 10 A2
### Blacklist bad/hijacked JWT tokens or session IDs
### Matches the specific values in the cookie or Authorization header for JWT it is sufficient to check the signature
resource "aws_waf_byte_match_set" "owasp_02_auth_token_string_set" {
  count = lower(var.target_scope) == "global" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-02-match-auth-token-${random_id.this.0.hex}"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "example-session-id"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "HEADER"
      data = "cookie"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = ".TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "HEADER"
      data = "authorization"
    }
  }
}

resource "aws_waf_rule" "owasp_02_auth_token_rule" {
  depends_on = [aws_waf_byte_match_set.owasp_02_auth_token_string_set]

  count = lower(var.target_scope) == "global" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-02-detect-bad-auth-token-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP02BadAuthToken${random_id.this.0.hex}"

  predicates {
    data_id = aws_waf_byte_match_set.owasp_02_auth_token_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }
}