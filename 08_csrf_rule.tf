# Regional
####################
## OWASP Top 10 A8
### CSRF token enforcement example
### Enforce the presence of CSRF token in request header
resource "aws_wafregional_byte_match_set" "owasp_08_csrf_method_string_set" {
  count = lower(var.target_scope) == "regional" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-08-match-csrf-method-${random_id.this.0.hex}"

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = "post"
    positional_constraint = "EXACTLY"

    field_to_match {
      type = "METHOD"
    }
  }
}

resource "aws_wafregional_size_constraint_set" "owasp_08_csrf_token_size_constrain_set" {
  count = lower(var.target_scope) == "regional" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-08-csrf-token-size-${random_id.this.0.hex}"

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "EQ"
    size                = var.csrf_expected_size

    field_to_match {
      type = "HEADER"
      data = var.csrf_expected_header
    }
  }
}

resource "aws_wafregional_rule" "owasp_08_csrf_rule" {
  depends_on = [aws_wafregional_byte_match_set.owasp_08_csrf_method_string_set, aws_wafregional_size_constraint_set.owasp_08_csrf_token_size_constrain_set]

  count = lower(var.target_scope) == "regional" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-08-enforce-csrf-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP08EnforceCSRF${random_id.this.0.hex}"

  predicate {
    data_id = aws_wafregional_byte_match_set.owasp_08_csrf_method_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }

  predicate {
    data_id = aws_wafregional_size_constraint_set.owasp_08_csrf_token_size_constrain_set.0.id
    negated = "false"
    type    = "SizeConstraint"
  }
}

# Global
####################
## OWASP Top 10 A8
### CSRF token enforcement example
### Enforce the presence of CSRF token in request header
resource "aws_waf_byte_match_set" "owasp_08_csrf_method_string_set" {
  count = lower(var.target_scope) == "global" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-08-match-csrf-method-${random_id.this.0.hex}"

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = "post"
    positional_constraint = "EXACTLY"

    field_to_match {
      type = "METHOD"
    }
  }
}

resource "aws_waf_size_constraint_set" "owasp_08_csrf_token_size_constrain_set" {
  count = lower(var.target_scope) == "global" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-08-csrf-token-size-${random_id.this.0.hex}"

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "EQ"
    size                = var.csrf_expected_size

    field_to_match {
      type = "HEADER"
      data = var.csrf_expected_header
    }
  }
}

resource "aws_waf_rule" "owasp_08_csrf_rule" {
  depends_on = [aws_waf_byte_match_set.owasp_08_csrf_method_string_set, aws_waf_size_constraint_set.owasp_08_csrf_token_size_constrain_set]

  count = lower(var.target_scope) == "global" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-08-enforce-csrf-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP08EnforceCSRF${random_id.this.0.hex}"

  predicates {
    data_id = aws_waf_byte_match_set.owasp_08_csrf_method_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }

  predicates {
    data_id = aws_waf_size_constraint_set.owasp_08_csrf_token_size_constrain_set.0.id
    negated = "false"
    type    = "SizeConstraint"
  }
}