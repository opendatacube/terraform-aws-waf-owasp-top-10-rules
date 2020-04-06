# Regional
####################
## OWASP Top 10 A7
### Mitigate abnormal requests via size restrictions
### Enforce consistent request hygene, limit size of key elements
resource "aws_wafregional_size_constraint_set" "owasp_07_size_restriction_set" {
  count = lower(var.target_scope) == "regional" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-07-size-restrictions-${random_id.this.0.hex}"

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_uri_size

    field_to_match {
      type = "URI"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_query_string_size

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_body_size

    field_to_match {
      type = "BODY"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_cookie_size

    field_to_match {
      type = "HEADER"
      data = "cookie"
    }
  }
}

resource "aws_wafregional_rule" "owasp_07_size_restriction_rule" {
  depends_on = [aws_wafregional_size_constraint_set.owasp_07_size_restriction_set]

  count = lower(var.target_scope) == "regional" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-07-restrict-sizes-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP07RestrictSizes${random_id.this.0.hex}"

  predicate {
    data_id = aws_wafregional_size_constraint_set.owasp_07_size_restriction_set.0.id
    negated = "false"
    type    = "SizeConstraint"
  }
}

# Global
####################
## OWASP Top 10 A7
### Mitigate abnormal requests via size restrictions
### Enforce consistent request hygene, limit size of key elements
resource "aws_waf_size_constraint_set" "owasp_07_size_restriction_set" {
  count = lower(var.target_scope) == "global" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-07-size-restrictions-${random_id.this.0.hex}"

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_uri_size

    field_to_match {
      type = "URI"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_query_string_size

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_body_size

    field_to_match {
      type = "BODY"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_cookie_size

    field_to_match {
      type = "HEADER"
      data = "cookie"
    }
  }
}

resource "aws_waf_rule" "owasp_07_size_restriction_rule" {
  depends_on = [aws_waf_size_constraint_set.owasp_07_size_restriction_set]

  count = lower(var.target_scope) == "global" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-07-restrict-sizes-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP07RestrictSizes${random_id.this.0.hex}"

  predicates {
    data_id = aws_waf_size_constraint_set.owasp_07_size_restriction_set.0.id
    negated = "false"
    type    = "SizeConstraint"
  }
}