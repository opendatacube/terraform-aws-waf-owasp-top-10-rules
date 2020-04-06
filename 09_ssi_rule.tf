# Regional
####################
## OWASP Top 10 A9
### Server-side includes & libraries in webroot
### Matches request patterns for webroot objects that shouldn't be directly accessible
resource "aws_wafregional_byte_match_set" "owasp_09_server_side_include_string_set" {
  count = lower(var.target_scope) == "regional" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-09-match-ssi-${random_id.this.0.hex}"

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".cfg"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".conf"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".config"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".ini"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".log"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".bak"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".backup"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }
}

resource "aws_wafregional_rule" "owasp_09_server_side_include_rule" {
  depends_on = [aws_wafregional_byte_match_set.owasp_09_server_side_include_string_set]

  count = lower(var.target_scope) == "regional" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-09-detect-ssi-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP09DetectSSI${random_id.this.0.hex}"

  predicate {
    data_id = aws_wafregional_byte_match_set.owasp_09_server_side_include_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }
}

# Global
####################
## OWASP Top 10 A9
### Server-side includes & libraries in webroot
### Matches request patterns for webroot objects that shouldn't be directly accessible
resource "aws_waf_byte_match_set" "owasp_09_server_side_include_string_set" {
  count = lower(var.target_scope) == "global" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-09-match-ssi-${random_id.this.0.hex}"

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".cfg"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".conf"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".config"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".ini"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".log"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".bak"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".backup"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }
}

resource "aws_waf_rule" "owasp_09_server_side_include_rule" {
  depends_on = [aws_waf_byte_match_set.owasp_09_server_side_include_string_set]

  count = lower(var.target_scope) == "global" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-09-detect-ssi-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP09DetectSSI${random_id.this.0.hex}"

  predicates {
    data_id = aws_waf_byte_match_set.owasp_09_server_side_include_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }
}