# Regional
####################
## OWASP Top 10 A6
## PHP Specific Security Misconfigurations
## Matches request patterns designed to exploit insecure PHP/CGI configuration
resource "aws_wafregional_byte_match_set" "owasp_06_php_insecure_qs_string_set" {
  count = lower(var.target_scope) == "regional" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-06-match-php-insecure-var-refs-${random_id.this.0.hex}"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "_SERVER["
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "_ENV["
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "auto_prepend_file="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "auto_append_file="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "allow_url_include="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "disable_functions="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "open_basedir="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "safe_mode="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }
}

resource "aws_wafregional_byte_match_set" "owasp_06_php_insecure_uri_string_set" {
  count = lower(var.target_scope) == "regional" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-06-match-php-insecure-uri-${random_id.this.0.hex}"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "php"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "/"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }
}

resource "aws_wafregional_rule" "owasp_06_php_insecure_rule" {
  depends_on = [aws_wafregional_byte_match_set.owasp_06_php_insecure_qs_string_set, aws_wafregional_byte_match_set.owasp_06_php_insecure_uri_string_set]

  count = lower(var.target_scope) == "regional" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-06-detect-php-insecure-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP06DetectPHPInsecure${random_id.this.0.hex}"

  predicate {
    data_id = aws_wafregional_byte_match_set.owasp_06_php_insecure_qs_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }

  predicate {
    data_id = aws_wafregional_byte_match_set.owasp_06_php_insecure_uri_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }
}

# Global
####################
## OWASP Top 10 A6
## PHP Specific Security Misconfigurations
## Matches request patterns designed to exploit insecure PHP/CGI configuration
resource "aws_waf_byte_match_set" "owasp_06_php_insecure_qs_string_set" {
  count = lower(var.target_scope) == "global" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-06-match-php-insecure-var-refs-${random_id.this.0.hex}"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "_SERVER["
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "_ENV["
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "auto_prepend_file="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "auto_append_file="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "allow_url_include="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "disable_functions="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "open_basedir="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "safe_mode="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }
}

resource "aws_waf_byte_match_set" "owasp_06_php_insecure_uri_string_set" {
  count = lower(var.target_scope) == "global" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-06-match-php-insecure-uri-${random_id.this.0.hex}"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "php"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "/"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }
}

resource "aws_waf_rule" "owasp_06_php_insecure_rule" {
  depends_on = [aws_waf_byte_match_set.owasp_06_php_insecure_qs_string_set, aws_waf_byte_match_set.owasp_06_php_insecure_uri_string_set]

  count = lower(var.target_scope) == "global" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-06-detect-php-insecure-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP06DetectPHPInsecure${random_id.this.0.hex}"

  predicates {
    data_id = aws_waf_byte_match_set.owasp_06_php_insecure_qs_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }

  predicates {
    data_id = aws_waf_byte_match_set.owasp_06_php_insecure_uri_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }
}