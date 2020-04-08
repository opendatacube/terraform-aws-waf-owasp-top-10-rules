# Regional
####################
## OWASP Top 10 A1
### Mitigate SQL Injection Attacks
### Matches attempted SQLi patterns in the URI, QUERY_STRING, BODY, COOKIES
resource "aws_wafregional_sql_injection_match_set" "owasp_01_sql_injection_set" {
  count = lower(var.target_scope) == "regional" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-01-detect-sql-injection-${random_id.this.0.hex}"

  sql_injection_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "HEADER"
      data = "Authorization"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "HEADER"
      data = "Authorization"
    }
  }
}

resource "aws_wafregional_rule" "owasp_01_sql_injection_rule" {
  depends_on = [aws_wafregional_sql_injection_match_set.owasp_01_sql_injection_set, aws_wafregional_byte_match_set.url_whitelist_string_set]

  count = lower(var.target_scope) == "regional" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-01-mitigate-sql-injection-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP01MitigateSQLInjection${random_id.this.0.hex}"

  predicate {
    data_id = aws_wafregional_sql_injection_match_set.owasp_01_sql_injection_set.0.id
    negated = "false"
    type    = "SqlInjectionMatch"
  }

  predicate {
    data_id = aws_wafregional_byte_match_set.url_whitelist_string_set.0.id
    negated = "true"
    type    = "ByteMatch"
  }
}

# Global
####################
## OWASP Top 10 A1
### Mitigate SQL Injection Attacks
### Matches attempted SQLi patterns in the URI, QUERY_STRING, BODY, COOKIES
resource "aws_waf_sql_injection_match_set" "owasp_01_sql_injection_set" {
  count = lower(var.target_scope) == "global" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-01-detect-sql-injection-${random_id.this.0.hex}"

  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "HEADER"
      data = "Authorization"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "HEADER"
      data = "Authorization"
    }
  }
}

resource "aws_waf_rule" "owasp_01_sql_injection_rule" {
  count = lower(var.target_scope) == "global" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-01-mitigate-sql-injection-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP01MitigateSQLInjection${random_id.this.0.hex}"

  predicates {
    data_id = aws_waf_sql_injection_match_set.owasp_01_sql_injection_set.0.id
    negated = "false"
    type    = "SqlInjectionMatch"
  }
}