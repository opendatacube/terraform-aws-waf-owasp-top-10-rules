# Regional
####################
## OWASP Top 10 A3
### Mitigate Cross Site Scripting Attacks
### Matches attempted XSS patterns in the URI, QUERY_STRING, BODY, COOKIES
resource "aws_wafregional_xss_match_set" "owasp_03_xss_set" {
  count = lower(var.target_scope) == "regional" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-03-detect-xss-${random_id.this.0.hex}"

  dynamic "xss_match_tuple" {
    for_each = var.disable_03_uri_url_decode ? [] : [1]
    content {
      text_transformation = "URL_DECODE"

      field_to_match {
        type = "URI"
      }
    }
  }

  dynamic "xss_match_tuple" {
    for_each = var.disable_03_uri_html_decode ? [] : [1]
    content {
      text_transformation = "HTML_ENTITY_DECODE"

      field_to_match {
        type = "URI"
      }
    }
  }

  dynamic "xss_match_tuple" {
    for_each = var.disable_03_query_string_url_decode ? [] : [1]
    content {
      text_transformation = "URL_DECODE"

      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }

  dynamic "xss_match_tuple" {
    for_each = var.disable_03_query_string_html_decode ? [] : [1]
    content {
      text_transformation = "HTML_ENTITY_DECODE"

      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }

  dynamic "xss_match_tuple" {
    for_each = var.disable_03_body_url_decode ? [] : [1]
    content {
      text_transformation = "URL_DECODE"

      field_to_match {
        type = "BODY"
      }
    }
  }

  dynamic "xss_match_tuple" {
    for_each = var.disable_03_body_html_decode ? [] : [1]
    content {
      text_transformation = "HTML_ENTITY_DECODE"

      field_to_match {
        type = "BODY"
      }
    }
  }

  dynamic "xss_match_tuple" {
    for_each = var.disable_03_cookie_url_decode ? [] : [1]
    content {
      text_transformation = "URL_DECODE"

      field_to_match {
        type = "HEADER"
        data = "cookie"
      }
    }
  }

  dynamic "xss_match_tuple" {
    for_each = var.disable_03_cookie_html_decode ? [] : [1]
    content {
      text_transformation = "HTML_ENTITY_DECODE"

      field_to_match {
        type = "HEADER"
        data = "cookie"
      }
    }
  }
}

resource "aws_wafregional_rule" "owasp_03_xss_rule" {
  depends_on = [aws_wafregional_xss_match_set.owasp_03_xss_set]

  count = lower(var.target_scope) == "regional" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-03-mitigate-xss-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP03MitigateXSS${random_id.this.0.hex}"

  predicate {
    data_id = aws_wafregional_xss_match_set.owasp_03_xss_set.0.id
    negated = "false"
    type    = "XssMatch"
  }
}

# Global
####################
## OWASP Top 10 A3
### Mitigate Cross Site Scripting Attacks
### Matches attempted XSS patterns in the URI, QUERY_STRING, BODY, COOKIES
resource "aws_waf_xss_match_set" "owasp_03_xss_set" {
  count = lower(var.target_scope) == "global" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-03-detect-xss-${random_id.this.0.hex}"

  dynamic "xss_match_tuples" {
    for_each = var.disable_03_uri_url_decode ? [] : [1]
    content {
      text_transformation = "URL_DECODE"

      field_to_match {
        type = "URI"
      }
    }
  }

  dynamic "xss_match_tuples" {
    for_each = var.disable_03_uri_html_decode ? [] : [1]
    content {
      text_transformation = "HTML_ENTITY_DECODE"

      field_to_match {
        type = "URI"
      }
    }
  }

  dynamic "xss_match_tuples" {
    for_each = var.disable_03_query_string_url_decode ? [] : [1]
    content {
      text_transformation = "URL_DECODE"

      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }

  dynamic "xss_match_tuples" {
    for_each = var.disable_03_query_string_html_decode ? [] : [1]
    content {
      text_transformation = "HTML_ENTITY_DECODE"

      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }

  dynamic "xss_match_tuples" {
    for_each = var.disable_03_body_url_decode ? [] : [1]
    content {
      text_transformation = "URL_DECODE"

      field_to_match {
        type = "BODY"
      }
    }
  }

  dynamic "xss_match_tuples" {
    for_each = var.disable_03_body_html_decode ? [] : [1]
    content {
      text_transformation = "HTML_ENTITY_DECODE"

      field_to_match {
        type = "BODY"
      }
    }
  }

  dynamic "xss_match_tuples" {
    for_each = var.disable_03_cookie_url_decode ? [] : [1]
    content {
      text_transformation = "URL_DECODE"

      field_to_match {
        type = "HEADER"
        data = "cookie"
      }
    }
  }

  dynamic "xss_match_tuples" {
    for_each = var.disable_03_cookie_html_decode ? [] : [1]
    content {
      text_transformation = "HTML_ENTITY_DECODE"

      field_to_match {
        type = "HEADER"
        data = "cookie"
      }
    }
  }
}

resource "aws_waf_rule" "owasp_03_xss_rule" {
  depends_on = [aws_waf_xss_match_set.owasp_03_xss_set]

  count = lower(var.target_scope) == "global" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-03-mitigate-xss-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP03MitigateXSS${random_id.this.0.hex}"

  predicates {
    data_id = aws_waf_xss_match_set.owasp_03_xss_set.0.id
    negated = "false"
    type    = "XssMatch"
  }
}