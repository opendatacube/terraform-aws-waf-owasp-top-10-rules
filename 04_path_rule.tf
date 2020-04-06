# Regional
####################
## OWASP Top 10 A4
### Path Traversal, LFI, RFI
### Matches request patterns designed to traverse filesystem paths, and include local or remote files
resource "aws_wafregional_byte_match_set" "owasp_04_paths_string_set" {
  count = lower(var.target_scope) == "regional" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-04-match-rfi-lfi-traversal-${random_id.this.0.hex}"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }
}

resource "aws_wafregional_rule" "owasp_04_paths_rule" {
  depends_on = [aws_wafregional_byte_match_set.owasp_04_paths_string_set]

  count = lower(var.target_scope) == "regional" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-04-detect-rfi-lfi-traversal-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP04DetectRFILFITraversal${random_id.this.0.hex}"

  predicate {
    data_id = aws_wafregional_byte_match_set.owasp_04_paths_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }
}

# Global
####################
## OWASP Top 10 A4
### Path Traversal, LFI, RFI
### Matches request patterns designed to traverse filesystem paths, and include local or remote files
resource "aws_waf_byte_match_set" "owasp_04_paths_string_set" {
  count = lower(var.target_scope) == "global" ? 1 : 0

  name = "${lower(var.waf_prefix)}-owasp-04-match-rfi-lfi-traversal-${random_id.this.0.hex}"

  dynamic "byte_match_tuples" {
    for_each = var.disable_04_uri_contains_previous_dir_after_url_decode ? [] : [1]
    content {
      text_transformation   = "URL_DECODE"
      target_string         = "../"
      positional_constraint = "CONTAINS"

      field_to_match {
        type = "URI"
      }
    }
  }

  dynamic "byte_match_tuples" {
    for_each = var.disable_04_uri_contains_previous_dir_after_html_decode ? [] : [1]
    content {
      text_transformation   = "HTML_ENTITY_DECODE"
      target_string         = "../"
      positional_constraint = "CONTAINS"

      field_to_match {
        type = "URI"
      }
    }
  }

  dynamic "byte_match_tuples" {
    for_each = var.disable_04_query_string_contains_previous_dir_after_url_decode ? [] : [1]
    content {
      text_transformation   = "URL_DECODE"
      target_string         = "../"
      positional_constraint = "CONTAINS"

      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }

  dynamic "byte_match_tuples" {
    for_each = var.disable_04_query_string_contains_previous_dir_after_html_decode ? [] : [1]
    content {
      text_transformation   = "HTML_ENTITY_DECODE"
      target_string         = "../"
      positional_constraint = "CONTAINS"

      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }

  dynamic "byte_match_tuples" {
    for_each = var.disable_04_uri_contains_url_path_after_url_decode ? [] : [1]
    content {
      text_transformation   = "URL_DECODE"
      target_string         = "://"
      positional_constraint = "CONTAINS"

      field_to_match {
        type = "URI"
      }
    }
  }

  dynamic "byte_match_tuples" {
    for_each = var.disable_04_uri_contains_url_path_after_html_decode ? [] : [1]
    content {
      text_transformation   = "HTML_ENTITY_DECODE"
      target_string         = "://"
      positional_constraint = "CONTAINS"

      field_to_match {
        type = "URI"
      }
    }
  }

  dynamic "byte_match_tuples" {
    for_each = var.disable_04_query_string_contains_url_path_after_url_decode ? [] : [1]
    content {
      text_transformation   = "URL_DECODE"
      target_string         = "://"
      positional_constraint = "CONTAINS"

      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }

  dynamic "byte_match_tuples" {
    for_each = var.disable_04_query_string_contains_url_path_after_html_decode ? [] : [1]
    content {
      text_transformation   = "HTML_ENTITY_DECODE"
      target_string         = "://"
      positional_constraint = "CONTAINS"

      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }
}

resource "aws_waf_rule" "owasp_04_paths_rule" {
  depends_on = [aws_waf_byte_match_set.owasp_04_paths_string_set]

  count = lower(var.target_scope) == "global" ? 1 : 0

  name        = "${lower(var.waf_prefix)}-owasp-04-detect-rfi-lfi-traversal-${random_id.this.0.hex}"
  metric_name = "${lower(var.waf_prefix)}OWASP04DetectRFILFITraversal${random_id.this.0.hex}"

  predicates {
    data_id = aws_waf_byte_match_set.owasp_04_paths_string_set.0.id
    negated = "false"
    type    = "ByteMatch"
  }
}