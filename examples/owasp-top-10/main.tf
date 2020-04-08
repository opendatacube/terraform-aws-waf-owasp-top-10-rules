module "owasp_top_10_rules" {
  source = "git::https://github.com/opendatacube/terraform-aws-waf-owasp-top-10-rules.git?ref=waf-module-enhancement"

  owner          = "odc-test"
  namespace      = "odc-test"
  environment    = "stage"
  waf_prefix     = "wafowasp"

  target_scope      = "regional"
  create_rule_group = "true"

  max_expected_uri_size          = "512"
  max_expected_query_string_size = "1024"
  max_expected_body_size         = "4096"
  max_expected_cookie_size       = "4093"

  csrf_expected_header = "x-csrf-token"
  csrf_expected_size   = "36"

  # NOTE: variables to set rules allow type. Deafult is set to `"BLOCK"` for all the rules.
  #   Allow values are - BLOCK, ALLOW and COUNT.
  rule_01_sql_injection_action_type    = "BLOCK"
  rule_02_auth_tokens_action_type      = "BLOCK"
  rule_03_xss_action_type              = "BLOCK"
  rule_04_lfi_rfi_paths_action_type    = "BLOCK"
  rule_06_php_insecure_action_type     = "BLOCK"
  rule_07_size_restriction_action_type = "BLOCK"
  rule_08_csrf_action_type             = "BLOCK"
  rule_09_ssi_action_type              = "BLOCK"

  # NOTE: variables to manage cross-site scripting filters. Deafult is set to `false`.
  disable_03_uri_url_decode           = false
  disable_03_uri_html_decode          = false
  disable_03_query_string_url_decode  = false
  disable_03_query_string_html_decode = false
  disable_03_body_url_decode          = false
  disable_03_body_html_decode         = false
  disable_03_cookie_url_decode        = false
  disable_03_cookie_html_decode       = false

  # NOTE: variables to manage dangerous HTTP request patterns filters, e.g. path traversal attempts. Deafult is set to `false`.
  disable_04_uri_contains_previous_dir_after_url_decode           = false
  disable_04_uri_contains_previous_dir_after_html_decode          = false
  disable_04_query_string_contains_previous_dir_after_url_decode  = false
  disable_04_query_string_contains_previous_dir_after_html_decode = false
  disable_04_uri_contains_url_path_after_url_decode               = false
  disable_04_uri_contains_url_path_after_html_decode              = false
  disable_04_query_string_contains_url_path_after_url_decode      = false
  disable_04_query_string_contains_url_path_after_html_decode     = false
}
