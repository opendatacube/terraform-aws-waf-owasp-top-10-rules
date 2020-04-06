# Random ID Generator

resource "random_id" "this" {
  count = lower(var.target_scope) == "regional" || lower(var.target_scope) == "global" ? 1 : 0

  byte_length = "8"

  keepers = {
    target_scope = lower(var.target_scope)
  }
}

## RULES CURRENTLY NOT IMPLEMENTED
# Regional
####################
## OWASP Top 10 A5
## Privileged Module Access Restrictions
## Restrict access to the admin interface to known source IPs only
## Matches the URI prefix, when the remote IP isn't in the whitelist

## 10. ## Generic
### IP Blacklist
### Matches IP addresses that should not be allowed to access content
### CURRENTLY NOT APPLICABLE

# Global
####################
## OWASP Top 10 A5
## Privileged Module Access Restrictions
## Restrict access to the admin interface to known source IPs only
## Matches the URI prefix, when the remote IP isn't in the whitelist
## CURRENTLY NOT APPLICABLE

## 10. ## Generic
### IP Blacklist
### Matches IP addresses that should not be allowed to access content
### CURRENTLY NOT APPLICABLE


## Regional - RuleGroup
resource "aws_wafregional_rule_group" "owasp_top_10" {
  depends_on = [
    "aws_wafregional_rule.owasp_01_sql_injection_rule",
    "aws_wafregional_rule.owasp_02_auth_token_rule",
    "aws_wafregional_rule.owasp_03_xss_rule",
    "aws_wafregional_rule.owasp_04_paths_rule",
    "aws_wafregional_rule.owasp_06_php_insecure_rule",
    "aws_wafregional_rule.owasp_07_size_restriction_rule",
    "aws_wafregional_rule.owasp_08_csrf_rule",
    "aws_wafregional_rule.owasp_09_server_side_include_rule",
  ]

  count = lower(var.create_rule_group) && lower(var.target_scope) == "regional" ? 1 : 0

  name        = format("%s-owasp-top-10-%s", lower(var.waf_prefix), random_id.this.0.hex)
  metric_name = format("%sOWASPTop10%s", lower(var.waf_prefix), random_id.this.0.hex)

  activated_rule {
    action {
      type = var.rule_07_size_restriction_action_type
    }

    priority = "1"
    rule_id  = aws_wafregional_rule.owasp_07_size_restriction_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_02_auth_tokens_action_type
    }

    priority = "2"
    rule_id  = aws_wafregional_rule.owasp_02_auth_token_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_01_sql_injection_action_type
    }

    priority = "3"
    rule_id  = aws_wafregional_rule.owasp_01_sql_injection_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_03_xss_action_type
    }

    priority = "4"
    rule_id  = aws_wafregional_rule.owasp_03_xss_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_04_lfi_rfi_paths_action_type
    }

    priority = "5"
    rule_id  = aws_wafregional_rule.owasp_04_paths_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_06_php_insecure_action_type
    }

    priority = "6"
    rule_id  = aws_wafregional_rule.owasp_06_php_insecure_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_08_csrf_action_type
    }

    priority = "7"
    rule_id  = aws_wafregional_rule.owasp_08_csrf_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_09_ssi_action_type
    }

    priority = "8"
    rule_id  = aws_wafregional_rule.owasp_09_server_side_include_rule.0.id
    type     = "REGULAR"
  }
}

## Global - RuleGroup
resource "aws_waf_rule_group" "owasp_top_10" {
  depends_on = [
    "aws_waf_rule.owasp_01_sql_injection_rule",
    "aws_waf_rule.owasp_02_auth_token_rule",
    "aws_waf_rule.owasp_03_xss_rule",
    "aws_waf_rule.owasp_04_paths_rule",
    "aws_waf_rule.owasp_06_php_insecure_rule",
    "aws_waf_rule.owasp_07_size_restriction_rule",
    "aws_waf_rule.owasp_08_csrf_rule",
    "aws_waf_rule.owasp_09_server_side_include_rule",
  ]

  count = lower(var.create_rule_group) && lower(var.target_scope) == "global" ? 1 : 0

  name        = format("%s-owasp-top-10-%s", lower(var.waf_prefix), random_id.this.0.hex)
  metric_name = format("%sOWASPTop10%s", lower(var.waf_prefix), random_id.this.0.hex)

  activated_rule {
    action {
      type = var.rule_07_size_restriction_action_type
    }

    priority = "1"
    rule_id  = aws_waf_rule.owasp_07_size_restriction_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_02_auth_tokens_action_type
    }

    priority = "2"
    rule_id  = aws_waf_rule.owasp_02_auth_token_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_01_sql_injection_action_type
    }

    priority = "3"
    rule_id  = aws_waf_rule.owasp_01_sql_injection_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_03_xss_action_type
    }

    priority = "4"
    rule_id  = aws_waf_rule.owasp_03_xss_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_04_lfi_rfi_paths_action_type
    }

    priority = "5"
    rule_id  = aws_waf_rule.owasp_04_paths_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_06_php_insecure_action_type
    }

    priority = "6"
    rule_id  = aws_waf_rule.owasp_06_php_insecure_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_08_csrf_action_type
    }

    priority = "7"
    rule_id  = aws_waf_rule.owasp_08_csrf_rule.0.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_09_ssi_action_type
    }

    priority = "8"
    rule_id  = aws_waf_rule.owasp_09_server_side_include_rule.0.id
    type     = "REGULAR"
  }
}
