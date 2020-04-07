# Terraform | AWS WAF | OWASP Top 10 vulnerabilities

## IMPORTANT CONSIDERATIONS
1. The original source was taken from https://github.com/masterpointio/terraform-aws-waf-owasp-top-10-rules and was adapted to the needs of the project at hand.

2. **MODULE USE CASE**
    * **Global WAF** for CloudFront usage
    * **Regional WAF** for ALB usage

## Use AWS WAF at terraform to Mitigate OWASP’s Top 10 Web Application Vulnerabilities
OWASP Top 10 Most Critical Web Application Security Risks is a powerful awareness document for web application security. It represents a broad consensus about the most critical security risks to web applications. Project members include a variety of security experts from around the world who have shared their expertise to produce this list[[1]](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project). You can read the document that they published here: [[2]](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf).

This is a Terraform module which creates AWF WAF resources for protection of your resources from the OWASP Top 10 Security Risks. This module is based on the whitepaper that AWS provides. The whitepaper tells how to use AWS WAF to mitigate those attacks[[3]](https://d0.awsstatic.com/whitepapers/Security/aws-waf-owasp.pdf)[[4]](https://aws.amazon.com/about-aws/whats-new/2017/07/use-aws-waf-to-mitigate-owasps-top-10-web-application-vulnerabilities/).

This module will only create match-sets[[5]](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-create-condition.html), rules[[6]](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rules.html), and a rule group (optional)[[7]](https://docs.aws.amazon.com/waf/latest/developerguide/working-with-rule-groups.html).
Those resources cannot be used without WebACL[[8]](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-working-with.html), which is not covered by this module.

To see the example on how to provision the resources only, check [Examples](#examples) section.

But to see the example on how to use this module together with WebACL to fully protect your application, see this page: [[9]](https://github.com/traveloka/terraform-aws-waf-webacl-supporting-resources/tree/master/examples)

References
* [1] : https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project
* [2] : https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf
* [3] : https://d0.awsstatic.com/whitepapers/Security/aws-waf-owasp.pdf
* [4] : https://aws.amazon.com/about-aws/whats-new/2017/07/use-aws-waf-to-mitigate-owasps-top-10-web-application-vulnerabilities/
* [5] : https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-create-condition.html
* [6] : https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rules.html
* [7] : https://docs.aws.amazon.com/waf/latest/developerguide/working-with-rule-groups.html
* [8] : https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-working-with.html
* [9] : https://github.com/traveloka/terraform-aws-waf-webacl-supporting-resources/tree/master/examples

## FAQ
1. **Can I use only some of the rules?** 
- Yes you can. This module will outputs the rules' ID. Attach to WebACL you created only the IDs of the rules that you want.
2. **Can I provision only some of the rules?** 
- No you can't. Recommendation is to set rule action type to `COUNT` for testing in order to avoid service affection; when ready, set it to BLOCK.
3. **Can I modify some match-sets of a rule?** 
- No you can't. The same answer to answer question number 2. But if you found something need to be fixed, e.g. match-sets causing lots of false positive, please don't hesitate to create an issue or a pull request to this repository!
- We have enable variables to enable/disable match-sets for `XSS` and `Path Traversal, LFI, RFI`. Check [Inputs](#inputs) section below for more detail.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| owner | The owner of the environment | string |  | yes |
| namespace | The unique namespace for the environment, which could be your organization name or abbreviation, e.g. 'odc' | string |  | Yes |
| environment | The name of the environment - e.g. dev, stage | string |  | Yes |
| waf_prefix | Prefix to use when naming resources | string | `"wafowasp"`  | No |
| target_scope | Valid values are `global` and `regional`. If `global`, means resources created will be for global targets such as Amazon CloudFront distribution. For regional targets like ALBs and API Gateway stages, set to `regional` | string |  | Yes |
| create_rule_group | All rules can be grouped into a Rule Group. Unfortunately, AWS WAF Rule Group limit per region is only 3. By setting the value to `false` will not create the rule group | string | `"true"` | No |
| rule_01_sql_injection_action_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"BLOCK"` | No |
| rule_02_auth_tokens_action_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"BLOCK"` | No |
| rule_03_xss_action_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"BLOCK"` | No |
| rule_04_lfi_rfi_paths_action_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"BLOCK"` | No |
| rule_06_php_insecure_action_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"BLOCK"` | No |
| rule_07_size_restriction_action_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"BLOCK"` | No |
| rule_08_csrf_action_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"BLOCK"` | No |
| rule_09_ssi_action_type | Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing) | string | `"BLOCK"` | No |

## Optional Inputs:  

### Variables to adjust size restriction
| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| max_expected_uri_size | Maximum number of bytes allowed in the URI component of the HTTP request. Generally the maximum possible value is determined by the server operating system (maps to file system paths), the web server software, or other middleware components. Choose a value that accomodates the largest URI segment you use in practice in your web application | string | `"512"` | No |
| max_expected_query_string_size | Maximum number of bytes allowed in the query string component of the HTTP request. Normally the  of query string parameters following the ? in a URL is much larger than the URI , but still bounded by the  of the parameters your web application uses and their values | string | `"1024"` | No |
| max_expected_body_size | Maximum number of bytes allowed in the body of the request. If you do not plan to allow large uploads, set it to the largest payload value that makes sense for your web application. Accepting unnecessarily large values can cause performance issues, if large payloads are used as an attack vector against your web application | string | `"4096"` | No |
| max_expected_cookie_size | Maximum number of bytes allowed in the cookie header. The maximum size should be less than 4096, the size is determined by the amount of information your web application stores in cookies. If you only pass a session token via cookies, set the size to no larger than the serialized size of the session token and cookie metadata | string | `"4093"` | No |
| csrf_expected_header | The custom HTTP request header, where the CSRF token value is expected to be encountered | string | `"x-csrf-token"` | No |
| csrf_expected_size | The size in bytes of the CSRF token value. For example if it's a canonically formatted UUIDv4 value the expected size would be 36 bytes/ASCII characters | string | `"36"` | No |

### Variables to disable XSS and PATH filters
| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| disable_03_uri_url_decode | Disable the 'URI contains a cross-site scripting threat after decoding as URL.' filter | bool | `false` | No |
| disable_03_uri_html_decode | Disable the 'URI contains a cross-site scripting threat after decoding as HTML tags.' filter | bool | `false` | No |
| disable_03_query_string_url_decode | Disable the 'Query string contains a cross-site scripting threat after decoding as URL.' filter | bool | `false` | No |
| disable_03_query_string_html_decode | Disable the 'Query string contains a cross-site scripting threat after decoding as HTML tags.' filter | bool | `false` | No |
| disable_03_body_url_decode | Disable the 'Body contains a cross-site scripting threat after decoding as URL.' filter | bool | `false` | No |
| disable_03_body_html_decode | Disable the 'Body contains a cross-site scripting threat after decoding as HTML tags.' filter | bool | `false` | No |
| disable_03_cookie_url_decode | Disable the 'Header cookie contains a cross-site scripting threat after decoding as URL.' filter | bool | `false` | No |
| disable_03_cookie_html_decode | Disable the 'Header 'cookie' contains a cross-site scripting threat after decoding as HTML tags.' filter | bool | `false` | No |
| disable_04_uri_contains_previous_dir_after_url_decode | Disable the 'URI contains: '../' after decoding as URL.' filter | bool | `false` | No |
| disable_04_uri_contains_previous_dir_after_html_decode | Disable the 'URI contains: '../' after decoding as HTML tags.' filter | bool | `false` | No |
| disable_04_query_string_contains_previous_dir_after_url_decode | Disable the 'Query string contains: '../' after decoding as URL.' filter | bool | `false` | No |
| disable_04_query_string_contains_previous_dir_after_html_decode | Disable the 'Query string contains: '../' after decoding as HTML tags.' filter | bool | `false` | No |
| disable_04_uri_contains_url_path_after_url_decode | Disable the 'URI contains: '://' after decoding as URL.' filter | bool | `false` | No |
| disable_04_uri_contains_url_path_after_html_decode | Disable the 'URI contains: '://' after decoding as HTML tags.' filter | bool | `false` | No |
| disable_04_query_string_contains_url_path_after_url_decode | Disable the 'Query string contains: '://' after decoding as URL.' filter | bool | `false` | No |
| disable_04_query_string_contains_url_path_after_html_decode | Disable the 'Query string contains: '://' after decoding as HTML tags.' filter | bool | `false` | No |

### Variables to enable URL whitelist
| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| enable_url_whitelist_string_match_set | Enable the 'URL whitelisting' filter. If enabled, provide values for `url_whitelist_uri_prefix` and `url_whitelist_url_host` | bool | `false` | No |
| url_whitelist_uri_prefix | URI prefix for URL whitelisting. Required if `enable_url_whitelist_string_match_set` is set to `true` | string | `""` | Yes |
| url_whitelist_url_host | Host for URL whitelisting. Required if `enable_url_whitelist_string_match_set` is set to `true` | string | `""` | Yes |

## Outputs

| Name | Description |
|------|-------------|
| rule_group_id | AWS WAF Rule Group which contains all rules for OWASP Top 10 protection |
| rule_01_sql_injection_rule_id | AWS WAF Rule which mitigates SQL Injection Attacks |
| rule_02_auth_token_rule_id | AWS WAF Rule which blacklists bad/hijacked JWT tokens or session IDs |
| rule_03_xss_rule_id | AWS WAF Rule which mitigates Cross Site Scripting Attacks |
| rule_04_paths_rule_id | AWS WAF Rule which mitigates Path Traversal, LFI, RFI |
| rule_06_php_insecure_rule_id | AWS WAF Rule which mitigates PHP Specific Security Misconfigurations |
| rule_07_size_restriction_rule_id | AWS WAF Rule which mitigates abnormal requests via size restrictions |
| rule_08_csrf_rule_id | AWS WAF Rule which enforces the presence of CSRF token in request header |
| rule_09_ssi_rule_id | AWS WAF Rule which blocks request patterns for webroot objects that shouldn't be directly accessible |

## Examples
* [owasp-top-10](examples/owasp-top-10)

## Related Modules
* [terraform-aws-waf-webacl-supporting-resources](https://github.com/traveloka/terraform-aws-waf-webacl-supporting-resources)

## License
Apache 2 Licensed. See LICENSE for full details.
