variable "owner" {
  description = "The owner of the environment"
  type = string
}

variable "namespace" {
  description = "The unique namespace for the environment, which could be your organization name or abbreviation"
  type = string
}

variable "environment" {
  description = "The name of the environment - e.g. dev, stage, prod"
  type = string
}

variable "waf_prefix" {
  default = "wafowasp"
  description = "Prefix to use when naming resources"
}

variable "target_scope" {
  type        = string
  description = "Valid values are `global` and `regional`. If `global`, means resources created will be for global targets such as Amazon CloudFront distribution. For regional targets like ALBs and API Gateway stages, set to `regional`"
}

variable "create_rule_group" {
  type        = string
  description = "All rules can be grouped into a Rule Group. Unfortunately, AWS WAF Rule Group limit per region is only 3. By setting the value to `false` will not create the rule group. Default is set to `true`."
  default     = "true"
}

variable "rule_01_sql_injection_action_type" {
  default     = "BLOCK"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "rule_02_auth_tokens_action_type" {
  default     = "BLOCK"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "rule_03_xss_action_type" {
  default     = "BLOCK"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "rule_04_lfi_rfi_paths_action_type" {
  default     = "BLOCK"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "rule_06_php_insecure_action_type" {
  default     = "BLOCK"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "rule_07_size_restriction_action_type" {
  default     = "BLOCK"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "rule_08_csrf_action_type" {
  default     = "BLOCK"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "rule_09_ssi_action_type" {
  default     = "BLOCK"
  description = "Rule action type. Either BLOCK, ALLOW, or COUNT (useful for testing)"
}

variable "max_expected_uri_size" {
  type        = string
  description = "Maximum number of bytes allowed in the URI component of the HTTP request. Generally the maximum possible value is determined by the server operating system (maps to file system paths), the web server software, or other middleware components. Choose a value that accomodates the largest URI segment you use in practice in your web application"
  default     = "512"
}

variable "max_expected_query_string_size" {
  type        = string
  description = "Maximum number of bytes allowed in the query string component of the HTTP request. Normally the  of query string parameters following the ? in a URL is much larger than the URI , but still bounded by the  of the parameters your web application uses and their values"
  default     = "1024"
}

variable "max_expected_body_size" {
  type        = string
  description = "Maximum number of bytes allowed in the body of the request. If you do not plan to allow large uploads, set it to the largest payload value that makes sense for your web application. Accepting unnecessarily large values can cause performance issues, if large payloads are used as an attack vector against your web application"
  default     = "4096"
}

variable "max_expected_cookie_size" {
  type        = string
  description = "Maximum number of bytes allowed in the cookie header. The maximum size should be less than 4096, the size is determined by the amount of information your web application stores in cookies. If you only pass a session token via cookies, set the size to no larger than the serialized size of the session token and cookie metadata"
  default     = "4093"
}

variable "csrf_expected_header" {
  type        = string
  description = "The custom HTTP request header, where the CSRF token value is expected to be encountered"
  default     = "x-csrf-token"
}

variable "csrf_expected_size" {
  type        = string
  description = "The size in bytes of the CSRF token value. For example if it's a canonically formatted UUIDv4 value the expected size would be 36 bytes/ASCII characters"
  default     = "36"
}

variable "disable_03_uri_url_decode" {
  default     = false
  type        = bool
  description = "Disable the 'URI contains a cross-site scripting threat after decoding as URL.' filter"
}

variable "disable_03_uri_html_decode" {
  default     = false
  type        = bool
  description = "Disable the 'URI contains a cross-site scripting threat after decoding as HTML tags.' filter."
}

variable "disable_03_query_string_url_decode" {
  default     = false
  type        = bool
  description = "Disable the 'Query string contains a cross-site scripting threat after decoding as URL.' filter."
}

variable "disable_03_query_string_html_decode" {
  default     = false
  type        = bool
  description = "Disable the 'Query string contains a cross-site scripting threat after decoding as HTML tags.' filter."
}

variable "disable_03_body_url_decode" {
  default     = false
  type        = bool
  description = "Disable the 'Body contains a cross-site scripting threat after decoding as URL.' filter."
}

variable "disable_03_body_html_decode" {
  default     = false
  type        = bool
  description = "Disable the 'Body contains a cross-site scripting threat after decoding as HTML tags.' filter."
}

variable "disable_03_cookie_url_decode" {
  default     = false
  type        = bool
  description = "Disable the 'Header cookie contains a cross-site scripting threat after decoding as URL.' filter."
}

variable "disable_03_cookie_html_decode" {
  default     = false
  type        = bool
  description = "Disable the 'Header 'cookie' contains a cross-site scripting threat after decoding as HTML tags.' filter."
}

variable "disable_04_uri_contains_previous_dir_after_url_decode" {
  default     = false
  type        = bool
  description = "Disable the 'URI contains: '../' after decoding as URL.' filter"
}

variable "disable_04_uri_contains_previous_dir_after_html_decode" {
  default     = false
  type        = bool
  description = "Disable the 'URI contains: '../' after decoding as HTML tags.' filter"
}

variable "disable_04_query_string_contains_previous_dir_after_url_decode" {
  default     = false
  type        = bool
  description = "Disable the 'Query string contains: '../' after decoding as URL.' filter"
}

variable "disable_04_query_string_contains_previous_dir_after_html_decode" {
  default     = false
  type        = bool
  description = "Disable the 'Query string contains: '../' after decoding as HTML tags.' filter"
}

variable "disable_04_uri_contains_url_path_after_url_decode" {
  default     = false
  type        = bool
  description = "Disable the 'URI contains: '://' after decoding as URL.' filter"
}

variable "disable_04_uri_contains_url_path_after_html_decode" {
  default     = false
  type        = bool
  description = "Disable the 'URI contains: '://' after decoding as HTML tags.' filter"
}

variable "disable_04_query_string_contains_url_path_after_url_decode" {
  default     = false
  type        = bool
  description = "Disable the 'Query string contains: '://' after decoding as URL.' filter"
}

variable "disable_04_query_string_contains_url_path_after_html_decode" {
  default     = false
  type        = bool
  description = "Disable the 'Query string contains: '://' after decoding as HTML tags.' filter"
}
