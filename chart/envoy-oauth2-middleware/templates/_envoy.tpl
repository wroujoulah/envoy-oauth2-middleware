{{- define "envoy-oauth2-middleware.config" -}}
static_resources:
    secrets:
      - name: token
        generic_secret:
          secret: 
            inline_string: {{ .Values.envoy.config.oidc.clientSecret }}
      - name: hmac
        generic_secret:
          secret:  
            inline_string: {{ .Values.envoy.secret.hmac }}
    listeners:
        - address:
            socket_address:
                address: {{ .Values.envoy.config.listener.address }}
                port_value: {{ .Values.envoy.config.listener.port }}
          filter_chains:
            - filters:
                - name: envoy.filters.network.http_connection_manager
                  typed_config:
                    '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                    codec_type: AUTO
                    stat_prefix: ingress_http
                    route_config:
                        name: local_route
                        virtual_hosts:
                            # this should be replaced with rediret based on query parm
                            - name: auth-upstream
                              domains:
                                - '*'
                              routes:
                                - match:
                                    safe_regex:
                                        regex: ^\/oauth2\/(userinfo)$
                                  route:
                                    cluster: oidc-domain
                                    auto_host_rewrite: true
                                  typed_per_filter_config:
                                    header_mutation.response_add_cors_headers:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                    lua.response_append_domain_setcookie_headers:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                    oauth2:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                    lua.jwt_cookie_to_header:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                - match:
                                    safe_regex:
                                        regex: ^\/oauth2\/(auth)$
                                  response_headers_to_add:
                                    - header:
                                        key: "content-type"
                                        value: "application/json"
                                    - header:
                                        key: "Cache-Control"
                                        value: "no-store, no-cache, must-revalidate, proxy-revalidate"
                                  direct_response:
                                    status: 200
                                    body:
                                      inline_string: '{"message": "Authenticated"}'
                                  typed_per_filter_config:
                                    header_mutation.response_add_cors_headers:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                    lua.response_append_domain_setcookie_headers:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                    oauth2:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                - match:
                                    safe_regex:
                                        regex: ^\/oauth2\/(sign_out)$
                                  redirect:
                                    https_redirect: true
                                    path_redirect: /redirect
                                    response_code: FOUND
                                  typed_per_filter_config:
                                    lua.response_redirect_using_rd:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                    lua.request_revoke_refresh_token:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                  response_headers_to_add:
                                    - header:
                                        key: "Cache-Control"
                                        value: "no-store, no-cache, must-revalidate, proxy-revalidate"
                                    - header:
                                        key: "Set-Cookie"
                                        value: "RefreshToken=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Domain={{ .Values.envoy.config.cookiesDomain }}; SameSite=Lax"
                                    - header:
                                        key: "Set-Cookie"
                                        value: "BearerToken=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Domain={{ .Values.envoy.config.cookiesDomain }}; SameSite=Lax"
                                    - header:
                                        key: "Set-Cookie"
                                        value: "OauthHMAC=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Domain={{ .Values.envoy.config.cookiesDomain }}; SameSite=Lax"
                                    - header:
                                        key: "Set-Cookie"
                                        value: "OauthExpires=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Domain={{ .Values.envoy.config.cookiesDomain }}; SameSite=Lax"
                                    - header:
                                        key: "Set-Cookie"
                                        value: "IdToken=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Domain={{ .Values.envoy.config.cookiesDomain }}; SameSite=Lax"
                                - match:
                                    safe_regex:
                                        regex: ^\/oauth2\/(start|callback)$
                                  redirect:
                                    https_redirect: true
                                    path_redirect: /redirect
                                    response_code: FOUND
                                  typed_per_filter_config:
                                    lua.response_redirect_using_rd:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                    lua.response_append_domain_setcookie_headers:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                    oauth2:
                                        '@type': type.googleapis.com/envoy.config.route.v3.FilterConfig
                                        config: {}
                                  response_headers_to_add:
                                    - header:
                                        key: "Cache-Control"
                                        value: "no-store, no-cache, must-revalidate, proxy-revalidate"
                                - match:
                                    prefix: /healthz
                                  direct_response:
                                    status: 200
                                    body:
                                        inline_string: Envoy is running
                    http_filters:
                        - name: header_mutation.response_add_cors_headers
                          disabled: true
                          typed_config:
                            "@type": type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation
                            mutations:
                              response_mutations:
                                - append:
                                      header:
                                        key: Access-Control-Allow-Origin
                                        value: {{ .Values.envoy.config.cors.allowOrigin }}
                                - append:
                                      header:
                                        key: Access-Control-Allow-Methods
                                        value: GET, OPTIONS
                                - append:
                                      header:
                                        key: Access-Control-Allow-Headers
                                        value: Content-Type, Authorization
                                - append:
                                      header:
                                        key: Access-Control-Expose-Headers
                                        value: Content-Type, Authorization
                                - append:
                                      header:
                                        key: Access-Control-Allow-Credentials
                                        value: "true"
                                - append:
                                      header:
                                        key: Access-Control-Max-Age
                                        value: "3600"
                        - name: lua.response_append_domain_setcookie_headers
                          disabled: true
                          typed_config:
                            '@type': type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
                            inline_code: |
                                function envoy_on_response(response_handle)
                                  local headers = response_handle:headers()
                                  local set_cookie_headers = headers:get("set-cookie")
                                  if set_cookie_headers then
                                    -- Envoy concatenates multiple headers with the same name using a comma,
                                    -- so we split the headers using the comma as a delimiter.
                                    local set_cookie_header_list = {}
                                    for set_cookie_header in string.gmatch(set_cookie_headers, "([^,]+)") do
                                      table.insert(set_cookie_header_list, set_cookie_header)
                                    end
                                    -- Append the domain to each Set-Cookie header and set them back
                                    local domain_to_append = "; Domain={{ .Values.envoy.config.cookiesDomain }}; SameSite=Lax"
                                    headers:remove("set-cookie")  -- Remove all existing Set-Cookie headers
                                    for _, set_cookie_header in ipairs(set_cookie_header_list) do
                                      local new_set_cookie_header = set_cookie_header .. domain_to_append
                                      headers:add("set-cookie", new_set_cookie_header)
                                    end
                                  end
                                end
                        - name: lua.request_revoke_refresh_token
                          disabled: true
                          typed_config:
                            "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
                            inline_code: |
                              function url_encode(str)
                                if str then
                                  str = string.gsub(str, "\n", "\r\n")
                                  str = string.gsub(str, "([^%w ])", function(c)
                                    return string.format("%%%02X", string.byte(c))
                                  end)
                                  str = string.gsub(str, " ", "+")
                                end
                                return str
                              end
                              function envoy_on_request(request_handle)
                                local cookies = request_handle:headers():get("cookie")
                                local token
                                if cookies then
                                  for cookie in string.gmatch(cookies, "([^;]+)") do
                                    local name, value = string.match(cookie, "%s*(.-)%s*=%s*(.+)%s*")
                                    if name == "RefreshToken" then
                                      token = value
                                      break
                                    end
                                  end
                                end
                                local client_id = "{{ .Values.envoy.config.oidc.clientId }}"
                                local encoded_client_id = url_encode(client_id)
                                local encoded_token = url_encode(token)
                                local body = "token=" .. encoded_token .. "&client_id=" .. encoded_client_id
                                local encoded_auth = handle:base64Escape("{{ .Values.envoy.config.oidc.clientId }}:{{ .Values.envoy.config.oidc.clientSecret }}")
                                local http_request = {
                                  [":method"] = "POST",
                                  [":path"] = "{{ .Values.envoy.config.oidc.endpoint.revoke }}",
                                  [":authority"] = "{{ .Values.envoy.config.oidc.domain }}",
                                  ["authorization"] = "Basic " .. encoded_auth,
                                  ["content-type"] = "application/x-www-form-urlencoded"
                                }
                                local headers, body = request_handle:httpCall(
                                  "oidc-domain",
                                  http_request,
                                  body,
                                  5000
                                )
                                local status_code = tonumber(headers[":status"])
                                if status_code ~= 200 then
                                    request_handle:respond({[":status"] = "502"}, "Upstream server error")
                                    return
                                end
                              end
                        - name: oauth2
                          disabled: true
                          typed_config:
                            '@type': type.googleapis.com/envoy.extensions.filters.http.oidc.v3.OAuth2
                            config:
                                token_endpoint:
                                    cluster: oidc-domain
                                    uri: {{ .Values.envoy.config.oidc.domain }}{{.Values.envoy.config.oidc.endpoint.token}}
                                    timeout: 5s
                                authorization_endpoint: https://{{ .Values.envoy.config.oidc.domain }}{{.Values.envoy.config.oidc.endpoint.authorize}}
                                redirect_uri: '%REQ(x-forwarded-proto)%://%REQ(:authority)%/oauth2/callback'
                                redirect_path_matcher:
                                    path:
                                        exact: /oauth2/callback
                                signout_path:
                                    path:
                                        exact: /oauth2/sign_out
                                deny_redirect_matcher:
                                    - name: :path
                                      prefix_match: /oauth2/auth
                                    - name: :path
                                      prefix_match: /oauth2/userinfo
                                use_refresh_token: true
                                default_refresh_token_expires_in: 1740s
                                forward_bearer_token: true
                                credentials:
                                    client_id: {{ .Values.envoy.config.oidc.clientId }}
                                    token_secret:
                                      name: token
                                    hmac_secret:
                                      name: hmac
                                auth_scopes:
                                    - openid
                        - name: lua.response_redirect_using_rd
                          disabled: true
                          typed_config:
                            '@type': type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
                            inline_code: |
                              function envoy_on_response(response_handle)
                                  -- Check if response code is 302
                                  local response_code = response_handle:headers():get(":status")
                                  if response_code == "302" then
                                      -- Get the Location header
                                      local location_header = response_handle:headers():get("location")
                                      if location_header then
                                          -- Check if Location header matches "/redirect"
                                          if string.match(location_header, "/redirect") then
                                              -- Extract the 'rd' query parameter
                                              local rd_value = string.match(location_header, "rd=([^&]+)")
                                              if rd_value then
                                                  -- Replace the Location header with the value of 'rd' query parameter
                                                  response_handle:headers():replace("location", rd_value)
                                              else
                                                  local base_url = string.match(location_header, "^(https?://[^/]+)")
                                                  local new_location = base_url .. "/oauth2/auth"
                                                  response_handle:headers():replace("location", new_location )
                                              end
                                          end
                                      end
                                  end
                              end
                        - name: lua.jwt_cookie_to_header
                          disabled: true
                          typed_config:
                            "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
                            inline_code: |
                              function envoy_on_request(request_handle)
                                local headers = request_handle:headers()
                                local cookies = headers:get("cookie")
                                local BearerTokenFound = false
                                if cookies then
                                  for cookie in string.gmatch(cookies, "([^;]+)") do
                                    local name, value = string.match(cookie, "%s*(.-)%s*=%s*(.+)%s*")
                                    if name == "BearerToken" then
                                      headers:add("Authorization", "Bearer " .. value)
                                      BearerTokenFound = true
                                      break
                                    end
                                  end
                                end
                                if not BearerTokenFound then
                                  request_handle:respond({[":status"] = "401"}, "No BearerToken")
                                  return
                                end
                              end
                        - name: envoy.filters.http.router
                          typed_config:
                            '@type': type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
    clusters:
        - name: oidc-domain
          connect_timeout: 2s
          type: STRICT_DNS
          lb_policy: ROUND_ROBIN
          dns_lookup_family: V4_ONLY
          load_assignment:
            cluster_name: oidc-domain
            endpoints:
                - lb_endpoints:
                    - endpoint:
                        address:
                            socket_address:
                                address: {{ .Values.envoy.config.oidc.domain }}
                                port_value: 443
          transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
                '@type': type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
{{- end }}
