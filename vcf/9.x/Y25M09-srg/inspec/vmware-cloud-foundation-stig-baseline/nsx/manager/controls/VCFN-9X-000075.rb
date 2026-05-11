control 'VCFN-9X-000075' do
  title 'The VMware Cloud Foundation NSX Manager must be configured to implement cryptographic mechanisms using a FIPS 140-2 approved algorithm to protect the confidentiality of remote maintenance sessions.'
  desc  'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc  'rationale', ''
  desc  'check', "
    Viewing the enabled cipher suites must be done via the API.

    Execute the following API call using curl or another REST API client:

    GET https://<nsx-mgr>/api/v1/cluster/api-service

    Example result:

    \"cipher_suites\": [
    \t{
    \t\t\"name\": \"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\",
    \t\t\"enabled\": true
    \t},
    \t{
    \t\t\"name\": \"TLS_AES_128_GCM_SHA256\",
    \t\t\"enabled\": true
    \t},
    \t{
    \t\t\"name\": \"TLS_AES_256_GCM_SHA384\",
    \t\t\"enabled\": true
    \t},
    \t{
    \t\t\"name\": \"TLS_CHACHA20_POLY1305_SHA256\",
    \t\t\"enabled\": true
    \t}
    ],

    Note: The output has been shortened for readability.

    If any cipher suites are enabled that are not listed below, this is a finding.

    TLS 1.2 Ciphers: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

    TLS 1.3 Ciphers: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
  "
  desc 'fix', "
    Capture the output from the check GET command and update the TLS 1.1 protocol to false.

    Run the following API call using curl or another REST API client:

    PUT https://<nsx-mgr>/api/v1/cluster/api-service

    Example request body:

    {
        \"session_timeout\": 1800,
        \"connection_timeout\": 30,
        \"protocol_versions\": [
            {
                \"name\": \"TLSv1.1\",
                \"enabled\": false
            },
            {
                \"name\": \"TLSv1.2\",
                \"enabled\": true
            },
            {
                \"name\": \"TLSv1.3\",
                \"enabled\": true
            }
        ],
        \"cipher_suites\": [
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA\",
                \"enabled\": false
            },
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256\",
                \"enabled\": false
            },
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA\",
                \"enabled\": false
            },
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384\",
                \"enabled\": false
            },
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_128_CBC_SHA\",
                \"enabled\": false
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_128_CBC_SHA256\",
                \"enabled\": false
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_128_GCM_SHA256\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_256_CBC_SHA\",
                \"enabled\": false
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_256_CBC_SHA256\",
                \"enabled\": false
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_256_GCM_SHA384\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_AES_128_GCM_SHA256\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_AES_256_GCM_SHA384\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_CHACHA20_POLY1305_SHA256\",
                \"enabled\": false
            }
        ],
        \"redirect_host\": \"\",
        \"client_api_rate_limit\": 100,
        \"global_api_concurrency_limit\": 199,
        \"client_api_concurrency_limit\": 40,
        \"basic_authentication_enabled\": true,
        \"cookie_based_authentication_enabled\": true,
        \"resource_type\": \"ApiServiceConfig\",
        \"id\": \"reverse_proxy_config\",
        \"display_name\": \"reverse_proxy_config\",
        \"_system_owned\": false,
        \"_protection\": \"NOT_PROTECTED\",
        \"_create_time\": 1733862743672,
        \"_create_user\": \"system\",
        \"_last_modified_time\": 1733948476863,
        \"_last_modified_user\": \"admin\",
        \"_revision\": 1
    }

    Note: Changes are applied to all nodes in the cluster. The API service on each node will restart after it is updated using this API. There may be a delay of up to a minute or so between the time this API call completes and when the new configuration goes into effect.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag gid: 'V-VCFN-9X-000075'
  tag rid: 'SV-VCFN-9X-000075'
  tag stig_id: 'VCFN-9X-000075'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']

  result = http("https://#{input('nsx_managerAddress')}/api/v1/cluster/api-service",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    results = JSON.parse(result.body)
    if !results['cipher_suites'].empty?
      results['cipher_suites'].each do |cipher|
        if cipher['enabled'] == true
          describe "Enabled cipher suite #{cipher['name']}" do
            subject { json(content: cipher.to_json)['name'] }
            it { should be_in input('nsx_allowedCiphers') }
          end
        else
          describe "Disabled cipher suite #{cipher['name']}" do
            subject { json(content: cipher.to_json)['name'] }
            it { should_not be_in input('nsx_allowedCiphers') }
          end
        end
      end
    else
      describe 'Unable to validate configured ciphers. No results returned.' do
        subject { results['cipher_suites'] }
        it { should_not be_empty }
      end
    end
  end
end
