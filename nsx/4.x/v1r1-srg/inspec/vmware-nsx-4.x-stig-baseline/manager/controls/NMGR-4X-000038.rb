control 'NMGR-4X-000038' do
  title 'The NSX Manager must only enable TLS 1.2.'
  desc  "
    A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

    An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

    Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.

    TLS 1.0 and 1.1 are deprecated protocols with well-published shortcomings and vulnerabilities. TLS 1.2 must be enabled on all interfaces and TLS 1.1 and 1.0 disabled where supported.
  "
  desc  'rationale', ''
  desc  'check', "
    Viewing TLS protocol enablement must be done via the API.

    Execute the following API call using curl or another REST API client:

    GET https://<nsx-mgr>/api/v1/cluster/api-service

    Expected result:
    \"protocol_versions\": [
    {
    \"name\": \"TLSv1.1\",
    \"enabled\": false
    },
    {
    \"name\": \"TLSv1.2\",
    \"enabled\": true
    }
    ],

    If TLS 1.1 is enabled, this is a finding.
  "
  desc 'fix', "
    Capture the output from the check GET command and update the TLS 1.1 protocol to false.

    Execute the following API call using curl or another REST API client:

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
            }
        ],
        \"cipher_suites\": [
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_128_CBC_SHA\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_128_CBC_SHA256\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_128_GCM_SHA256\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_256_CBC_SHA\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_256_CBC_SHA256\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_RSA_WITH_AES_256_GCM_SHA384\",
                \"enabled\": true
            },
            {
                \"name\": \"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\",
                \"enabled\": true
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
        \"_create_time\": 1668401188125,
        \"_create_user\": \"system\",
        \"_last_modified_time\": 1668427053322,
        \"_last_modified_user\": \"admin\",
        \"_system_owned\": false,
        \"_protection\": \"NOT_PROTECTED\",
        \"_revision\": 2
    }

    Note: Changes are applied to all nodes in the cluster. The API service on each node will restart after it is updated using this API. There may be a delay of up to a minute or so between the time this API call completes and when the new configuration goes into effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag satisfies: ['SRG-APP-000172-NDM-000259']
  tag gid: 'V-NMGR-4X-000038'
  tag rid: 'SV-NMGR-4X-000038'
  tag stig_id: 'NMGR-4X-000038'
  tag cci: ['CCI-000197', 'CCI-001941']
  tag nist: ['IA-2 (8)', 'IA-5 (1) (c)']

  result = http("https://#{input('nsxManager')}/api/v1/cluster/api-service",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    results = JSON.parse(result.body)
    results['protocol_versions'].each do |protocol|
      case protocol['name']
      when 'TLSv1.1'
        describe "Protocol #{protocol['name']} enabled" do
          subject { json(content: protocol.to_json)['enabled'] }
          it { should cmp 'false' }
        end
      when 'TLSv1.2'
        describe "Protocol #{protocol['name']} enabled" do
          subject { json(content: protocol.to_json)['enabled'] }
          it { should cmp 'true' }
        end
      end
    end
  end
end
