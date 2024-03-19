control 'TNDM-3X-000101' do
  title 'The NSX-T Manager must disable TLS 1.1 and enable TLS 1.2.'
  desc 'TLS 1.0 and 1.1 are deprecated protocols with well-published shortcomings and vulnerabilities. TLS 1.2 must be enabled on all interfaces and TLS 1.1 and 1.0 disabled where supported.'
  desc 'check', 'Viewing TLS protocol enablement must be done via the API.

Execute the following API call using curl or another REST API client:

GET https://<nsx-mgr>/api/v1/cluster/api-service

Expected result:
    "protocol_versions": [
        {
            "name": "TLSv1.1",
            "enabled": false
        },
        {
            "name": "TLSv1.2",
            "enabled": true
        }
    ],

If TLS 1.1 is enabled, this is a finding.'
  desc 'fix', 'Capture the output from the check GET command and update the TLS 1.1 protocol to false.

Execute the following API call using curl or another REST API client:

PUT https://<nsx-mgr>/api/v1/cluster/api-service

Example request body:

{
  "global_api_concurrency_limit": 199,
  "client_api_rate_limit": 100,
  "client_api_concurrency_limit": 40,
  "connection_timeout": 30,
  "redirect_host": "",
  "cipher_suites": [
    {"enabled": true, "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
    {"enabled": true, "name": "TLS_RSA_WITH_AES_256_GCM_SHA384"},
    {"enabled": true, "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
    {"enabled": true, "name": "TLS_RSA_WITH_AES_128_GCM_SHA256"}
    {"enabled": true, "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384}",
    {"enabled": true, "name": "TLS_RSA_WITH_AES_256_CBC_SHA256"},
    {"enabled": true, "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
    {"enabled": true, "name": "TLS_RSA_WITH_AES_256_CBC_SHA"},
    {"enabled": true, "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
    {"enabled": true, "name": "TLS_RSA_WITH_AES_128_CBC_SHA256"},
    {"enabled": false, "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
    {"enabled": false, "name": "TLS_RSA_WITH_AES_128_CBC_SHA"}
  ],
  "protocol_versions": [
    {"enabled": false, "name": "TLSv1.1"},
    {"enabled": true, "name": "TLSv1.2"}
  ]
}

Note: Changes are applied to all nodes in the cluster. The API service on each node will restart after it is updated using this API. There may be a delay of up to a minute or so between the time this API call completes and when the new configuration goes into effect.'
  impact 0.5
  tag check_id: 'C-55258r810395_chk'
  tag severity: 'medium'
  tag gid: 'V-251798'
  tag rid: 'SV-251798r879588_rule'
  tag stig_id: 'TNDM-3X-000101'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-55212r810396_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

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
