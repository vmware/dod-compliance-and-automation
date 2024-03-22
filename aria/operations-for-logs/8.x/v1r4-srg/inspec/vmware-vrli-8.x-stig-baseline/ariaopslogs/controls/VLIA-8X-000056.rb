control 'VLIA-8X-000056' do
  title 'The application server must utilize FIPS 140-2 approved encryption modules.'
  desc  "
    Encryption is only as good as the encryption modules utilized.  Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms.  The use of TLS provides confidentiality of data in transit between the application server and client.

    TLS must be enabled and non-FIPS-approved SSL versions must be disabled.  NIST SP 800-52 specifies the preferred configurations for government systems.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the VMware Aria Operations for Logs admin portal (/admin/) as an administrator.

    In the menu on the left, choose \"Configuration\", then \"General\".

    On the \"General Configuration\" page, under \"FIPS MODE\", if \"Activate FIPS Mode\" is not enabled, this is a finding.
  "
  desc 'fix', "
    Login to the VMware Aria Operations for Logs admin portal (/admin/) as an administrator.

    In the menu on the left, choose \"Configuration\", then \"General\".

    On the \"General Configuration\" page, under \"FIPS MODE\", ensure \"Activate FIPS Mode\" is enabled, then click \"Save\".

    Note: Once FIPS mode is activated, it can never be de-activated.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000172-AU-002550'
  tag satisfies: ['SRG-APP-000156-AU-002380', 'SRG-APP-000179-AU-002670', 'SRG-APP-000514-AU-002890', 'SRG-APP-000610-AU-000050']
  tag gid: 'V-VLIA-8X-000056'
  tag rid: 'SV-VLIA-8X-000056'
  tag stig_id: 'VLIA-8X-000056'
  tag cci: ['CCI-000197', 'CCI-000803', 'CCI-001941', 'CCI-002450']
  tag nist: ['IA-2 (8)', 'IA-5 (1) (c)', 'IA-7', 'SC-13']
  tag mitigations: 'We have a prioritized feature request to implement this in the near term. .'

  token = http("https://#{input('apipath')}/sessions",
               method: 'POST',
               headers: {
                 'Content-Type' => 'application/json',
                 'Accept' => 'application/json'
               },
               data: "{\"username\":\"#{input('username')}\",\"password\":\"#{input('password')}\",\"provider\":\"Local\"}",
               ssl_verify: false)

  describe token do
    its('status') { should cmp 200 }
  end

  unless token.status != 200
    sessID = JSON.parse(token.body)['sessionId']

    response = http("https://#{input('apipath')}/fips",
                    method: 'GET',
                    headers: {
                      'Content-Type' => 'application/json',
                      'Accept' => 'application/json',
                      'Authorization' => "Bearer #{sessID}"
                    },
                    ssl_verify: false)

    describe response do
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      describe json(content: response.body) do
        its(['enabled']) { should cmp 'true' }
      end
    end
  end
end
