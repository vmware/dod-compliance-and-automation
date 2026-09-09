control 'VLMA-8X-000001' do
  title 'VMware Aria Suite Lifecycle must enable FIPS mode.'
  desc  'Remote management access is accomplished by leveraging common communication protocols and establishing a remote connection to the application server via a network for the purposes of managing the application server. Enabling strong cryptography, FIPS means there are very less chances that remote connection could be intercepted and compromised. '
  desc  'rationale', ''
  desc  'check', "
    Log in to the VMware Aria Suite Lifecycle management interface.

    Click on Lifecycle Operations >> Settings >> System Details >> FIPS Mode Compliance

    If FIPS mode is not enabled, this is a finding.
  "
  desc  'fix', "
    Log in to the VMware Aria Suite Lifecycle management interface.

    Click on Lifecycle Operations >> Settings >> System Details >> FIPS Mode Compliance

    Ensure the checkbox for FIPS Mode Compliance is enabled.

    Click \"Update\" to reboot the appliance.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag satisfies: ['SRG-APP-000015-AS-000010', 'SRG-APP-000179-AS-000129']
  tag gid: 'V-VLMA-8X-000001'
  tag rid: 'SV-VLMA-8X-000001'
  tag stig_id: 'VLMA-8X-000001'
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-001453']
  tag nist: ['AC-17 (2)', 'IA-7']

  cred = Base64.encode64("#{input('username')}:#{input('password')}")

  response = http("https://#{input('hostname')}/lcm/locker/api/security/fips",
                  method: 'GET',
                  headers: {
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json',
                    'Authorization' => "Basic #{cred}"
                  },
                  ssl_verify: false)

  describe response do
    its('status') { should cmp 200 }
  end

  unless response.status != 200
    result = JSON.parse(response.body)

    describe result['enabled'] do
      it { should cmp true }
    end
  end
end
