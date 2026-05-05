control 'VCFA-9X-000253' do
  title 'VMware Cloud Foundation Operations for Logs must enable FIPS-validated cryptography.'
  desc  'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. '
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Logs is not deployed, this is not applicable.

    From VCF Operations for Logs, go to Configuration >> General.

    Review the FIPS Mode configuration.

    If \"Activate FIPS Mode\" is disabled, this is a finding.
  "
  desc 'fix', "
    From VCF Operations for Logs, go to Configuration >> General.

    Under FIPS Mode click the radio button next to \"Activate FIPS Mode\" and click Save.

    Note: Enabling FIPS mode will initiate a restart on all nodes and cannot be later disabled.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000555'
  tag satisfies: ['SRG-APP-000179', 'SRG-APP-000224', 'SRG-APP-000411', 'SRG-APP-000412', 'SRG-APP-000514', 'SRG-APP-000600', 'SRG-APP-000610', 'SRG-APP-000620', 'SRG-APP-000630', 'SRG-APP-000635']
  tag gid: 'V-VCFA-9X-000253'
  tag rid: 'SV-VCFA-9X-000253'
  tag stig_id: 'VCFA-9X-000253'
  tag cci: ['CCI-000803', 'CCI-001188', 'CCI-001967', 'CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['IA-3 (1)', 'IA-7', 'MA-4 (6)', 'SC-13 b', 'SC-23 (3)']

  if input('opslogs_deployed')
    response = http("https://#{input('opslogs_apihostname')}/api/v2/fips",
                    method: 'GET',
                    ssl_verify: false,
                    headers: { 'Content-Type' => 'application/json',
                               'Accept' => 'application/json',
                               'Authorization' => "Bearer #{input('opslogs_apitoken')}" })

    describe response do
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      responseval = json(content: response.body)['enabled']

      if responseval
        describe 'FIPS-validated cryptography must be enabled' do
          subject { responseval }
          it { should cmp true }
        end
      else
        describe 'FIPS-validated cryptography must be enabled' do
          subject { responseval }
          it { should_not be_nil }
        end
      end
    end
  else
    impact 0.0
    describe 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.'
    end
  end
end
