control 'CFAP-5X-000125' do
  title 'The SDDC Manager must not provide environment information to third parties.'
  desc  'Providing technical details about an environments infrastructure to third parties could unknowningly expose sensitive information to bad actors if intercepted.'
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager UI, navigate to Administration >> VMware CEIP.

    If the \"Join the VMware Customer Experience Improvement Program\" is checked, this is a finding.
  "
  desc 'fix', "
    From the SDDC Manager UI, navigate to Administration >> VMware CEIP.

    Uncheck the box next to \"Join the VMware Customer Experience Improvement Program\" and CEIP will be disabled.

    Alternatively, if Cloud Foundation has not been deployed yet, CEIP can be disabled in the deployment workbook.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFAP-5X-000125'
  tag rid: 'SV-CFAP-5X-000125'
  tag stig_id: 'CFAP-5X-000125'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('sddcManager')}/v1/system/ceip",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'Authorization' => "#{input('bearerToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('status') { should cmp 'DISABLED' }
    end
  end
end
