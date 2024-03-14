control 'CFAP-4X-000008' do
  title 'SDDC Manager must use an account dedicated for downloading updates and patches.'
  desc  'Using a dedicated My VMware account when access is allowed to pull updates online will ensure consistent access to updates and security patches in the event of system administrator turnover or account access issues.'
  desc  'rationale', ''
  desc  'check', "
    If SDDC Manager is not pulling updates online, this is Not Applicable.

    From the SDDC Manager UI under Administration >> Repository Settings.

    If the account used to authenticate with VMware is not a dedicated account, this is a finding.
  "
  desc 'fix', "
    From the SDDC Manager UI under Administration >> Repository Settings.

    Update the account used to authenticate to VMware to a dedicated account for pulling updates that is not associated with a particular system administrator.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFAP-4X-000008'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  myvmwareaccount = input('myVmwareAccount')

  unless myvmwareaccount.nil?
    result = http("https://#{input('sddcManager')}/v1/system/settings/depot",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'Authorization' => "#{input('bearerToken')}",
                  },
                ssl_verify: false)

    describe result do
      its('status') { should cmp 200 }
    end
    unless result.status != 200
      describe json(content: result.body) do
        its(['vmwareAccount', 'username']) { should cmp myvmwareaccount }
      end
    end
  end
end
