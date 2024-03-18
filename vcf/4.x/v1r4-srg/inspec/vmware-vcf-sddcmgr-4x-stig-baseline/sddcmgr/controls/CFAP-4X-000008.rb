control 'CFAP-4X-000008' do
  title 'The SDDC Manager must use an account dedicated for downloading updates and patches.'
  desc  'Using a dedicated My VMware account when access is allowed to pull updates online will ensure consistent access to updates and security patches in the event of system administrator turnover or account access issues.'
  desc  'rationale', ''
  desc  'check', "
    If SDDC Manager is not pulling updates online, this is not applicable.

    From the SDDC Manager UI, navigate to Administration >> Online Depot.

    If the account used to authenticate with VMware is not a dedicated account, this is a finding.
  "
  desc 'fix', "
    From the SDDC Manager UI, navigate to Administration >> Online Depot.

    Update the account used to authenticate to VMware to a dedicated account for pulling updates that is not associated with a particular system administrator.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFAP-4X-000008'
  tag rid: 'SV-CFAP-4X-000008'
  tag stig_id: 'CFAP-4X-000008'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  myvmwareaccount = input('myVmwareAccount')

  result = http("https://#{input('sddcManager')}/v1/system/settings/depot",
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
    if myvmwareaccount.empty?
      # if no account is given assume the online depot should not be configured
      describe json(content: result.body) do
        its(['vmwareAccount', 'username']) { should be nil }
      end
    else
      describe json(content: result.body) do
        its(['vmwareAccount', 'username']) { should cmp myvmwareaccount }
      end
    end
  end
end
