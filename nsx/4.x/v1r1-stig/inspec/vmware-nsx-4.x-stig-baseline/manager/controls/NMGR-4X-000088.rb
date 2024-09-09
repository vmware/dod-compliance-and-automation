control 'NMGR-4X-000088' do
  title 'The NSX Manager must not provide environment information to third parties.'
  desc "Providing technical details about an environment's infrastructure to third parties could unknowingly expose sensitive information to bad actors if intercepted."
  desc 'check', '
    From the NSX Manager web interface, go to System >> Settings >> General Settings >> Customer Program >> Customer Experience Improvement Program.

    If Joined is set to "Yes", this is a finding.
  '
  desc 'fix', '
    From the NSX Manager web interface, go to System >> Settings >> General Settings >> Customer Program >> Customer Experience Improvement Program, and then click "Edit".

    Uncheck "Join the VMware Customer Experience Improvement Program" and click "Save".
  '
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag gid: 'V-263221'
  tag rid: 'SV-263221r977430_rule'
  tag stig_id: 'NMGR-4X-000088'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('nsxManager')}/api/v1/telemetry/config",
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
    describe json(content: result.body) do
      its('ceip_acceptance') { should cmp 'false' }
    end
  end
end
