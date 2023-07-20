control 'TNDM-3X-000098' do
  title 'The NSX-T Manager must not provide environment information to third parties.'
  desc  "Providing technical details about an environment's infrastructure to third parties could unknowingly expose sensitive information to bad actors if intercepted."
  desc  'rationale', ''
  desc  'check', "
    From the NSX-T Manager web interface, go to System >> Customer Experience Improvement Program.

    If Joined is set to \"Yes\", this is a finding.
  "
  desc 'fix', "
    From the NSX-T Manager web interface, go to System >> Customer Experience Improvement Program, and then click \"Edit\".

    Uncheck \"Join the VMware Customer Experience Improvement Program\" and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag gid: 'V-251795'
  tag rid: 'SV-251795r810388_rule'
  tag stig_id: 'TNDM-3X-000098'
  tag fix_id: 'F-55209r810387_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  result = http("https://#{input('nsxManager')}/api/v1/telemetry/config",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
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
