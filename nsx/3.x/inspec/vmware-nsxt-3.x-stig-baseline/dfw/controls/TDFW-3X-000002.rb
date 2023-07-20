control 'TDFW-3X-000002' do
  title 'The NSX-T Distributed Firewall must not have any unpublished firewall policies or rules.'
  desc  'Unpublished firewall rules may be enabled inadvertently and cause unintended filtering or introduce unvetted/unauthorized traffic flows.'
  desc  'rationale', ''
  desc  'check', "
    From the NSX-T Manager web interface, go to Security >> Distributed Firewall >> Category Specific Rules.

    If there is a message for Total Unpublished Changes and Publish is not greyed out, this is a finding.
  "
  desc 'fix', "
    From the NSX-T Manager web interface, go to Security >> Distributed Firewall >> Category Specific Rules.

    Review any unpublished changes and click either \"Revert\" or \"Publish\".
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-NET-000019-FW-000004'
  tag gid: 'V-251726'
  tag rid: 'SV-251726r810032_rule'
  tag stig_id: 'TDFW-3X-000002'
  tag fix_id: 'F-55117r810031_fix'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']

  result = http("https://#{input('nsxManager')}/policy/api/v1/infra/drafts",
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
      its('result_count') { should cmp 0 }
    end
  end
end
