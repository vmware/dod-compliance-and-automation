control 'T0RT-3X-000038' do
  title 'The NSX-T Tier-0 Gateway must be configured to restrict traffic destined to itself.'
  desc 'The route processor handles traffic destined to the router, the key component used to build forwarding paths, and is also instrumental with all network management functions. Hence, any disruption or DoS attack to the route processor can result in mission critical network outages.'
  desc 'check', 'If the Tier-0 Gateway is deployed in an Active/Active HA mode, this is Not Applicable.

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules and choose each Tier-0 Gateway in the drop-down.

Review each Tier-0 Gateway Firewalls rules to verify rules exist to restrict traffic to itself.

If a rule or rules do not exist to restrict traffic to external interface IPs, this is a finding.'
  desc 'fix', 'To configure firewall rule(s) to restrict traffic destined to interfaces on a Tier-0 Gateway do the following:

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules and select the target Tier-0 Gateway from the drop-down.

Click "Add Rule" (Add a policy first if needed) and configure the destinations to include all IPs for external interfaces.

Update the action to "Drop" or "Reject".

Enable logging, then under the "Applied To" field, select the target Tier-0 Gateways and click "Publish" to enforce the new rule.

Other rules may be constructed to allow traffic to external interface IPs if required above this default deny rule.'
  impact 0.7
  tag check_id: 'C-55186r810129_chk'
  tag severity: 'high'
  tag gid: 'V-251749'
  tag rid: 'SV-251749r810131_rule'
  tag stig_id: 'T0RT-3X-000038'
  tag gtitle: 'SRG-NET-000205-RTR-000001'
  tag fix_id: 'F-55140r810130_fix'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']

  t0s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
                },
              ssl_verify: false)

  describe t0s do
    its('status') { should cmp 200 }
  end
  unless t0s.status != 200
    t0sjson = JSON.parse(t0s.body)
    if t0sjson['results'] == []
      describe 'No T0 Gateways are deployed...skipping...' do
        skip 'No T0 Gateways are deployed...skipping...'
      end
    else
      describe 'This check is a manual check' do
        skip 'Review each Tier-0 Gateway Firewalls rules to verify rules exist to restrict traffic to itself.'
      end
    end
  end
end
