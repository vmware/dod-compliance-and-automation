control 'T0RT-3X-000016' do
  title 'The NSX-T Tier-0 Gateway must be configured to have all inactive interfaces removed.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface.

If an interface is no longer used, the configuration must be deleted.'
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways.

For every Tier-0 Gateway, expand the Tier-0 Gateway >> Interfaces, and click on the number of interfaces present to open the interfaces dialog.

Review each interface present to determine if they are not in use or inactive.

If there are any interfaces present on a Tier-0 Gateway that are not in use or inactive, this is a finding.'
  desc 'fix', 'Disable multicast PIM routing on interfaces that are not required to support multicast by doing the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways and expand the target Tier-0 gateway.

Expand "Interfaces", then click on the number of interfaces present to open the interfaces dialog. Select "Delete" on the unneeded interface, and then click "Delete" again to confirm.'
  impact 0.3
  tag check_id: 'C-55183r810120_chk'
  tag severity: 'low'
  tag gid: 'V-251746'
  tag rid: 'SV-251746r810122_rule'
  tag stig_id: 'T0RT-3X-000016'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-55137r810121_fix'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']

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
        skip 'This is a manual check. Review T0 interfaces and determine if any existing interfaces are orphaned and should be removed.'
      end
    end
  end
end
