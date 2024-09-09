control 'NT0R-4X-000016' do
  title 'The NSX Tier-0 Gateway router must be configured to have all inactive interfaces removed.'
  desc '
    An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a router by connecting to a configured interface that is not in use.

    If an interface is no longer used, the configuration must be deleted and the interface disabled. For sub-interfaces, delete sub-interfaces that are on inactive interfaces and delete sub-interfaces that are themselves inactive. If the sub-interface is no longer necessary for authorized communications, it must be deleted.
  '
  desc 'check', '
    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

    For every Tier-0 Gateway, expand the Tier-0 Gateway >> Interfaces and GRE Tunnels, and click on the number of interfaces present to open the interfaces dialog.

    Review each interface present to determine if they are not in use or inactive.

    If there are any interfaces present on a Tier-0 Gateway that are not in use or inactive, this is a finding.
  '
  desc 'fix', '
    Remove unused interfaces by doing the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways and expand the target Tier-0 gateway.

    Expand "Interfaces and GRE Tunnels", then click on the number of interfaces present to open the interfaces dialog.

    Select "Delete" on the unneeded interface, and then click "Delete" again to confirm.
  '
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag gid: 'V-263299'
  tag rid: 'SV-263299r977664_rule'
  tag stig_id: 'NT0R-4X-000016'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']

  t0s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s",
             method: 'GET',
             headers: {
               'Accept' => 'application/json',
               'X-XSRF-TOKEN' => "#{input('sessionToken')}",
               'Cookie' => "#{input('sessionCookieId')}"
             },
             ssl_verify: false)

  # if status is not 200 return a failure but if it's 200 do not run the test so this control does not pass and is properly skipped as a manual review.
  if t0s.status != 200
    describe t0s do
      its('status') { should cmp 200 }
    end
  else
    t0sjson = JSON.parse(t0s.body)
    if t0sjson['results'] == []
      impact 0.0
      describe 'No T0 Gateways are deployed. This is Not Applicable.' do
        skip 'No T0 Gateways are deployed. This is Not Applicable.'
      end
    else
      describe 'This check is a manual check' do
        skip 'This is a manual check. Review T0 interfaces and determine if any existing interfaces are orphaned and should be removed.'
      end
    end
  end
end
