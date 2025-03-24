control 'NT1R-4X-000016' do
  title 'The NSX Tier-1 Gateway router must be configured to have all inactive interfaces removed.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a router by connecting to a configured interface that is not in use.

If an interface is no longer used, the configuration must be deleted and the interface disabled. For sub-interfaces, delete sub-interfaces that are on inactive interfaces and delete sub-interfaces that are themselves inactive. If the sub-interface is no longer necessary for authorized communications, it must be deleted.'
  desc 'check', 'From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-1 Gateways.

For every Tier-1 Gateway, expand the Tier-1 Gateway. Click on the number in the Linked Segments to review the currently linked segments.

For every Tier-1 Gateway, expand the Tier-1 Gateway. Expand Interfaces and GRE Tunnels, and click on the number of interfaces present to open the interfaces dialog.

Review each interface or linked segment present to determine if they are not in use or inactive.

If there are any linked segments or service interfaces present on a Tier-1 Gateway that are not in use or inactive, this is a finding.'
  desc 'fix', 'To remove a stale linked segment from a Tier-1 Gateway, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Segments and edit the target segment.

Under Connected Gateway, change to "None" and click "Save".

Note: The stale linked segment can also be deleted if there are no active workloads attached to it.

To remove a stale service interface from a Tier-1 Gateway, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-1 Gateways >> Edit the target Tier-1 gateway.

Expand "Interfaces and GRE Tunnels", then click on the number of interfaces present to open the interfaces dialog.

On the stale service interface, select "Delete" and click "Delete" again to confirm.'
  impact 0.7
  ref 'DPMS Target VMware NSX 4.x Tier-1 Gateway Router'
  tag check_id: 'C-69435r995025_chk'
  tag severity: 'high'
  tag gid: 'V-265518'
  tag rid: 'SV-265518r999924_rule'
  tag stig_id: 'NT1R-4X-000016'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-69343r999924_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']

  t1s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-1s",
             method: 'GET',
             headers: {
               'Accept' => 'application/json',
               'X-XSRF-TOKEN' => "#{input('sessionToken')}",
               'Cookie' => "#{input('sessionCookieId')}"
             },
             ssl_verify: false)

  # if status is not 200 return a failure but if it's 200 do not run the test so this control does not pass and is properly skipped as a manual review.
  if t1s.status != 200
    describe t1s do
      its('status') { should cmp 200 }
    end
  else
    t1sjson = JSON.parse(t1s.body)
    if t1sjson['results'] == []
      impact 0.0
      describe 'No T1 Gateways are deployed. This is Not Applicable.' do
        skip 'No T1 Gateways are deployed. This is Not Applicable.'
      end
    else
      describe 'This is a manual check' do
        skip 'This is a manual check. Review T1 interfaces and determine if any existing interfaces are orphaned and should be removed.'
      end
    end
  end
end
