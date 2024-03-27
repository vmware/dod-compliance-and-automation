control 'TNDM-3X-000102' do
  title 'The NSX-T Manager must disable SNMP v2.'
  desc 'SNMPv3 supports commercial-grade security, including authentication, authorization, access control, and privacy. Previous versions of the protocol contained well-known security weaknesses that were easily exploited. As such, SNMPv1/2 receivers must be disabled.'
  desc 'check', 'From the NSX-T Manager web interface, go to the System >> Fabric >> Profiles >> Node Profiles.

Click "All NSX Nodes" and view the SNMP Polling and Traps configuration.

If SNMP v2c Polling or Traps are configured, this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to the System >> Fabric >> Profiles >> Node Profiles.

Click on "All NSX Nodes" and delete and v2c Polling or Trap configurations.'
  impact 0.5
  tag check_id: 'C-55259r810398_chk'
  tag severity: 'medium'
  tag gid: 'V-251799'
  tag rid: 'SV-251799r879588_rule'
  tag stig_id: 'TNDM-3X-000102'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-55213r810399_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  result = http("https://#{input('nsxManager')}/api/v1/node/services/snmp",
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
      its(['service_properties', 'v2_configured']) { should cmp 'false' }
    end
  end
end
