control 'NMGR-4X-000098' do
  title 'The NSX Manager must disable SNMP v2.'
  desc 'SNMPv3 supports commercial-grade security, including authentication, authorization, access control, and privacy. Previous versions of the protocol contained well-known security weaknesses that were easily exploited. As such, SNMPv1/2 receivers must be disabled.'
  desc 'check', 'From the NSX Manager web interface, go to the System >> Configuration >> Fabric >> Profiles >> Node Profiles.

Click "All NSX Nodes" and view the SNMP Polling and Traps configuration.

If SNMP v2c Polling or Traps are configured, this is a finding.'
  desc 'fix', 'From the NSX Manager web interface, go to the System >> Configuration >> Fabric >> Profiles >> Node Profiles.

Click on "All NSX Nodes" and delete and v2c Polling or Trap configurations.'
  impact 0.5
  ref 'DPMS Target VMware NSX 4.x Manager NDM'
  tag check_id: 'C-69271r994283_chk'
  tag severity: 'medium'
  tag gid: 'V-265354'
  tag rid: 'SV-265354r994285_rule'
  tag stig_id: 'NMGR-4X-000098'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-69179r994284_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
