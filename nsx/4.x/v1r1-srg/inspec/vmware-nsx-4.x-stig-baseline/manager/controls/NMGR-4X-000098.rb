control 'NMGR-4X-000098' do
  title 'The NSX Manager must disable SNMP v2.'
  desc  'SNMPv3 supports commercial-grade security, including authentication, authorization, access control, and privacy. Previous versions of the protocol contained well-known security weaknesses that were easily exploited. As such, SNMPv1/2 receivers must be disabled.'
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to the System >> Fabric >> Profiles >> Node Profiles.

    Click \"All NSX Nodes\" and view the SNMP Polling and Traps configuration.

    If SNMP v2c Polling or Traps are configured, this is a finding.
  "
  desc 'fix', "
    From the NSX Manager web interface, go to the System >> Fabric >> Profiles >> Node Profiles.

    Click on \"All NSX Nodes\" and delete and v2c Polling or Trap configurations.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag gid: 'V-NMGR-4X-000098'
  tag rid: 'SV-NMGR-4X-000098'
  tag stig_id: 'NMGR-4X-000098'
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
