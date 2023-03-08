control 'NMGR-4X-000067' do
  title 'The NSX Manager must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc  "
    The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

    Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

    DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to System >> Fabric >> Profiles >> Node Profiles.

    Click \"All NSX Nodes\" and verify the NTP servers listed.

    or

    From an NSX Manager shell, run the following command:

    > get ntp-server

    If the output does not contain at least two authoritative time sources, this is a finding.

    If the output contains unknown or non-authoritative time sources, this is a finding.
  "
  desc 'fix', "
    To configure a profile to apply NTP servers to all NSX Manager nodes, do the following:

    From the NSX Manager web interface, go to System >> Fabric >> Profiles >> Node Profiles.

    Click \"All NSX Nodes\" and then click \"Edit\".

    Under NTP servers, remove any unknown or non-authoritative NTP servers, enter at least two authoritative servers, and then click \"Save\".

    or

    From an NSX Manager shell, run the following commands:

    > del ntp-server <server-ip or server-name>
    > set ntp-server <server-ip or server-name>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag gid: 'V-NMGR-4X-000067'
  tag rid: 'SV-NMGR-4X-000067'
  tag stig_id: 'NMGR-4X-000067'
  tag cci: ['CCI-001893']
  tag nist: ['AU-8 (2)']

  result = http("https://#{input('nsxManager')}/api/v1/node/services/ntp",
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
      its(['service_properties', 'start_on_boot']) { should cmp 'true' }
      its(['service_properties', 'servers']) { should include "#{input('ntpServer1')}" }
      its(['service_properties', 'servers']) { should include "#{input('ntpServer2')}" }
    end
  end
end
