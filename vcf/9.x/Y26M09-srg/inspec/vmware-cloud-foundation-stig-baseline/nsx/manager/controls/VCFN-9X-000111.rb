control 'VCFN-9X-000111' do
  title 'The VMware Cloud Foundation NSX Manager must be configured to synchronize system clocks with an authoritative time source.'
  desc  'Time synchronization of system clocks is essential for the correct execution of many system services, including identification and authentication processes that involve certificates and time-of-day restrictions as part of access control. Denial of service or failure to deny expired credentials may result without properly synchronized clocks within and between systems and system components. Time is commonly expressed in Coordinated Universal Time (UTC), a modern continuation of Greenwich Mean Time (GMT), or local time with an offset from UTC. The granularity of time measurements refers to the degree of synchronization between system clocks and reference clocks, such as clocks synchronizing within hundreds of milliseconds or tens of milliseconds. Organizations may define different time granularities for system components. Time service can be critical to other security capabilities such as access control and identification and authentication depending on the nature of the mechanisms used to support the capabilities.'
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to System >> Configuration >> Fabric >> Profiles >> Node Profiles.

    Click \"All NSX Nodes\" and verify the NTP servers listed.

    or

    From an NSX Manager shell, run the following command:

    > get ntp-servers

    If the NTP servers listed are not a site specific authoritative time source, this is a finding.
  "
  desc 'fix', "
    To configure a profile to apply NTP servers to all NSX Manager nodes, do the following:

    From the NSX Manager web interface, go to System >> Configuration >> Fabric >> Profiles >> Node Profiles.

    Click \"All NSX Nodes\" and then click \"Edit\".

    Under NTP servers, remove any unknown or nonauthoritative NTP servers, enter authoritative NTP servers, and then click \"Save\".

    or

    From an NSX Manager shell, run the following commands:

    > del ntp-server <server-ip or server-name>
    > set ntp-server <server-ip or server-name>

    Note: It is recommended to configure 1 or 3 or more NTP servers to help prevent \"split-brain\" scenarios.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000920-NDM-000320'
  tag satisfies: ['SRG-APP-000925-NDM-000330']
  tag gid: 'V-VCFN-9X-000111'
  tag rid: 'SV-VCFN-9X-000111'
  tag stig_id: 'VCFN-9X-000111'
  tag cci: ['CCI-004922', 'CCI-004923']
  tag nist: ['SC-45', 'SC-45 (1) (a)']

  result = http("https://#{input('nsx_managerAddress')}/api/v1/node/services/ntp",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    ntpresults = JSON.parse(result.body)
    if ntpresults['service_properties']['servers'].empty?
      describe 'The number of ntp servers' do
        subject { ntpresults['service_properties']['servers'] }
        it { should_not be_empty }
      end
    else
      describe 'The NTP service should start on boot' do
        subject { ntpresults['service_properties']['start_on_boot'] }
        it { should cmp 'true' }
      end
      ntpresults['service_properties']['servers'].each do |ntpserver|
        describe "NTP Server: #{ntpserver}" do
          subject { ntpserver }
          it { should be_in "#{input('nsx_ntpServers')}" }
        end
      end
    end
  end
end
