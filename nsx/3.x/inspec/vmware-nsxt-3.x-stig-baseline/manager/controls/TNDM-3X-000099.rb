control 'TNDM-3X-000099' do
  title 'The NSX-T Manager must disable SSH.'
  desc 'The NSX-T shell provides temporary access to commands essential for server maintenance. Intended primarily for use in break-fix scenarios, the NSX-T shell is well suited for checking and modifying configuration details, not always generally accessible, using the web interface. The NSX-T shell is accessible remotely using SSH. Under normal operating conditions, SSH access to the managers must be disabled as is the default. As with the NSX-T shell, SSH is also intended only for temporary use during break-fix scenarios. SSH must therefore be disabled under normal operating conditions and must only be enabled for diagnostics or troubleshooting. Remote access to the managers must therefore be limited to the web interface and API at all other times.'
  desc 'check', 'From an NSX-T Manager shell, run the following command(s):

> get service ssh

Expected results:
Service name:      ssh
Service state:     stopped
Start on boot:     False

If the output does not match the expected results, this is a finding.'
  desc 'fix', 'From an NSX-T Manager shell, run the following command(s):

> stop service ssh
> clear service ssh start-on-boot'
  impact 0.3
  tag check_id: 'C-55256r810389_chk'
  tag severity: 'low'
  tag gid: 'V-251796'
  tag rid: 'SV-251796r879588_rule'
  tag stig_id: 'TNDM-3X-000099'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-55210r810390_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  result = http("https://#{input('nsxManager')}/api/v1/node/services/ssh/status",
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
      its('runtime_state') { should cmp 'stopped' }
    end
  end

  result = http("https://#{input('nsxManager')}/api/v1/node/services/ssh",
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
      its(['service_properties', 'start_on_boot']) { should cmp 'false' }
    end
  end
end
