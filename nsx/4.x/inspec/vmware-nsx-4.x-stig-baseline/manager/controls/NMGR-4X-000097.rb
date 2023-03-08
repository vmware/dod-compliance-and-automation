control 'NMGR-4X-000097' do
  title 'The NSX Manager must disable SSH.'
  desc  'The NSX shell provides temporary access to commands essential for server maintenance. Intended primarily for use in break-fix scenarios, the NSX shell is well suited for checking and modifying configuration details, not always generally accessible, using the web interface. The NSX shell is accessible remotely using SSH. Under normal operating conditions, SSH access to the managers must be disabled as is the default. As with the NSX shell, SSH is also intended only for temporary use during break-fix scenarios. SSH must therefore be disabled under normal operating conditions and must only be enabled for diagnostics or troubleshooting. Remote access to the managers must therefore be limited to the web interface and API at all other times.'
  desc  'rationale', ''
  desc  'check', "
    From an NSX Manager shell, run the following command:

    > get service ssh

    Expected results:
    Service name: ssh
    Service state: stopped
    Start on boot: False

    If the SSH server is not stopped or starts on boot, this is a finding.
  "
  desc 'fix', "
    From an NSX Manager shell, run the following command(s):

    > stop service ssh
    > clear service ssh start-on-boot
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag gid: 'V-NMGR-4X-000097'
  tag rid: 'SV-NMGR-4X-000097'
  tag stig_id: 'NMGR-4X-000097'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
