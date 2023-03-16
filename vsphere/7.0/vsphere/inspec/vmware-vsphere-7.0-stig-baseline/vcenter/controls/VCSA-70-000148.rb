control 'VCSA-70-000148' do
  title 'The vCenter Server must be configured to send logs to a central log server.'
  desc  'vCenter must be configured to send near real-time log data to syslog collectors so information will be available to investigators in the case of a security incident or to assist in troubleshooting.'
  desc  'rationale', ''
  desc  'check', "
    Open the Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

    Log in with local operating system administrative credentials or with a Single Sign-On (SSO) account that is a member of the \"SystemConfiguration.BashShellAdministrator\" group.

    Select \"Syslog\" on the left navigation pane.

    On the resulting pane on the right, verify at least one site-specific syslog receiver is configured and is listed as \"Reachable\".

    If no valid syslog collector is configured or if the collector is not listed as \"Reachable\", this is a finding.
  "
  desc 'fix', "
    Open the VAMI by navigating to https://<vCenter server>:5480.

    Log in with local operating system administrative credentials or with an SSO account that is a member of the \"SystemConfiguration.BashShellAdministrator\" group.

    Select \"Syslog\" on the left navigation pane.

    On the resulting pane on the right, click \"Edit\" or \"Configure\".

    Edit or add the address and port of a site-specific syslog aggregator or Security Information Event Management (SIEM) system with the appropriate protocol.

    User Datagram Protocol (UDP) is discouraged due to its stateless and unencrypted nature. Transport Layer Security (TLS) is preferred.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358'
  tag gid: 'V-256339'
  tag rid: 'SV-256339r885628_rule'
  tag stig_id: 'VCSA-70-000148'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  # Check syslog servers
  result = http("https://#{input('vcURL')}/api/appliance/logging/forwarding",
              method: 'GET',
              headers: {
                'vmware-api-session-id' => "#{input('vcApiToken')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe result.body do
      it { should_not cmp '[]' }
    end
    servers = JSON.parse(result.body)
    servers.each do |server|
      describe server do
        its(['hostname']) { should be_in input('syslogServers') }
      end
    end
  end
  # Check status of syslog servers
  result = http("https://#{input('vcURL')}/api/appliance/logging/forwarding?action=test",
              method: 'POST',
              headers: {
                'vmware-api-session-id' => "#{input('vcApiToken')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe result.body do
      it { should_not cmp '[]' }
    end
    servers = JSON.parse(result.body)
    servers.each do |server|
      describe server do
        its(['state']) { should cmp 'UP' }
      end
    end
  end
end
