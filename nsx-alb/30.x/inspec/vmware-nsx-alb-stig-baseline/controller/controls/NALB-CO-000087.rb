control 'NALB-CO-000087' do
  title 'The NSX Advanced Load Balancer Controller must off-load audit records onto a different system or media than the system being audited.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the NSX ALB controller is configured to send log data to a syslog server.

    From the NSX ALB Controller web interface go to Operations >> Notifications >> Syslog.

    If no syslog servers are defined or unapproved syslog servers are configured, this is a finding.

    From the NSX ALB Controller web interface go to Operations >> Alerts >> Alert Actions.

    If the \"Syslog-Config\" and \"Syslog-System\" alert actions do not a syslog server profile set, this is a finding.

    From the NSX ALB Controller web interface go to Operations >> Alerts >> Alert Config.

    If the \"Syslog-Config-Events\" alert configuration is not configured to use the \"Syslog-Config\" alert action, this is a finding.

    If the \"Syslog-System-Events\" alert configuration is not configured to use the \"Syslog-System\" alert action, this is a finding.
  "
  desc 'fix', "
    To configure a new syslog notification configuration, perform the following steps:

    From the NSX ALB Controller web Interface go to Operations >> Notification >> Syslog.

    Click the create button or edit an existing syslog configuration.

    Enter a name and add the appropriate syslog servers and click Save.

    To configure the alert actions to use the syslog configuration, perform the following steps:

    From the NSX ALB Controller web Interface go to Operations >> Alerts >> Alert Actions.

    Edit the \"Syslog-Config\" alert action and select the previously configure syslog notification profile and click Save.

    Repeat for the \"Syslog-System\" alert action.

    To configure the alert config to use the alert action, perform the following steps:

    From the NSX ALB Controller web Interface go to Operations >> Alerts >> Alert Config.

    Edit the \"Syslog-Config-Events\" alert configuration and select the \"Syslog-Config\" alert action as the alert action and click Save.

    Repeat for the \"Syslog-System-Events\" alert configuration.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag satisfies: ['SRG-APP-000516-NDM-000350']
  tag gid: 'V-NALB-CO-000087'
  tag rid: 'SV-NALB-CO-000087'
  tag stig_id: 'NALB-CO-000087'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  alertconfig = http("https://#{input('avicontroller')}/api/alertconfig",
    method: 'GET',
    headers: {
      'Accept-Encoding' => 'application/json',
      'X-Avi-Version' => "#{input('aviversion')}",
      'Cookie' => "sessionid=#{input('sessionCookieId')}",
    },
    ssl_verify: false)

  describe alertconfig do
    its('status') { should cmp 200 }
  end

  unless alertconfig.status != 200
    alert_configs = json(content: alertconfig.body).params['results']

    syslog_config_events = alert_configs.find { |config| config['name'] == 'Syslog-Config-Events' }

    describe 'Alert Configuration' do
      it 'Syslog Config Events should exist' do
        expect(syslog_config_events).not_to be_nil
      end
    end

    # Syslog Config
    syslog_config_url = syslog_config_events['action_group_ref']

    syslog_config_response = http(syslog_config_url,
      method: 'GET',
      headers: {
        'Accept-Encoding' => 'application/json',
        'X-Avi-Version' => "#{input('aviversion')}",
        'Cookie' => "sessionid=#{input('sessionCookieId')}",
      },
      ssl_verify: false)

    describe syslog_config_response do
      its('status') { should cmp 200 }
    end

    unless syslog_config_response.status != 200
      describe json(content: syslog_config_response.body) do
        it 'should have name "Syslog Config"' do
          expect(subject['name']).to eq('Syslog-Config')
        end
        it 'should have Syslog Configured' do
          expect(subject['syslog_config_ref']).not_to be_nil
        end
      end
    end

    syslog_config_response_json = json(content: syslog_config_response.body)
    syslog_config_server_url = syslog_config_response_json['syslog_config_ref']

    syslog_config_server_response = http(syslog_config_server_url,
      method: 'GET',
      headers: {
        'Accept-Encoding' => 'application/json',
        'X-Avi-Version' => "#{input('aviversion')}",
        'Cookie' => "sessionid=#{input('sessionCookieId')}",
      },
      ssl_verify: false)

    describe syslog_config_server_response do
      its('status') { should cmp 200 }
    end

    unless syslog_config_server_response.status != 200
      syslog_config_server = json(content: syslog_config_server_response.body)
      describe syslog_config_server do
        it 'Should not be empty' do
          expect(syslog_config_server).not_to be_nil
        end
        it 'Should have syslog Server configured' do
          expect(syslog_config_server['syslog_servers']).not_to be_nil
        end
      end

      if syslog_config_server
        expected_syslog_config_servers = input('allowed_syslog_servers')
        actual_syslog_config_servers = syslog_config_server['syslog_servers']

        if actual_syslog_config_servers.is_a?(Array)
          actual_syslog_config_servers.each do |server|
            syslog_server = server['syslog_server']

            describe 'Syslog' do
              it 'should have approved syslog servers' do
                expect(expected_syslog_config_servers).to include(syslog_server), "Syslog Server '#{syslog_server}' is not allowed"
              end
            end
          end
        else
          describe 'Syslog' do
            it 'should have syslog server information' do
              raise 'No syslog server information found'
            end
          end
        end
      end
    end

    # Syslog System
    syslog_system_events = alert_configs.find { |config| config['name'] == 'Syslog-System-Events' }

    describe 'Alert Configuration' do
      it 'Syslog System Events should exist' do
        expect(syslog_system_events).not_to be_nil
      end
    end

    syslog_system_url = syslog_system_events['action_group_ref']

    syslog_system_response = http(syslog_system_url,
      method: 'GET',
      headers: {
        'Accept-Encoding' => 'application/json',
        'X-Avi-Version' => "#{input('aviversion')}",
        'Cookie' => "sessionid=#{input('sessionCookieId')}",
      },
      ssl_verify: false)

    describe syslog_system_response do
      its('status') { should cmp 200 }
    end

    unless syslog_system_response.status != 200
      describe json(content: syslog_system_response.body) do
        it 'should have name "Syslog System"' do
          expect(subject['name']).to eq('Syslog-System')
        end
        it 'should have Syslog Configured' do
          expect(subject['syslog_config_ref']).not_to be_nil
        end
      end
    end

    syslog_system_response_json = json(content: syslog_system_response.body)
    syslog_system_server_url = syslog_system_response_json['syslog_config_ref']

    syslog_system_server_response = http(syslog_system_server_url,
      method: 'GET',
      headers: {
        'Accept-Encoding' => 'application/json',
        'X-Avi-Version' => "#{input('aviversion')}",
        'Cookie' => "sessionid=#{input('sessionCookieId')}",
      },
      ssl_verify: false)

    describe syslog_system_server_response do
      its('status') { should cmp 200 }
    end

    unless syslog_system_server_response.status != 200
      syslog_system_server = json(content: syslog_system_server_response.body)
      describe syslog_system_server do
        it 'Should not be empty' do
          expect(syslog_system_server).not_to be_nil
        end
        it 'Should have syslog Server configured' do
          expect(syslog_system_server['syslog_servers']).not_to be_nil
        end
      end

      if syslog_system_server
        expected_syslog_system_servers = input('allowed_syslog_servers')
        actual_syslog_system_servers = syslog_system_server['syslog_servers']

        if actual_syslog_system_servers.is_a?(Array)
          actual_syslog_system_servers.each do |server|
            syslog_server = server['syslog_server']

            describe 'Syslog' do
              it 'should have approved syslog servers' do
                expect(expected_syslog_system_servers).to include(syslog_server), "Syslog Server '#{syslog_server}' is not allowed"
              end
            end
          end
        else
          describe 'Syslog' do
            it 'should have syslog server information' do
              raise 'No syslog server information found'
            end
          end
        end
      end
    end
  end
end
