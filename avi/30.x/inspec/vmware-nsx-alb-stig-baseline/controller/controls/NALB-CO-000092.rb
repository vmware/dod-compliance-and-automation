control 'NALB-CO-000092' do
  title 'The NSX Advanced Load Balancer Controller must be configured to to conduct backups.'
  desc  "
    System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

    This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the NSX ALB configuration to determine if the device is configured to conduct backups.

    From the NSX ALB Controller web interface navigate to Administration >> Controller >> Configuration Backup.

    If configuration backups are not enabled, this is a finding.

    If a remote backup server is not configured and enabled, this is a finding.
  "
  desc 'fix', "
    From the NSX ALB Controller web interface navigate to Administration >> Controller >> Configuration Backup.

    Click Edit.

    Check the \"Enable Configuration Backup\" box.

    Provide a passphrase and frequency for the backups to occur.

    Check the \"Enable Remote Server Backup\" box and enter the remote server connection information then click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag satisfies: ['SRG-APP-000516-NDM-000341']
  tag gid: 'V-NALB-CO-000092'
  tag rid: 'SV-NALB-CO-000092'
  tag stig_id: 'NALB-CO-000092'
  tag cci: ['CCI-000366', 'CCI-000539']
  tag nist: ['CM-6 b', 'CP-9 (c)  ']

  # Check for configuration backups
  results = http("https://#{input('avicontroller')}/api/scheduler",
                  method: 'GET',
                  headers: {
                    'Accept-Encoding' => 'application/json',
                    'X-Avi-Version' => "#{input('aviversion')}",
                    'Cookie' => "sessionid=#{input('sessionCookieId')}",
                  },
                  ssl_verify: false)

  describe results do
    its('status') { should cmp 200 }
  end

  unless results.status != 200
    resultsjson = JSON.parse(results.body)
    if resultsjson['results'] == []
      describe 'No backup schedules found...skipping.' do
        skip 'No backup schedules found...skipping.'
      end
    else
      resultsjson['results'].each do |result|
        describe 'Configuration backups enabled' do
          subject { result['enabled'] }
          it { should cmp true }
        end
      end
    end
  end

  # Check for remote backups
  results2 = http("https://#{input('avicontroller')}/api/backupconfiguration",
                  method: 'GET',
                  headers: {
                    'Accept-Encoding' => 'application/json',
                    'X-Avi-Version' => "#{input('aviversion')}",
                    'Cookie' => "sessionid=#{input('sessionCookieId')}",
                  },
                  ssl_verify: false)

  describe results2 do
    its('status') { should cmp 200 }
  end

  unless results2.status != 200
    results2json = JSON.parse(results2.body)
    if results2json['results'] == []
      describe 'No backup configuration found...skipping.' do
        skip 'No backup configuration found...skipping.'
      end
    else
      results2json['results'].each do |result|
        describe 'Remote backups enabled' do
          subject { result['upload_to_remote_host'] }
          it { should cmp true }
        end
      end
    end
  end
end
