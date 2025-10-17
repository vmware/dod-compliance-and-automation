control 'CDAP-10-000036' do
  title 'VMware Cloud Director must disable SNMP if not used.'
  desc  'Application servers provide a myriad of differing processes, features and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system. Application servers must provide the capability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance, for example, disabling dynamic JSP reloading on production application servers as a best practice.'
  desc  'rationale', ''
  desc  'check', "
    Verify SNMP is disabled by running the following command on each appliance:

    # vicfg-snmp --show

    Example output:

    Current SNMP agent setting
    Enabled                 : false
    UDP port                : 161
    V1/V2c Communities      :
    V2c Notification targets :
    Notification filter oids:
    V3 Notification targets :
    V3 Users                :
    Contact                 :
    Location                :
    Engine ID               :
    Auth Protocol           : usmNoAuthProtocol
    Priv Protocol           : usmNoPrivProtocol
    Log level               : warning
    Process ID              : n/a
    Large Storage Support   : False
    Simple Application Names: True

    If SNMP is enabled and not in use, this is a finding.

    If SNMP is enabled and configured to use V1 or V2c, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command to disable SNMP:

    # vicfg-snmp --disable

    If V1/V2c is configured migrate the configuration to V3 if SNMP is needed.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-CDAP-10-000036'
  tag rid: 'SV-CDAP-10-000036'
  tag stig_id: 'CDAP-10-000036'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  snmpEnabled = input('snmpEnabled')
  snmpInfo = command('vicfg-snmp --show').stdout.strip
  if snmpEnabled
    describe snmpInfo do
      it { should match /Enabled.*: true/ }
      it { should match %r{V1/V2c Communities.*: \n} }
      it { should match /V2c Notification targets.*: \n/ }
    end
  else
    describe snmpInfo do
      it { should match /Enabled.*: false/ }
    end
  end
end
