control 'VCPG-67-000022' do
  title 'Rsyslog must be configured to monitor VMware Postgres logs.'
  desc  "For performance reasons, rsyslog file monitoring is preferred over
configuring VMware Postgres to send events to a syslog facility. Without
ensuring that logs are created, that rsyslog configs are created, and that
those configs are loaded, the log file monitoring and shipping will not be
effective.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # cat /etc/vmware-syslog/stig-services-vpostgres.conf

    Expected result:

    input(type=\"imfile\"
    File=\"/var/log/vmware/vpostgres/serverlog.std*\"
    Tag=\"vpostgres-first\"
    Severity=\"info\"
    Facility=\"local0\")

    input(type=\"imfile\"
    File=\"/var/log/vmware/vpostgres/postgresql-*.log\"
    Tag=\"vpostgres\"
    Severity=\"info\"
    Facility=\"local0\")

    If the file does not exist, this is a finding.

    If the output of the command does not match the expected result above, this
is a finding.

    If there is no output from the command, vPostgres will default to
\"stderr\", and this is not a finding.
  "
  desc 'fix', "
    Navigate to and open /etc/vmware-syslog/stig-services-vpostgres.conf.

    Create the file if it does not exist.

    Set the contents of the file as follows:

    input(type=\"imfile\"
    File=\"/var/log/vmware/vpostgres/serverlog.std*\"
    Tag=\"vpostgres-first\"
    Severity=\"info\"
    Facility=\"local0\")

    input(type=\"imfile\"
    File=\"/var/log/vmware/vpostgres/postgresql-*.log\"
    Tag=\"vpostgres\"
    Severity=\"info\"
    Facility=\"local0\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag satisfies: ['SRG-APP-000359-DB-000319', 'SRG-APP-000360-DB-000320',
'SRG-APP-000092-DB-000208']
  tag gid: 'V-239214'
  tag rid: 'SV-239214r717064_rule'
  tag stig_id: 'VCPG-67-000022'
  tag fix_id: 'F-42406r679014_fix'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  describe file('/etc/vmware-syslog/stig-services-vpostgres.conf') do
    it { should exist }
  end
  describe command('grep -v "^#" /etc/vmware-syslog/stig-services-vpostgres.conf') do
    its('stdout') { should match "input(type=\"imfile\"\nFile=\"/var/log/vmware/vpostgres/serverlog.std*\"\nTag=\"vpostgres-first\"\nSeverity=\"info\"\nFacility=\"local0\")\n\ninput(type=\"imfile\"\nFile=\"/var/log/vmware/vpostgres/postgresql-*.log\"\nTag=\"vpostgres\"\nSeverity=\"info\"\nFacility=\"local0\")\n" }
  end
end
