# encoding: UTF-8

control 'VCPG-70-000019' do
  title 'Rsyslog must be configured to monitor VMware Postgres logs.'
  desc  "For performance reasons, rsyslog file monitoring is preferred over
configuring VMware Postgres to send events to a syslog facility. Without
ensuring that logs are created, that rsyslog configs are create and that those
configs are loaded, the log file monitoring and shipping will not be effective."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V VMware-Postgres-cis-visl-scripts|grep -E
\"vmware-services-vmware-vpostgres.conf|vmware-services-vmware-postgres-archiver.conf\"
| grep \"^..5......\"

    If the command returns any output, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /etc/vmware-syslog/vmware-services-vmware-vpostgres.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    # vmware-vpostgres first logs, before loading configuration
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/serverlog.std*\"
          Tag=\"vpostgres-first\"
          Severity=\"info\"
          Facility=\"local0\")
    # vmware-vpostgres logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/postgresql-*.log\"
          Tag=\"vpostgres\"
          Severity=\"info\"
          Facility=\"local0\")

    Navigate to and open:

    /etc/vmware-syslog/vmware-services-vmware-postgres-archiver.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    # vmware-postgres-archiver logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/pg_archiver.log.std*\"
          Tag=\"postgres-archiver\"
          Severity=\"info\"
          Facility=\"local0\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000019'
  tag fix_id: nil
  tag cci: 'CCI-001855'
  tag nist: ['AU-5 (1)']

  describe file('/etc/vmware-syslog/stig-services-vpostgres.conf') do
    it { should exist }
  end
  describe command('grep -v "^#" /etc/vmware-syslog/stig-services-vpostgres.conf') do
    its ('stdout') { should match "input(type=\"imfile\"\nFile=\"/var/log/vmware/vpostgres/serverlog.std*\"\nTag=\"vpostgres-first\"\nSeverity=\"info\"\nFacility=\"local0\")\n\ninput(type=\"imfile\"\nFile=\"/var/log/vmware/vpostgres/postgresql-*.log\"\nTag=\"vpostgres\"\nSeverity=\"info\"\nFacility=\"local0\")\n" }
  end

end

