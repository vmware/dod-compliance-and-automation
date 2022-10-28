control 'VCPG-70-000019' do
  title 'Rsyslog must be configured to monitor VMware Postgres logs.'
  desc  'For performance reasons, rsyslog file monitoring is preferred over configuring VMware Postgres to send events to a syslog facility. Without ensuring that logs are created, that rsyslog configs are create and that those configs are loaded, the log file monitoring and shipping will not be effective.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V VMware-Postgres-cis-visl-scripts|grep -E \"vmware-services-vmware-vpostgres.conf|vmware-services-vmware-postgres-archiver.conf\" | grep \"^..5......\"

    If the command returns any output, this is a finding.
  "
  desc 'fix', "
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
  tag satisfies: ['SRG-APP-000360-DB-000320', 'SRG-APP-000515-DB-000318']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000019'
  tag cci: ['CCI-001851', 'CCI-001855', 'CCI-001858']
  tag nist: ['AU-4 (1)', 'AU-5 (1)', 'AU-5 (2)']

  describe command('rpm -V VMware-Postgres-cis-visl-scripts|grep -E "vmware-services-vmware-vpostgres.conf|vmware-services-vmware-postgres-archiver.conf" | grep "^..5......"') do
    its('stdout.strip') { should cmp '' }
  end
end
