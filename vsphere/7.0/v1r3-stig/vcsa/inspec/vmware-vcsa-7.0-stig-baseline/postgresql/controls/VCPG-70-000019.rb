control 'VCPG-70-000019' do
  title '"Rsyslog" must be configured to monitor VMware Postgres logs.'
  desc 'For performance reasons, "rsyslog" file monitoring is preferred over configuring VMware Postgres to send events to a "syslog" facility. Without ensuring that logs are created, that "rsyslog" configs are created, and that those configs are loaded, the log file monitoring and shipping will not be effective.

'
  desc 'check', 'At the command prompt, run the following command:

# rpm -V VMware-Postgres-cis-visl-scripts|grep -E "vmware-services-vmware-vpostgres.conf|vmware-services-vmware-postgres-archiver.conf" | grep "^..5......"

If the command returns any output, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware-syslog/vmware-services-vmware-vpostgres.conf

Create the file if it does not exist.

Set the contents of the file as follows:

# vmware-vpostgres first logs, before loading configuration
input(type="imfile"
      File="/var/log/vmware/vpostgres/serverlog.std*"
      Tag="vpostgres-first"
      Severity="info"
      Facility="local0")
# vmware-vpostgres logs
input(type="imfile"
      File="/var/log/vmware/vpostgres/postgresql-*.log"
      Tag="vpostgres"
      Severity="info"
      Facility="local0")

Navigate to and open:

/etc/vmware-syslog/vmware-services-vmware-postgres-archiver.conf

Create the file if it does not exist.

Set the contents of the file as follows:

# vmware-postgres-archiver logs
input(type="imfile"
      File="/var/log/vmware/vpostgres/pg_archiver.log.std*"
      Tag="postgres-archiver"
      Severity="info"
      Facility="local0")'
  impact 0.5
  tag check_id: 'C-60284r887611_chk'
  tag severity: 'medium'
  tag gid: 'V-256609'
  tag rid: 'SV-256609r887613_rule'
  tag stig_id: 'VCPG-70-000019'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-60227r887612_fix'
  tag satisfies: ['SRG-APP-000359-DB-000319', 'SRG-APP-000360-DB-000320', 'SRG-APP-000515-DB-000318']
  tag cci: ['CCI-001851', 'CCI-001855', 'CCI-001858']
  tag nist: ['AU-4 (1)', 'AU-5 (1)', 'AU-5 (2)']

  describe command('rpm -V VMware-Postgres-cis-visl-scripts|grep -E "vmware-services-vmware-vpostgres.conf|vmware-services-vmware-postgres-archiver.conf" | grep "^..5......"') do
    its('stdout.strip') { should cmp '' }
  end
end
