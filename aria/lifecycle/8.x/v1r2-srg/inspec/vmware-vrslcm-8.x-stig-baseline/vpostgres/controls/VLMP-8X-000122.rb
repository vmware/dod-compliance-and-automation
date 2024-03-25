control 'VLMP-8X-000122' do
  title 'VMware Aria Suite Lifecycle vpostgres must off-load audit data to a separate log management facility.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.

    The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.
  "
  desc  'rationale', ''
  desc  'check', "
    If logs are shipped to a syslog server via another method such as rsyslog, this is Not Applicable.

    As a database administrator, perform the following at the command prompt:

    $ /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW log_destination\"

    Example result:

    stderr, syslog

    If \"log_destination\" does not include syslog, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    $ /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET log_destination = 'syslog';\"
    $ /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET syslog_facility = 'LOCAL0';\"
    $ /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET syslog_ident = 'postgres';\"

    Note: There can be more than one option set for log_destination and values should be comma separated.

    Note: Configure the syslog_facility as appropriate for your environment.

    Restart the vpostgres service by running the following command:

    # systemctl restart vpostgres.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag satisfies: ['SRG-APP-000092-DB-000208']
  tag gid: 'V-VLMP-8X-000122'
  tag rid: 'SV-VLMP-8X-000122'
  tag stig_id: 'VLMP-8X-000122'
  tag cci: ['CCI-001464', 'CCI-001851']
  tag nist: ['AU-14 (1)', 'AU-4 (1)']

  syslog_enabled = input('syslog_enabled')
  if syslog_enabled
    sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
    describe sql.query('SHOW log_destination;', ["#{input('postgres_default_db')}"]) do
      its('output') { should include 'syslog' }
    end
  else
    describe 'For PostgreSQL installations that ship logs via another method such as rsyslog, this is Not Applicable.' do
      skip 'For PostgreSQL installations that ship logs via another method such as rsyslog, this is Not Applicable.'
    end
  end
end
