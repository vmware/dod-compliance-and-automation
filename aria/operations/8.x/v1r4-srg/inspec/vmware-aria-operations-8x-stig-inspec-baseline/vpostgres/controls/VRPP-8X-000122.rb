control 'VRPP-8X-000122' do
  title 'VMware Aria Operations vPostgres must off-load audit data to a separate log management facility.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.

    vPostgres may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.
  "
  desc  'rationale', ''
  desc  'check', "
    If logs are shipped to a syslog server via another method such as rsyslog, this is Not Applicable.

    As a database administrator, run the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW log_destination;\\\"\"

    Example result:

    stderr,syslog

    If 'log_destination' does not include syslog, this is a finding.
  "
  desc 'fix', "
    As a database administrator, run the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"ALTER SYSTEM SET log_destination = 'syslog';\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"ALTER SYSTEM SET syslog_facility = 'local6';\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"ALTER SYSTEM SET syslog_ident = 'vpostgres-repl';\\\"\"

    Note: There can be more than one option set for log_destination and values should be comma separated.
    Note: Configure the syslog_facility as appropriate for your environment.

    Reload the vPostgres service by running the following command:

    # systemctl restart vpostgres-repl.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag gid: 'V-VRPP-8X-000122'
  tag rid: 'SV-VRPP-8X-000122'
  tag stig_id: 'VRPP-8X-000122'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  syslog_enabled = input('syslog_enabled')
  if syslog_enabled
    describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW log_destination;\"'") do
      its('stdout.strip') { should include 'syslog' }
    end
  else
    describe 'For PostgreSQL installations that ship logs via another method such as rsyslog, this is Not Applicable.' do
      skip 'For PostgreSQL installations that ship logs via another method such as rsyslog, this is Not Applicable.'
    end
  end
end
