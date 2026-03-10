control 'PSQL-00-000122' do
  title 'The Cloud Director PostgreSQL database must off-load audit data to a separate log management facility.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.

    The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # grep -v \"^\" /etc/rsyslog.d/stig-services-postgres.conf

    Expected result:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
    File=\"/var/vmware/vpostgres/current/pgdata/log/*.log\"
    Tag=\"postgres-runtime\"
    Severity=\"info\"
    Facility=\"local0\")

    If the file does not exist, this is a finding.

    If the output of the command does not match the expected result above, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/rsyslog.d/stig-services-postgres.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
    File=\"/var/vmware/vpostgres/current/pgdata/log/*.log\"
    Tag=\"postgres-runtime\"
    Severity=\"info\"
    Facility=\"local0\")

    At the command prompt, run the following command:

    # systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag satisfies: ['SRG-APP-000745-DB-000120', 'SRG-APP-000795-DB-000130']
  tag gid: 'V-PSQL-00-000122'
  tag rid: 'SV-PSQL-00-000122'
  tag stig_id: 'PSQL-00-000122'
  tag cci: ['CCI-001851', 'CCI-003821', 'CCI-003831']
  tag nist: ['AU-4 (1)', 'AU-6 (4)', 'AU-9 b']

  goodcontent = inspec.profile.file('stig-services-postgres.conf')
  describe file('/etc/rsyslog.d/stig-services-postgres.conf') do
    its('content') { should eq goodcontent }
  end
end
