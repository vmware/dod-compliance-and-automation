control 'VCPG-80-000122' do
  title 'The vCenter PostgreSQL service must off-load audit data to a separate log management facility.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.

    The database management system (DBMS) may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.
  "
  desc  'rationale', ''
  desc  'check', "
    By default there is a vmware-services-vmware-vpostgres.conf rsyslog and vmware-services-vmware-postgres-archiver.conf configuration file that includes the service logs when syslog is configured on vCenter but it must be verified.

    At the command prompt, run the following command:

    # cat /etc/vmware-syslog/vmware-services-vmware-vpostgres.conf

    Expected result:

    # vmware-vpostgres first logs stdout, before loading configuration
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/serverlog.stdout\"
          Tag=\"vpostgres-first\"
          Severity=\"info\"
          Facility=\"local0\")
    # vmware-vpostgres first logs stderr, before loading configuration
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/serverlog.stderr\"
          Tag=\"vpostgres-first\"
          Severity=\"info\"
          Facility=\"local0\")
    # vmware-vpostgres logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/postgresql-*.log\"
          Tag=\"vpostgres\"
          Severity=\"info\"
          Facility=\"local0\")

    If the output does not match the expected result, this is a finding.

    At the command prompt, run the following command:

    # cat /etc/vmware-syslog/vmware-services-vmware-postgres-archiver.conf

    Expected result:

    # vmware-postgres-archiver stdout log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/pg_archiver.log.stdout\"
          Tag=\"postgres-archiver\"
          Severity=\"info\"
          Facility=\"local0\")
    # vmware-postgres-archiver stderr log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/pg_archiver.log.stderr\"
          Tag=\"postgres-archiver\"
          Severity=\"info\"
          Facility=\"local0\")

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware-syslog/vmware-services-vmware-vpostgres.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    # vmware-vpostgres first logs stdout, before loading configuration
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/serverlog.stdout\"
          Tag=\"vpostgres-first\"
          Severity=\"info\"
          Facility=\"local0\")
    # vmware-vpostgres first logs stderr, before loading configuration
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/serverlog.stderr\"
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

    # vmware-postgres-archiver stdout log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/pg_archiver.log.stdout\"
          Tag=\"postgres-archiver\"
          Severity=\"info\"
          Facility=\"local0\")
    # vmware-postgres-archiver stderr log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vpostgres/pg_archiver.log.stderr\"
          Tag=\"postgres-archiver\"
          Severity=\"info\"
          Facility=\"local0\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag gid: 'V-VCPG-80-000122'
  tag rid: 'SV-VCPG-80-000122'
  tag stig_id: 'VCPG-80-000122'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  goodcontent = inspec.profile.file('vmware-services-vmware-vpostgres.conf')
  describe file('/etc/vmware-syslog/vmware-services-vmware-vpostgres.conf') do
    its('content') { should eq goodcontent }
  end
  goodcontentarch = inspec.profile.file('vmware-services-vmware-postgres-archiver.conf')
  describe file('/etc/vmware-syslog/vmware-services-vmware-postgres-archiver.conf') do
    its('content') { should eq goodcontentarch }
  end
end
