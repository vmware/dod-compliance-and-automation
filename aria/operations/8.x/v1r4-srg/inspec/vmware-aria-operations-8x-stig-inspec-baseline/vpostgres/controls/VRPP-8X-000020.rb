control 'VRPP-8X-000020' do
  title 'VMware Aria Operations vPostgres must be configured to protect log files from unauthorized access.'
  desc  "
    If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

    To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.
  "
  desc  'rationale', ''
  desc  'check', "
    If vPostgres is logging directly to syslog and not storing audit data locally, this control is Not Applicable.

    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW log_file_mode;\\\"\"

    Expected result:

    0600

    If the output does not match the expected result, this is a finding.

    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW log_directory;\\\"\"

    The log directory may be a relative path to the 'data_directory' setting, which can be found by running the following command:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW data_directory;\\\"\"

    After finding the log destination, execute the following command:

    $ find <log dir>/* -xdev -type f -a '(' -not -perm 600 -o -not -user postgres -o -not -group users ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -c \\\"ALTER SYSTEM SET log_file_mode = '0600';\\\"\"

    Reload the vPostgres service by running the following command:

    # systemctl restart vpostgres-repl.service

    At the command prompt, enter the following command(s):

    # chmod 600 <file>
    # chown postgres:users <file>

    Note: Replace <file> with the file path of the file with incorrect permissions.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag satisfies: ['SRG-APP-000119-DB-000060', 'SRG-APP-000120-DB-000061']
  tag gid: 'V-VRPP-8X-000020'
  tag rid: 'SV-VRPP-8X-000020'
  tag stig_id: 'VRPP-8X-000020'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a']

  pg_log_dir = input('pg_log_dir')
  pg_owner = input('pg_owner')
  pg_group = input('pg_group')

  describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW log_file_mode;\"'") do
    its('stdout.strip') { should cmp '0600' }
  end

  logfiles = command("find #{pg_log_dir}/* -xdev -type f")

  logfiles.stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp pg_owner }
      its('group') { should cmp pg_group }
    end
  end
end
