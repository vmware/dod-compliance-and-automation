control 'VLIC-8X-000012' do
  title 'The Aria Operations for Logs Cassandra database must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.'
  desc  "
    Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceed the rights of a regular user.

    DBMS functionality and the nature and requirements of databases will vary; so while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. The requirements for production servers will be more restrictive than those used for development and research.

    The DBMS must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization).

    In the case of a database management system, this requirement covers stored procedures, functions, triggers, views, etc.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # /usr/lib/loginsight/application/lib/apache-cassandra-<VERSION>/bin/cqlsh-no-pass -e \"SELECT role FROM system_auth.roles WHERE is_superuser = True ALLOW FILTERING;\"

    Expected result:

     role
    ---------
     lisuper

    (1 rows)

    If the output does not match the expected result, this is a finding.

    If no lines are returned this is NOT a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command for each unexpected user:

    # /usr/lib/loginsight/application/lib/apache-cassandra-<VERSION>/bin/cqlsh-no-pass -e \"DROP USER <user>;\"

    Note: Replace <user> with each unexpected user returned from the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000378-DB-000365'
  tag gid: 'V-VLIC-8X-000012'
  tag rid: 'SV-VLIC-8X-000012'
  tag stig_id: 'VLIC-8X-000012'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']

  describe.one do
    describe command("#{input('cassandraroot')}/bin/cqlsh-no-pass -e \"SELECT role FROM system_auth.roles WHERE is_superuser = True ALLOW FILTERING;\"") do
      its('stdout.strip') { should include 'lisuper' }
      its('stdout.strip') { should include '(1 rows)' }
    end
    describe command("#{input('cassandraroot')}/bin/cqlsh-no-pass -e \"SELECT role FROM system_auth.roles WHERE is_superuser = True ALLOW FILTERING;\"") do
      its('stdout.strip') { should include '(0 rows)' }
    end
  end
end
