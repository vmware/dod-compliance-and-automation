control 'WOAD-3X-000004' do
  title 'The Workspace ONE Access vPostgres instance must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc  "
    Authentication with a DoD-approved PKI certificate does not necessarily imply authorization to access the DBMS.  To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems, including databases, must be properly configured to implement access control policies.

    Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

    Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

    This requirement is applicable to access control enforcement applications, a category that includes database management systems.  If the DBMS does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    #/opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"\\du;\"

    Expected result:

    For non-clustered deployments:

                                       List of roles
     Role name |                         Attributes                         | Member of
    -----------+------------------------------------------------------------+-----------
     horizon   |                                                            | {}
     postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS | {}

    For clustered deployments:

                                       List of roles
     Role name |                         Attributes                         | Member of
    -----------+------------------------------------------------------------+-----------
     horizon   |                                                            | {}
     pgpool    |                                                            | {}
     postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS | {}
     repl      | Replication                                                | {}

    If the output does not match the expected result, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"DROP USER IF EXISTS <user>;\"

    Replace <user> with the account discovered during the check.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag satisfies: ['SRG-APP-000133-DB-000362']
  tag gid: 'V-WOAD-3X-000004'
  tag rid: 'SV-WOAD-3X-000004'
  tag stig_id: 'WOAD-3X-000004'
  tag cci: ['CCI-000213', 'CCI-001499']
  tag nist: ['AC-3', 'CM-5 (6)']

  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -c "\du;"') do
      its('stdout.strip') { should cmp "horizon||{}\npostgres|Superuser, Create role, Create DB, Replication, Bypass RLS|{}" }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = '\\du;'

    describe sql.query(sqlquery) do
      its('output') { should cmp "horizon||{}\npostgres|Superuser, Create role, Create DB, Replication, Bypass RLS|{}" }
    end
  end
end
