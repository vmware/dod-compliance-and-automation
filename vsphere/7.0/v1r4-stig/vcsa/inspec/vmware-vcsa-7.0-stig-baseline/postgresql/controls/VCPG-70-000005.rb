control 'VCPG-70-000005' do
  title 'The VMware Postgres database must protect log files from unauthorized access and modification.'
  desc 'If audit data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could use to their advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from all unauthorized access. This includes read, write, copy, etc.

'
  desc 'check', "At the command prompt, run the following command:

# find /var/log/vmware/vpostgres/* -xdev -type f -a '(' -not -perm 600 -o -not -user vpostgres -o -not -group vpgmongrp ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', %q(At the command prompt, run the following commands:

# chmod 600 <file>
# chown vpostgres:vpgmongrp <file>

Note: Replace <file> with the file that has incorrect permissions.

At the command prompt, run the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_file_mode TO '0600';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  tag check_id: 'C-60270r887569_chk'
  tag severity: 'medium'
  tag gid: 'V-256595'
  tag rid: 'SV-256595r887571_rule'
  tag stig_id: 'VCPG-70-000005'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-60213r887570_fix'
  tag satisfies: ['SRG-APP-000118-DB-000059', 'SRG-APP-000119-DB-000060', 'SRG-APP-000120-DB-000061']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_file_mode;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_log_file_mode')}" }
  end

  command("find '#{input('pg_log_dir')}'/* -xdev -type f").stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp 'vpostgres' }
      its('group') { should cmp 'vpgmongrp' }
    end
  end
end
