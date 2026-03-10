control 'VCPG-80-000020' do
  title 'The vCenter PostgreSQL service must be configured to protect log files from unauthorized access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.'
  desc 'check', %q(Verify the default log file permissions and permissions on existing log files.

At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_file_mode;"

Expected result:

0600

If "log_file_mode" is not set to "0600", this is a finding.

At the command prompt, run the following command:

# find /var/log/vmware/vpostgres/* -xdev -type f -a '(' -not -perm 600 -o -not -user vpostgres -o -not -group vpgmongrp ')' -exec ls -ld {} \;

If any files are returned, this is a finding.)
  desc 'fix', 'A script is included with vCenter to generate a PostgreSQL STIG configuration.

At the command prompt, run the following commands:

# chmod +x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py
# /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py --action stig_enable --pg-data-dir /storage/db/vpostgres
# chmod -x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py

Restart the PostgreSQL service by running the following command:

# vmon-cli --restart vmware-vpostgres

At the command prompt, run the following commands:

# chmod 600 <file>
# chown vpostgres:vpgmongrp <file>

Note: Replace <file> with the file that has incorrect permissions.'
  impact 0.5
  tag check_id: 'C-62912r935418_chk'
  tag severity: 'medium'
  tag gid: 'V-259172'
  tag rid: 'SV-259172r960930_rule'
  tag stig_id: 'VCPG-80-000020'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-62821r935419_fix'
  tag satisfies: ['SRG-APP-000118-DB-000059', 'SRG-APP-000119-DB-000060', 'SRG-APP-000120-DB-000061']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']

  pg_log_dir = input('pg_log_dir')
  pg_owner = input('pg_owner')
  pg_group = input('pg_group')

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW log_file_mode;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp '0600' }
  end

  describe sql.query('SHOW log_directory;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp pg_log_dir }
  end

  logfiles = command("find #{pg_log_dir}/* -xdev -type f -a '(' -not -perm 600 -o -not -user #{pg_owner} -o -not -group #{pg_group} ')'")
  logfiles.stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp pg_owner }
      its('group') { should cmp pg_group }
    end
  end
end
