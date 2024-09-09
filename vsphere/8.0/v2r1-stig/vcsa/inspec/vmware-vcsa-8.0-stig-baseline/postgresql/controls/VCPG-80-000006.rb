control 'VCPG-80-000006' do
  title 'The vCenter PostgreSQL service configuration files must not be accessible by unauthorized users.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

"
  desc 'check', "At the command prompt, run the following command:

# find /storage/db/vpostgres/*conf* -xdev -type f -a '(' -not -perm 600 -o -not -user vpostgres -o -not -group vpgmongrp ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command prompt, run the following commands:

# chmod 600 <file>
# chown vpostgres:vpgmongrp <file>

Note: Replace <file> with the file that has incorrect permissions.'
  impact 0.5
  tag check_id: 'C-62908r935406_chk'
  tag severity: 'medium'
  tag gid: 'V-259168'
  tag rid: 'SV-259168r960882_rule'
  tag stig_id: 'VCPG-80-000006'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-62817r935407_fix'
  tag satisfies: ['SRG-APP-000090-DB-000065', 'SRG-APP-000121-DB-000202', 'SRG-APP-000122-DB-000203', 'SRG-APP-000123-DB-000204', 'SRG-APP-000380-DB-000360']
  tag cci: ['CCI-000171', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001813']
  tag nist: ['AU-12 b', 'AU-9 a', 'AU-9', 'AU-9', 'CM-5 (1) (a)']

  pg_owner = input('pg_owner')
  pg_group = input('pg_group')

  pgfiles = command("find #{input('pg_data_dir')} -type f -maxdepth 1 -name '*conf*'").stdout
  if !pgfiles.empty?
    pgfiles.split.each do |fname|
      describe file(fname) do
        its('mode') { should cmp '0600' }
        its('owner') { should cmp pg_owner }
        its('group') { should cmp pg_group }
      end
    end
  else
    describe 'No log files found...skipping.' do
      skip 'No log files found...skipping.'
    end
  end
end
