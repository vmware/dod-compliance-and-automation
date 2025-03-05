control 'PSQL-00-000006' do
  title 'The SDDC Manager PostgreSQL service configuration files must not be accessible by unauthorized users.'
  desc  "
    Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

    Suppression of auditing could permit an adversary to evade detection.

    Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, perform the following command:

    # find /data/pgdata/*conf* -xdev -type f -a '(' -not -perm 600 -o -not -user postgres -o -not -group users ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, enter the following commands:

    # chmod 600 <file>
    # chown postgres:users <file>

    Note: Replace <file> with the file with incorrect permissions.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag satisfies: ['SRG-APP-000121-DB-000202', 'SRG-APP-000122-DB-000203', 'SRG-APP-000123-DB-000204', 'SRG-APP-000380-DB-000360']
  tag gid: 'V-PSQL-00-000006'
  tag rid: 'SV-PSQL-00-000006'
  tag stig_id: 'PSQL-00-000006'
  tag cci: ['CCI-000171', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001813']
  tag nist: ['AU-12 b', 'AU-9', 'AU-9 a', 'CM-5 (1) (a)']

  pg_owner = input('pg_owner')
  pg_group = input('pg_group')

  conffiles = command("find #{input('pg_data_dir')} -type f -maxdepth 1 -name '*conf*'").stdout
  if !conffiles.empty?
    conffiles.split.each do |fname|
      describe file(fname) do
        its('mode') { should cmp '0600' }
        its('owner') { should cmp pg_owner }
        its('group') { should cmp pg_group }
      end
    end
  else
    describe 'No conf files found...skipping.' do
      skip 'No conf files found...skipping.'
    end
  end
end
