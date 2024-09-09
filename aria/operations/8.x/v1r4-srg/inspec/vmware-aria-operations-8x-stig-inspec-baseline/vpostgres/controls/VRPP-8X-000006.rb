control 'VRPP-8X-000006' do
  title 'VMware Aria Operations vPostgres configuration files must not be accessible by unauthorized users.'
  desc  "
    Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

    Suppression of auditing could permit an adversary to evade detection.

    Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # find /storage/db/vcops/vpostgres/data/*conf* -xdev -type f -a '(' -not -perm 600 -o -not -user postgres -o -not -group users ')' -exec ls -ld {} \\;

    # find /storage/db/vcops/vpostgres/repl/*conf* -xdev -type f -a '(' -not -perm 600 -o -not -user postgres -o -not -group users ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s) for each file returned by the query above:

    # chmod 600 <file>
    # chown postgres:users <file>

    Note: Replace <file> with the file path of the file with incorrect permissions.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag satisfies: ['SRG-APP-000121-DB-000202', 'SRG-APP-000122-DB-000203', 'SRG-APP-000123-DB-000204', 'SRG-APP-000380-DB-000360']
  tag gid: 'V-VRPP-8X-000006'
  tag rid: 'SV-VRPP-8X-000006'
  tag stig_id: 'VRPP-8X-000006'
  tag cci: ['CCI-000171', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001813']
  tag nist: ['AU-12 b', 'AU-9', 'AU-9 a', 'CM-5 (1) (a)']

  pg_owner = input('pg_owner')
  pg_group = input('pg_group')

  command("find #{input('pg_data_dir')} -type f -maxdepth 1 -name '*conf*'").stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp pg_owner }
      its('group') { should cmp pg_group }
    end
  end

  command("find #{input('pg_repl_dir')} -type f -maxdepth 1 -name '*conf*'").stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp pg_owner }
      its('group') { should cmp pg_group }
    end
  end
end
