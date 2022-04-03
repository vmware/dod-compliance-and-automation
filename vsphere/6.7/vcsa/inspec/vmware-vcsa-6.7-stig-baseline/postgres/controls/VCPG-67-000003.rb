control 'VCPG-67-000003' do
  title "VMware Postgres configuration files must not be accessible by
unauthorized users."
  desc  "VMware Postgres has several configuration files that directly control
the security posture of the DBMS. Protecting these files from unauthorized
access and modification is fundamental to ensuring the security of VMware
Postgres.

    Misconfigured audits can degrade the system's performance by overwhelming
the audit log. Misconfigured audits may also make it more difficult to
establish, correlate, and investigate the events relating to an incident or
identify those responsible for one.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, enter the following command:

    # find /storage/db/vpostgres/*conf* -xdev -type f -a '(' -not -perm 600 -o
-not -user vpostgres -o -not -group users ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, enter the following command:

    # chmod 600 <file>
    # chown vpostgres:users <file>

    Note: Replace <file> with the file with incorrect permissions.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag satisfies: ['SRG-APP-000090-DB-000065', 'SRG-APP-000121-DB-000202',
'SRG-APP-000122-DB-000203', 'SRG-APP-000123-DB-000204',
'SRG-APP-000380-DB-000360']
  tag gid: 'V-239198'
  tag rid: 'SV-239198r717049_rule'
  tag stig_id: 'VCPG-67-000003'
  tag fix_id: 'F-42390r678966_fix'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']

  command("find #{input('pg_install_dir')} -type f -maxdepth 1 -name '*conf*'").stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp 'vpostgres' }
      its('group') { should cmp 'users' }
    end
  end
end
