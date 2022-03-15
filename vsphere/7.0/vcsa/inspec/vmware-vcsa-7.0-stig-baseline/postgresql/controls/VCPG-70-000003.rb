control 'VCPG-70-000003' do
  title "VMware Postgres configuration files must not be accessible by
unauthorized users."
  desc  "VMware Postgres has a handful of configuration files that directly
control the security posture of the DBMS. Protecting these files from
unauthorized access and modification is fundamental to ensuring the security of
VMware Postgres itself."
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
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000003'
  tag fix_id: nil
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
