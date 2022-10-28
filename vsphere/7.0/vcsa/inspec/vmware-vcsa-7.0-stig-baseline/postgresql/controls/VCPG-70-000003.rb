control 'VCPG-70-000003' do
  title 'VMware Postgres configuration files must not be accessible by unauthorized users.'
  desc  'VMware Postgres has a handful of configuration files that directly control the security posture of the DBMS. Protecting these files from unauthorized access and modification is fundamental to ensuring the security of VMware Postgres itself.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, enter the following command:

    # find /storage/db/vpostgres/*conf* -xdev -type f -a '(' -not -perm 600 -o -not -user vpostgres -o -not -group vpgmongrp ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, enter the following command:

    # chmod 600 <file>
    # chown vpostgres:vpgmongrp <file>

    Note: Replace <file> with the file with incorrect permissions.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag satisfies: ['SRG-APP-000121-DB-000202', 'SRG-APP-000122-DB-000203', 'SRG-APP-000123-DB-000204', 'SRG-APP-000380-DB-000360']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000003'
  tag cci: ['CCI-000171', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001813']
  tag nist: ['AU-12 b', 'AU-9', 'CM-5 (1)']

  command("find #{input('pg_install_dir')} -type f -maxdepth 1 -name '*conf*'").stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp 'vpostgres' }
      its('group') { should cmp 'vpgmongrp' }
    end
  end
end
