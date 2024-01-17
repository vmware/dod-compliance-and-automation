control 'WOAD-3X-000007' do
  title 'The Workspace ONE Access vPostgres configuration files must not be accessible by unauthorized users.'
  desc  'VMware Postgres has a handful of configuration files that directly control the security posture of the DBMS. Protecting these files from unauthorized access and modification is fundamental to ensuring the security of VMware Postgres itself.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, enter the following command:

    # find /db/data/*conf* -xdev -type f -a '(' -not -perm 600 -o -not -user postgres -o -not -group users ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, enter the following command:

    # chmod 600 <file>
    # chown postgres:users <file>

    Note: Replace <file> with the file with incorrect permissions.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag satisfies: ['SRG-APP-000121-DB-000202', 'SRG-APP-000122-DB-000203', 'SRG-APP-000123-DB-000204', 'SRG-APP-000380-DB-000360']
  tag gid: 'V-WOAD-3X-000007'
  tag rid: 'SV-WOAD-3X-000007'
  tag stig_id: 'WOAD-3X-000007'
  tag cci: ['CCI-000171', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001813']
  tag nist: ['AU-12 b', 'AU-9', 'CM-5 (1)']

  conffiles = command('find /db/data/ -name *.conf -xdev -type f').stdout
  if !conffiles.empty?
    conffiles.split.each do |fname|
      describe file(fname) do
        it { should_not be_more_permissive_than('0600') }
        its('owner') { should eq 'postgres' }
        its('group') { should eq 'users' }
      end
    end
  else
    describe 'No configuration files found...skipping.' do
      skip 'No configuration files found...skipping.'
    end
  end
end
