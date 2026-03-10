control 'UBTU-22-232010' do
  title 'Ubuntu 22.04 LTS must have directories that contain system commands set to a mode of "755" or less permissive.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', %q(Verify the system commands directories have mode "755" or less permissive by using the following command:

     $ find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;

If any directories are found to be group-writable or world-writable, this is a finding.)
  desc 'fix', "Configure Ubuntu 22.04 LTS commands directories to be protected from unauthorized access. Run the following command:

     $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec chmod -R 755 '{}' \\;"
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64214r953266_chk'
  tag severity: 'medium'
  tag gid: 'V-260485'
  tag rid: 'SV-260485r991559_rule'
  tag stig_id: 'UBTU-22-232010'
  tag gtitle: 'SRG-OS-000258-GPOS-00099'
  tag fix_id: 'F-64122r953267_fix'
  tag 'documentable'
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']

  system_directories = command('find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type d').stdout.strip.split("\n").entries

  if system_directories
    system_directories.each do |sysdir|
      describe file(sysdir) do
        it { should_not be_more_permissive_than('0755') }
      end
    end
  else
    describe 'No system directories found...troubleshoot test and rerun...' do
      skip 'No system directories found...troubleshoot test and rerun...'
    end
  end
end
