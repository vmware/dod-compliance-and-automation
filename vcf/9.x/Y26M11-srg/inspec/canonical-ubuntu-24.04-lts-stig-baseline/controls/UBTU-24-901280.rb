control 'UBTU-24-901280' do
  title 'Ubuntu 24.04 LTS must have directories that contain system commands group-owned by root.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has to make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', %q(Verify the system commands directories are group-owned by root with the following command:

$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \;

If any system commands directories are returned that are not Set Group ID up on execution (SGID) files and owned by a privileged account, this is a finding.)
  desc 'fix', "Configure the system commands directories to be protected from unauthorized access. Run the following command:

$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec chgrp root '{}' \\;"
  impact 0.5
  tag check_id: 'C-74859r1066965_chk'
  tag severity: 'medium'
  tag gid: 'V-270826'
  tag rid: 'SV-270826r1066967_rule'
  tag stig_id: 'UBTU-24-901280'
  tag gtitle: 'SRG-OS-000258-GPOS-00099'
  tag fix_id: 'F-74760r1066966_fix'
  tag 'documentable'
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']

  system_command_directories = command('find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type d').stdout.strip.split("\n").entries

  if system_command_directories
    system_command_directories.each do |sysdir|
      describe file(sysdir) do
        its('group') { should cmp 'root' }
      end
    end
  else
    describe 'No system command directories found...troubleshoot test and rerun...' do
      skip 'No system command directories found...troubleshoot test and rerun...'
    end
  end
end
