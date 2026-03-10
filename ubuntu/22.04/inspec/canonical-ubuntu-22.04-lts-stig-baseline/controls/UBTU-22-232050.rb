control 'UBTU-22-232050' do
  title 'Ubuntu 22.04 LTS must have system commands owned by "root" or a system account.'
  desc 'If Ubuntu 22.04 LTS were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to Ubuntu 22.04 LTS with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system commands contained in the following directories are owned by "root", or a required system account, by using the following command:

     $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \;

If any system commands are returned and are not owned by a required system account, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS commands and their respective parent directories to be protected from unauthorized access. Run the following command, replacing "<command_name>" with any system command not owned by "root" or a required system account:

     $ sudo chown root <command_name>'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64224r953296_chk'
  tag severity: 'medium'
  tag gid: 'V-260495'
  tag rid: 'SV-260495r991560_rule'
  tag stig_id: 'UBTU-22-232050'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-64132r953297_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  system_commands = command('find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f').stdout.strip.split("\n").entries
  valid_system_commands = Set[]

  if system_commands.count > 0
    system_commands.each do |sys_cmd|
      if file(sys_cmd).exist?
        valid_system_commands <<= sys_cmd
      end
    end
  end

  if valid_system_commands.count > 0
    valid_system_commands.each do |val_sys_cmd|
      describe file(val_sys_cmd) do
        its('owner') { should cmp 'root' }
      end
    end
  else
    describe 'Number of system commands found in /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin or /usr/local/sbin, that are NOT owned by root' do
      subject { valid_system_commands }
      its('count') { should eq 0 }
    end
  end
end
