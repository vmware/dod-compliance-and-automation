control 'UBTU-22-232145' do
  title 'Ubuntu 22.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DOD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.'
  desc 'check', 'Verify that all public directories have the public sticky bit set by using the following command:

     $ sudo find / -type d -perm -002 ! -perm -1000

If any public directories are found missing the sticky bit, this is a finding.'
  desc 'fix', 'Configure all public directories to have the sticky bit set to prevent unauthorized and unintended information transferred via shared system resources.

Set the sticky bit on all public directories using the following command, replacing "<public_directory_name>" with any directory path missing the sticky bit:

     $ sudo chmod +t  <public_directory_name>'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64242r953350_chk'
  tag severity: 'medium'
  tag gid: 'V-260513'
  tag rid: 'SV-260513r958524_rule'
  tag stig_id: 'UBTU-22-232145'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-64150r953351_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  lines = command('find / -xdev -type d  \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null').stdout.strip.split("\n").entries
  if lines.count > 0
    lines.each do |line|
      dir = line.strip
      describe directory(dir) do
        it { should be_sticky }
      end
    end
  else
    describe 'Sticky bit has been set on all world writable directories' do
      subject { lines }
      its('count') { should eq 0 }
    end
  end
end
