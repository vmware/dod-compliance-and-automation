control 'PHTN-40-000105' do
  title 'The Photon operating system must enable symlink access control protection in the kernel.'
  desc "By enabling the fs.protected_symlinks kernel parameter, symbolic links are permitted to be followed only when outside a sticky world-writable directory, or when the UID of the link and follower match, or when the directory owner matches the symlink's owner. Disallowing such symlinks helps mitigate vulnerabilities based on insecure file system accessed by privileged programs, avoiding an exploitation vector exploiting unsafe use of open() or creat()."
  desc 'check', 'At the command line, run the following command to verify symlink protection is enabled:

# /sbin/sysctl fs.protected_symlinks

Example result:

fs.protected_symlinks = 1

If the "fs.protected_symlinks" kernel parameter is not set to "1", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/sysctl.d/zz-stig-hardening.conf

Add or update the following line:

fs.protected_symlinks = 1

At the command line, run the following command to load the new configuration:

# /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

Note: If the file zz-stig-hardening.conf does not exist, it must be created.'
  impact 0.7
  tag check_id: 'C-62581r933582_chk'
  tag severity: 'high'
  tag gid: 'V-258841'
  tag rid: 'SV-258841r958726_rule'
  tag stig_id: 'PHTN-40-000105'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-62490r933583_fix'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  describe kernel_parameter('fs.protected_symlinks') do
    its('value') { should cmp 1 }
  end
end
