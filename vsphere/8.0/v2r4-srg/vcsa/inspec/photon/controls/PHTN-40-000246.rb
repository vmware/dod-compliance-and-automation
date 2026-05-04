control 'PHTN-40-000246' do
  title 'The Photon operating system must restrict core dumps.'
  desc 'By enabling the fs.suid_dumpable kernel parameter, core dumps are not generated for setuid or otherwise protected/tainted binaries. This prevents users from potentially accessing core dumps with privileged information they would otherwise not have access to read.'
  desc 'check', 'At the command line, run the following command to verify core dumps are restricted:

# /sbin/sysctl fs.suid_dumpable

Example result:

fs.suid_dumpable = 0

If the "fs.suid_dumpable" kernel parameter is not set to "0", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/sysctl.d/zz-stig-hardening.conf

Add or update the following line:

fs.suid_dumpable = 0

At the command line, run the following command to load the new configuration:

# /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

Note: If the file zz-stig-hardening.conf does not exist, it must be created.'
  impact 0.5
  tag check_id: 'C-62644r933771_chk'
  tag severity: 'medium'
  tag gid: 'V-258904'
  tag rid: 'SV-258904r991589_rule'
  tag stig_id: 'PHTN-40-000246'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62553r933772_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('fs.suid_dumpable') do
    its('value') { should cmp 0 }
  end
end
