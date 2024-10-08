control 'PHTN-40-000067' do
  title 'The Photon operating system must restrict access to the kernel message buffer.'
  desc 'Restricting access to the kernel message buffer limits access only to root. This prevents attackers from gaining additional system information as a nonprivileged user.'
  desc 'check', 'At the command line, run the following command to verify kernel message buffer restrictions are enabled:

# /sbin/sysctl kernel.dmesg_restrict

Example result:

kernel.dmesg_restrict = 1

If the "kernel.dmesg_restrict" kernel parameter is not set to "1", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/sysctl.d/zz-stig-hardening.conf

Add or update the following line:

kernel.dmesg_restrict = 1

At the command line, run the following command to load the new configuration:

# /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

Note: If the file zz-stig-hardening.conf does not exist, it must be created.'
  impact 0.5
  tag check_id: 'C-62568r933543_chk'
  tag severity: 'medium'
  tag gid: 'V-258828'
  tag rid: 'SV-258828r958524_rule'
  tag stig_id: 'PHTN-40-000067'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-62477r933544_fix'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  describe kernel_parameter('kernel.dmesg_restrict') do
    its('value') { should cmp 1 }
  end
end
