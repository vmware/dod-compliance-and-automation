control 'UBTU-22-213010' do
  title 'Ubuntu 22.04 LTS must restrict access to the kernel message buffer.'
  desc 'Restricting access to the kernel message buffer limits access only to root. This prevents attackers from gaining additional system information as a nonprivileged user.'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to restrict access to the kernel message buffer by using the following command:

     $ sysctl kernel.dmesg_restrict
     kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.

Verify that there are no configurations that enable the kernel dmesg function:

     $ sudo grep -ir kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
     /etc/sysctl.d/10-kernel-hardening.conf:kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1", is commented out, is missing, or conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to restrict access to the kernel message buffer.

Add or modify the following line in the "/etc/sysctl.conf" file:

kernel.dmesg_restrict = 1

Remove any configurations that conflict with the above from the following locations:

/run/sysctl.d/
/etc/sysctl.d/
/usr/local/lib/sysctl.d/
/usr/lib/sysctl.d/
/lib/sysctl.d/
/etc/sysctl.conf

Reload settings from all system configuration files by using the following command:

     $ sudo sysctl --system'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64201r953227_chk'
  tag severity: 'low'
  tag gid: 'V-260472'
  tag rid: 'SV-260472r958524_rule'
  tag stig_id: 'UBTU-22-213010'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-64109r953228_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  describe kernel_parameter('kernel.dmesg_restrict') do
    its('value') { should eq 1 }
  end
end
