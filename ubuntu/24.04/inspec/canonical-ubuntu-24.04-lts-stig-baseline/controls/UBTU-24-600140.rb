control 'UBTU-24-600140' do
  title 'Ubuntu 24.04 LTS must restrict access to the kernel message buffer.'
  desc 'Restricting access to the kernel message buffer limits access only to root. This prevents attackers from gaining additional system information as a nonprivileged user.'
  desc 'check', 'Verify Ubuntu 24.04 LTS is configured to restrict access to the kernel message buffer with the following command:

$ sysctl kernel.dmesg_restrict
kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.

Verify there are no configurations that enable the kernel dmesg function:

$ sudo grep -r kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
/etc/sysctl.d/10-kernel-hardening.conf:kernel.dmesg_restrict = 1

If any instance of "kernel.dmesg_restrict" is uncommented and set to "0", or if conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to restrict access to the kernel message buffer.

Set the system to the required kernel parameter by adding or modifying the following line in /etc/sysctl.conf or a config file in the /etc/sysctl.d/ directory:

     kernel.dmesg_restrict = 1

Remove any configurations that conflict with the above from the following locations:
     /run/sysctl.d/
     /etc/sysctl.d/
     /usr/local/lib/sysctl.d/
     /usr/lib/sysctl.d/
     /lib/sysctl.d/
     /etc/sysctl.conf

Reload settings from all system configuration files with the following command:

     $ sudo sysctl --system'
  impact 0.3
  tag check_id: 'C-74782r1067179_chk'
  tag severity: 'low'
  tag gid: 'V-270749'
  tag rid: 'SV-270749r1137695_rule'
  tag stig_id: 'UBTU-24-600140'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-74683r1066735_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  describe kernel_parameter('kernel.dmesg_restrict') do
    its('value') { should eq 1 }
  end

  sysctl_files = command('find /etc/sysctl.conf /run/sysctl.d /etc/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d -type f 2>/dev/null').stdout.split("\n")

  sysctl_files.each do |file_path|
    describe file(file_path) do
      its('content') { should_not match(/^\s*kernel\.dmesg_restrict\s*=\s*0\b/) }
    end
  end
end
