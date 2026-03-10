control 'UBTU-22-213020' do
  title 'Ubuntu 22.04 LTS must implement address space layout randomization to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in prohibited memory locations. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify Ubuntu 22.04 LTS implements address space layout randomization (ASLR) by using the following command:

     $ sysctl kernel.randomize_va_space
     kernel.randomize_va_space = 2

If no output is returned, verify the kernel parameter "randomize_va_space" is set to "2" by using the following command:

     $ cat /proc/sys/kernel/randomize_va_space
     2

If "kernel.randomize_va_space" is not set to "2", this is a finding.

Verify that a saved value of the "kernel.randomize_va_space" variable is not defined.

     $ sudo grep -ER "^kernel.randomize_va_space=[^2]" /etc/sysctl.conf /etc/sysctl.d

If this returns a result, this is a finding.'
  desc 'fix', 'Remove the "kernel.randomize_va_space" entry found in the "/etc/sysctl.conf" file or any file located in the "/etc/sysctl.d/" directory.

Reload the system configuration files for the changes to take effect by using the following command:

     $ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64203r953233_chk'
  tag severity: 'medium'
  tag gid: 'V-260474'
  tag rid: 'SV-260474r958928_rule'
  tag stig_id: 'UBTU-22-213020'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-64111r953234_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']

  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should cmp 2 }
  end
end
