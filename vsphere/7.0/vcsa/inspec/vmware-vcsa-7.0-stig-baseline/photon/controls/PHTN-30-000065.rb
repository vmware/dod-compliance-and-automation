control 'PHTN-30-000065' do
  title 'The Photon operating system must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.'
  desc "ASLR makes it more difficult for an attacker to predict the location of attack code they have introduced into a process's address space during an attempt at exploitation.

ASLR also makes it more difficult for an attacker to know the location of existing code to repurpose it using return-oriented programming (ROP) techniques."
  desc 'check', 'At the command line, run the following command:

# cat /proc/sys/kernel/randomize_va_space

If the value of "randomize_va_space" is not "2", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/sysctl.d/50-security-hardening.conf

Ensure the "randomize_va_space" is uncommented and set to the following:

kernel.randomize_va_space=2

At the command line, run the following command:

# sysctl --system'
  impact 0.5
  tag check_id: 'C-60210r887277_chk'
  tag severity: 'medium'
  tag gid: 'V-256535'
  tag rid: 'SV-256535r887279_rule'
  tag stig_id: 'PHTN-30-000065'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-60153r887278_fix'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']

  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
end
