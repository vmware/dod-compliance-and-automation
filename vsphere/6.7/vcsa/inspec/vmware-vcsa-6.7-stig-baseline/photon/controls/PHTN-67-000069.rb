control 'PHTN-67-000069' do
  title "The Photon operating system must implement address space layout
randomization (ASLR) to protect its memory from unauthorized code execution."
  desc  "ASLR makes it more difficult for an attacker to predict the location
of attack code he or she has introduced into a process's address space during
an attempt at exploitation. Additionally, ASLR also makes it more difficult for
an attacker to know the location of existing code to repurpose it using
return-oriented programming techniques."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # cat /proc/sys/kernel/randomize_va_space

    If the value of \"randomize_va_space\" is not \"2\", this is a finding.
  "
  desc 'fix', "
    Open /etc/sysctl.d/50-security-hardening.conf with a text editor.

    Ensure that the \"randomize_va_space\" is uncommented and set to the
following:

    kernel.randomize_va_space=2

    At the command line, execute the following command:

    # sysctl --system
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag gid: 'V-239140'
  tag rid: 'SV-239140r675228_rule'
  tag stig_id: 'PHTN-67-000069'
  tag fix_id: 'F-42310r675227_fix'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']

  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
end
