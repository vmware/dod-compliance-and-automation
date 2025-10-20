control 'PHTN-50-000160' do
  title 'The Photon operating system must implement address space layout randomization to protect its memory from unauthorized code execution.'
  desc  "
    Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

    Examples of attacks are buffer overflow attacks.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify address space layout randomization is enabled:

    # cat /proc/sys/kernel/randomize_va_space

    If the value of \"randomize_va_space\" is not \"2\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/sysctl.d/zz-stig-hardening.conf

    Add or update the following line:

    kernel.randomize_va_space=2

    At the command line, run the following command to load the new configuration:

    # /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

    Note: If the file zz-stig-hardening.conf does not exist it must be created.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag gid: 'V-PHTN-50-000160'
  tag rid: 'SV-PHTN-50-000160'
  tag stig_id: 'PHTN-50-000160'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']

  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should cmp 2 }
  end
end
