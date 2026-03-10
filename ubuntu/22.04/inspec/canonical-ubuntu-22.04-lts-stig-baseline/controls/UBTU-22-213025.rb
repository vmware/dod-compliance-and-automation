control 'UBTU-22-213025' do
  title 'Ubuntu 22.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the NX (no-execution) bit flag is set on the system by using the following command:

     $ sudo dmesg | grep -i "execute disable"
     [    0.000000] NX (Execute Disable) protection: active

If "dmesg" does not show "NX (Execute Disable) protection: active", check the hardware capabilities of the installed CPU by using the following command:

     $ grep flags /proc/cpuinfo | grep -o nx | sort -u
     nx

If no output is returned, this is a finding.'
  desc 'fix', %q(Configure Ubuntu 22.04 LTS to enable NX.

If the installed CPU is hardware capable of NX protection, check if the system's BIOS/UEFI setup configuration permits toggling the "NX bit" or "no execution bit", and set it to "enabled".)
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64204r953236_chk'
  tag severity: 'medium'
  tag gid: 'V-260475'
  tag rid: 'SV-260475r958928_rule'
  tag stig_id: 'UBTU-22-213025'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-64112r953237_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']

  describe.one do
    describe command('dmesg | grep -i "execute disable"').stdout.strip do
      it { should match /.+(NX \(Execute Disable\) protection: active)/ }
    end
    describe command('grep flags /proc/cpuinfo | grep -o nx | sort -u') do
      its('stdout') { should match 'nx' }
    end
  end
end
