# encoding: UTF-8

control 'V-219341' do
  title "The Ubuntu operating system must implement non-executable data to
protect its memory from unauthorized code execution."
  desc  "Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can either be hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Examples of attacks are buffer overflow attacks.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the NX (no-execution) bit flag is set on the system.

    Check that the no-execution bit flag is set with the following commands:

    # dmesg | grep -i \"execute disable\"
    [ 0.000000] NX (Execute Disable) protection: active

    If \"dmesg\" does not show \"NX (Execute Disable) protection: active\",
check the cpuinfo settings with the following command:

    # grep flags /proc/cpuinfo | grep -w nx | sort -u
    flags : fpu vme de pse tsc ms nx rdtscp lm constant_tsc

    If \"flags\" does not contain the \"nx\" flag, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to enable NX.

    If \"nx\" is not showing up in /proc/cpuinfo and the system's BIOS setup
configuration permits toggling the No Execution bit, then set it to \"enable\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag gid: 'V-219341'
  tag rid: 'SV-219341r508662_rule'
  tag stig_id: 'UBTU-18-010513'
  tag fix_id: 'F-21065r305352_fix'
  tag cci: ['SV-110007', 'V-100903', 'CCI-002824']
  tag nist: ['SI-16']

  desc 'fix', 'The NX bit execute protection must be enabled in the system BIOS.'

  options = {
    assignment_regex: /^\s*([^:]*?)\s*:\s*(.*?)\s*$/
  }
  describe.one do
    describe command('dmesg | grep NX').stdout.strip do
      it { should match /.+(NX \(Execute Disable\) protection: active)/ }
    end
    describe parse_config_file('/proc/cpuinfo', options).flags.split(' ') do
      it { should include 'nx' }
    end
  end
end

