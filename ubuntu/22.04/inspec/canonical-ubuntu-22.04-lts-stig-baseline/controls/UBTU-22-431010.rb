control 'UBTU-22-431010' do
  title 'Ubuntu 22.04 LTS must have the "apparmor" package installed.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).

'
  desc 'check', 'Verify Ubuntu 22.04 LTS has the "apparmor" package installed by using the following command:

     $ dpkg -l | grep apparmor
     ii     apparmor     3.0.4-2ubuntu2.3     amd64     user-space parser utility for AppArmor

If the "apparmor" package is not installed, this is a finding.'
  desc 'fix', 'Install the "appArmor" package by using the following command:

     $ sudo apt-get install apparmor'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64285r953479_chk'
  tag severity: 'medium'
  tag gid: 'V-260556'
  tag rid: 'SV-260556r958702_rule'
  tag stig_id: 'UBTU-22-431010'
  tag gtitle: 'SRG-OS-000312-GPOS-00124'
  tag fix_id: 'F-64193r953480_fix'
  tag satisfies: ['SRG-OS-000312-GPOS-00124', 'SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag cci: ['CCI-001764', 'CCI-001774', 'CCI-002165']
  tag nist: ['CM-7 (2)', 'CM-7 (5) (b)', 'AC-3 (4)']

  describe package('apparmor') do
    it { should be_installed }
  end
end
