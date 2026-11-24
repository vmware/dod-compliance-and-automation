control 'UBTU-24-100500' do
  title 'Ubuntu 24.04 LTS must have AppArmor installed.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at Ubuntu 24.04 LTS-level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).

'
  desc 'check', 'Verify Ubuntu 24.04 LTS has AppArmor installed with the following command:

$ dpkg -l | grep apparmor
ii  apparmor                                4.0.1really4.0.1-0ubuntu0.24.04.3        amd64        user-space parser utility for AppArmor
ii  libapparmor1:amd64                      4.0.1really4.0.1-0ubuntu0.24.04.3        amd64        changehat AppArmor library

If the AppArmor package is not installed, this is a finding.'
  desc 'fix', 'Install "AppArmor" with the following command:

$ sudo apt install apparmor

Note: AppArmor must have properly configured profiles for applications and home directories. All configurations will be based on the actual system setup and organization and normally are on a per role basis. Refer to the AppArmor documentation for more information on configuring profiles.'
  impact 0.5
  tag check_id: 'C-74692r1066464_chk'
  tag severity: 'medium'
  tag gid: 'V-270659'
  tag rid: 'SV-270659r1066466_rule'
  tag stig_id: 'UBTU-24-100500'
  tag gtitle: 'SRG-OS-000312-GPOS-00124'
  tag fix_id: 'F-74593r1066465_fix'
  tag satisfies: ['SRG-OS-000312-GPOS-00124', 'SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag cci: ['CCI-002165', 'CCI-001764', 'CCI-001774']
  tag nist: ['AC-3 (4)', 'CM-7 (2)', 'CM-7 (5) (b)']

  describe package('apparmor') do
    it { should be_installed }
  end
end
