control 'UBTU-22-431015' do
  title 'Ubuntu 22.04 LTS must be configured to use AppArmor.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).

'
  desc 'check', 'Verify Ubuntu 22.04 LTS AppArmor is active by using the following commands:

     $ systemctl is-enabled apparmor.service
     enabled

     $ systemctl is-active apparmor.service
     active

If "apparmor.service" is not enabled and active, this is a finding.

Check if AppArmor profiles are loaded and enforced by using the following command:

     $ sudo apparmor_status | grep -i profile
     32 profiles are loaded.
     32 profiles are in enforce mode.
     0 profiles are in complain mode.
     0 profiles are in kill mode.
     0 profiles are in unconfined mode.
     2 processes have profiles defined.
     0 processes are unconfined but have a profile defined.

If no profiles are loaded and enforced, this is a finding.'
  desc 'fix', 'Enable and start "apparmor.service" by using the following command:

     $ sudo systemctl enable apparmor.service --now

Note: AppArmor must have properly configured profiles for applications and home directories. All configurations will be based on the actual system setup and organization and normally are on a per role basis. See the AppArmor documentation for more information on configuring profiles.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64286r953482_chk'
  tag severity: 'medium'
  tag gid: 'V-260557'
  tag rid: 'SV-260557r958804_rule'
  tag stig_id: 'UBTU-22-431015'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-64194r953483_fix'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag cci: ['CCI-001764', 'CCI-001774', 'CCI-002235']
  tag nist: ['CM-7 (2)', 'CM-7 (5) (b)', 'AC-6 (10)']

  describe systemd_service('apparmor') do
    it { should be_enabled }
  end
  describe systemd_service('apparmor').params['ActiveState'] do
    it { should cmp 'active' }
  end

  describe command("sudo apparmor_status | grep -i profile |grep -i loaded |awk '{print $1}'") do
    its('stdout.strip') { should >= '1' }
  end

  describe command("sudo apparmor_status | grep -i profile |grep -i enforce |awk '{print $1}'") do
    its('stdout.strip') { should >= '1' }
  end
end
