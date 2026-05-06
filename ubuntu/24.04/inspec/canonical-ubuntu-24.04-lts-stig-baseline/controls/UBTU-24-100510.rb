control 'UBTU-24-100510' do
  title 'Ubuntu 24.04 LTS must be configured to use AppArmor.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at Ubuntu 24.04 LTS-level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).

'
  desc 'check', 'Verify Ubuntu 24.04 LTS AppArmor active with the following commands:

$ systemctl is-active apparmor.service
active

If "active" is not returned, this is a finding.

$ systemctl is-enabled apparmor.service
enabled

If "enabled" is not returned, this is a finding.'
  desc 'fix', 'Enable "apparmor" with the following command:

$ sudo systemctl enable apparmor.service

Start "apparmor" with the following command:

$ sudo systemctl start apparmor.service

Note: AppArmor must have properly configured profiles for applications and home directories. All configurations will be based on the actual system setup and organization and normally are on a per role basis. Refer to the AppArmor documentation for more information on configuring profiles.'
  impact 0.5
  tag check_id: 'C-74693r1066467_chk'
  tag severity: 'medium'
  tag gid: 'V-270660'
  tag rid: 'SV-270660r1066469_rule'
  tag stig_id: 'UBTU-24-100510'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-74594r1066468_fix'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000324-GPOS-00125', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag cci: ['CCI-001764', 'CCI-002235', 'CCI-001774']
  tag nist: ['CM-7 (2)', 'AC-6 (10)', 'CM-7 (5) (b)']

  describe systemd_service('apparmor') do
    it { should be_enabled }
    it { should be_running }
  end
end
