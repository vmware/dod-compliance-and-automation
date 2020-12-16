# encoding: UTF-8

control 'V-219323' do
  title 'The Ubuntu operating system must be configured to use AppArmor.'
  desc  "Control of program execution is a mechanism used to prevent execution
of unauthorized programs. Some operating systems may provide a capability that
runs counter to the mission or provides users with functionality that exceeds
mission requirements. This includes functions and services installed at the
operating system level.

    Some of the programs, installed by default, may be harmful or may not be
necessary to support essential organizational operations (e.g., key missions,
functions). Removal of executable programs is not always possible; therefore,
establishing a method of preventing program execution is critical to
maintaining a secure system baseline.

    Methods for complying with this requirement include restricting execution
of programs in certain environments, while preventing execution in other
environments; or limiting execution of certain program functionality based on
organization-defined criteria (e.g., privileges, subnets, sandboxed
environments, or roles).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system prevents program execution in accordance with
local policies.

    Check that apparmor is installed and active by running the following
command:

    # dpkg -l | grep apparmor

    If the \"apparmor\" package is not installed, this is a finding.

    #systemctl is-active apparmor.service

    active

    If \"active\" is not returned, this is a finding.

    #systemctl is-enabled apparmor.service

    enabled

    If \"enabled\" is not returned, then this is a finding.
  "
  desc  'fix', "
    Install \"Apparmor\" (if it is not installed) with the following command:

    # sudo apt-get install apparmor

    # sudo systemctl enable apparmor.service

    Start \"Apparmor\" with the following command:

    # sudo systemctl start apparmor.service

    Note: Apparmor must have properly configured profiles for applications and
home directories. All configurations will be based on the actual system setup
and organization and normally are on a per role basis. See the \"Apparmor\"
documentation for more information on configuring profiles.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-219323'
  tag rid: 'SV-219323r508662_rule'
  tag stig_id: 'UBTU-18-010441'
  tag fix_id: 'F-21047r305298_fix'
  tag cci: ['V-100869', 'SV-109973', 'CCI-001764']
  tag nist: ['CM-7 (2)']

  describe service('apparmor') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

