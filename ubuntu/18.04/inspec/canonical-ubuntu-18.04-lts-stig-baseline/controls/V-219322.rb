# encoding: UTF-8

control 'V-219322' do
  title "Pam_Apparmor must be configured to allow system administrators to pass
information to any other Ubuntu operating system administrator or user, change
security attributes, and to confine all non-privileged users from executing
functions to include disabling, circumventing, or altering implemented security
safeguards/countermeasures."
  desc  "When discretionary access control policies are implemented, subjects
are not constrained with regard to what actions they can take with information
for which they have already been granted access. Thus, subjects that have been
granted access to information are not prevented from passing (i.e., the
subjects have the discretion to pass) the information to other subjects or
objects. A subject that is constrained in its operation by Mandatory Access
Control policies is still able to operate under the less rigorous constraints
of this requirement. Thus, while Mandatory Access Control imposes constraints
preventing a subject from passing information to another subject operating at a
different sensitivity level, this requirement permits the subject to pass the
information to any subject at the same sensitivity level. The policy is bounded
by the information system boundary. Once the information is passed outside the
control of the information system, additional means may be required to ensure
the constraints remain in effect. While the older, more traditional definitions
of discretionary access control require identity-based access control, that
limitation is not required for this use of discretionary access control.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the Ubuntu operating system is configured to allow system
administrators to pass information to any other Ubuntu operating system
administrator or user.

    Check that \"Pam_Apparmor\" is installed on the system with the following
command:

    # dpkg -l | grep -i apparmor

    ii libpam-apparmor 2.10.95-0Ubuntu2.6

    If the \"Pam_Apparmor\" package is not installed, this is a finding.

    Check that the \"AppArmor\" daemon is running with the following command:

    # systemctl status apparmor.service | grep -i active

    If something other than \"Active: active\" is returned, this is a finding.

    Note: Pam_Apparmor must have properly configured profiles. All
configurations will be based on the actual system setup and organization. See
the \"Pam_Apparmor\" documentation for more information on configuring profiles.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to allow system administrators to
pass information to any other Ubuntu operating system administrator or user.

    Install \"Pam_Apparmor\" (if it is not installed) with the following
command:

    # sudo apt-get install libpam-apparmor

    Enable/Activate \"Apparmor\" (if it is not already active) with the
following command:

    # sudo systemctl enable apparmor.service

    Start \"Apparmor\" with the following command:

    # sudo systemctl start apparmor.service

    Note: Pam_Apparmor must have properly configured profiles. All
configurations will be based on the actual system setup and organization. See
the \"Pam_Apparmor\" documentation for more information on configuring profiles.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000312-GPOS-00122'
  tag satisfies: ['SRG-OS-000312-GPOS-00122', 'SRG-OS-000312-GPOS-00123',
'SRG-OS-000312-GPOS-00124', 'SRG-OS-000324-GPOS-0012']
  tag gid: 'V-219322'
  tag rid: 'SV-219322r508662_rule'
  tag stig_id: 'UBTU-18-010437'
  tag fix_id: 'F-21046r305295_fix'
  tag cci: ['V-100867', 'SV-109971', 'CCI-002235', 'CCI-002165']
  tag nist: ['AC-6 (10)', 'AC-3 (4)']

  describe package('libpam-apparmor') do
    it { should be_installed }
  end

  num_loaded_profiles = inspec.command('apparmor_status | grep "profiles are loaded." | cut -f 1 -d " "').stdout
  num_enforced_profiles = inspec.command('apparmor_status | grep "profiles are in enforce mode." | cut -f 1 -d " "').stdout

  describe 'AppArmor Profiles' do
    it 'loaded and enforced' do
      expect(num_loaded_profiles).to eq(num_enforced_profiles)
    end
  end
end

