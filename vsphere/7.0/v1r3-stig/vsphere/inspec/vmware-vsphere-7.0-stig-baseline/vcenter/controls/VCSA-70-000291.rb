control 'VCSA-70-000291' do
  title 'The vCenter Server must limit membership to the "TrustedAdmins" Single Sign-On (SSO) group.'
  desc 'The vSphere "TrustedAdmins" group grants additional rights to administer the vSphere Trust Authority feature.

To force accountability and nonrepudiation, the SSO group "TrustedAdmins" must be severely restricted.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Groups.

Click the next page arrow until the "TrustedAdmins" group appears.

Click "TrustedAdmins".

Review the members of the group and verify only authorized accounts are present.

Note: These accounts act as root on the Photon operating system and have the ability to severely damage vCenter, inadvertently or otherwise.

If any accounts are present as members of "TrustedAdmins" that are not authorized, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Groups.

Click the next page arrow until the "TrustedAdmins" group appears.

Click "TrustedAdmins".

Click the three vertical dots next to the name of each unauthorized account.

Select "Remove Member".'
  impact 0.5
  tag check_id: 'C-60046r885722_chk'
  tag severity: 'medium'
  tag gid: 'V-256371'
  tag rid: 'SV-256371r885724_rule'
  tag stig_id: 'VCSA-70-000291'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-59989r885723_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  trustedAdminUsers = input('trustedAdminUsers')
  users = powercli_command('Get-SsoGroup -Domain vsphere.local -Name TrustedAdmins | Get-SsoPersonUser | Select-Object -ExpandProperty Name')
  if users.stdout.empty?
    describe 'Stderr should be empty if no users found' do
      subject { users.stderr }
      it { should be_empty }
    end
    describe 'No users found in TrustedAdmins' do
      subject { users.stdout }
      it { should be_empty }
    end
  else
    users.stdout.gsub("\r\n", "\n").split("\n").each do |user|
      describe user do
        it { should be_in trustedAdminUsers }
      end
    end
  end
  trustedAdminGroups = input('trustedAdminGroups')
  groups = powercli_command('Get-SsoGroup -Domain vsphere.local -Name TrustedAdmins | Get-SsoGroup | Select-Object -ExpandProperty Name')
  if groups.stdout.empty?
    describe 'Stderr should be empty if no groups found' do
      subject { groups.stderr }
      it { should be_empty }
    end
    describe 'No groups found in TrustedAdmins' do
      subject { groups.stdout }
      it { should be_empty }
    end
  else
    groups.stdout.gsub("\r\n", "\n").split("\n").each do |group|
      describe group do
        it { should be_in trustedAdminGroups }
      end
    end
  end
end
