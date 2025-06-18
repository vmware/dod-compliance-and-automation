control 'VCFA-9X-000333' do
  title 'The VMware Cloud Foundation vCenter Server must limit membership to the "SystemConfiguration.BashShellAdministrators" Single Sign-On (SSO) group.'
  desc  "
    vCenter SSO integrates with PAM in the underlying Photon operating system so members of the \"SystemConfiguration.BashShellAdministrators\" SSO group can log on to the operating system without needing a separate account. However, even though unique SSO users log on, they are transparently using a group account named \"sso-user\" as far as Photon auditing is concerned. While the audit trail can still be traced back to the individual SSO user, it is a more involved process.

    To force accountability and nonrepudiation, the SSO group \"SystemConfiguration.BashShellAdministrators\" must be severely restricted.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Groups.

    Click the next page arrow until the \"SystemConfiguration.BashShellAdministrators\" group appears.

    Click \"SystemConfiguration.BashShellAdministrators\".

    Review the members of the group and ensure that only authorized accounts are present.

    Note: By default the Administrator and two unique service accounts similar to \"vmware-applmgmtservice-714684a4-342f-4eff-a232-cdc21def00c2\" and \"svc-sddc-manager-vcenter-1-2493\" will be in the group and should not be removed.

    If there are any accounts present as members of SystemConfiguration.BashShellAdministrators that are not authorized, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Groups.

    Click the next page arrow until the \"SystemConfiguration.BashShellAdministrators\" group appears.

    Click \"SystemConfiguration.BashShellAdministrators\".

    Click the three vertical dots next to the name of each unauthorized account.

    Select \"Remove Member\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000333'
  tag rid: 'SV-VCFA-9X-000333'
  tag stig_id: 'VCFA-9X-000333'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vcenter_bashShellAdminUsers = input('vcenter_bashShellAdminUsers')
  vcenter_bashShellAdminGroups = input('vcenter_bashShellAdminGroups')

  currentUsersCommand = 'Get-SsoGroup -Domain vsphere.local -Name SystemConfiguration.BashShellAdministrators | Get-SsoPersonUser | Select-Object -ExpandProperty Name'
  currentUsers = powercli_command(currentUsersCommand).stdout.strip
  if currentUsers.blank?
    describe 'No users found in SystemConfiguration.BashShellAdministrators group.' do
      subject { currentUsers }
      it { should be_blank }
    end
  else
    # Convert currentUsers to array
    currentUsers = currentUsers.gsub("\r\n", "\n").split("\n")
    # Find vmware-applmgmtservice user and add to approved user array
    applmgmtuser = currentUsers.grep(/vmware-applmgmtservice-*/)
    unless applmgmtuser.blank?
      vcenter_bashShellAdminUsers.push(applmgmtuser[0])
    end
    # Find svc-sddc-manager-vcenter- user and add to approved user array
    svcsddcuser = currentUsers.grep(/svc-sddc-manager-*/)
    unless svcsddcuser.blank?
      vcenter_bashShellAdminUsers.push(svcsddcuser[0])
    end

    currentUsers.each do |user|
      describe "The user: #{user}" do
        subject { user }
        it { should be_in vcenter_bashShellAdminUsers }
      end
    end
  end

  currentGroupsCommand = 'Get-SsoGroup -Domain vsphere.local -Name SystemConfiguration.BashShellAdministrators | Get-SsoGroup | Select-Object -ExpandProperty Name'
  currentGroups = powercli_command(currentGroupsCommand).stdout.strip
  if currentGroups.blank?
    describe 'No groups found in SystemConfiguration.BashShellAdministrators group. SystemConfiguration.BashShellAdministrators' do
      subject { currentGroups }
      it { should be_blank }
    end
  else
    currentGroups.gsub("\r\n", "\n").split("\n").each do |group|
      describe "The group: #{group}" do
        subject { group }
        it { should be_in vcenter_bashShellAdminGroups }
      end
    end
  end
end
