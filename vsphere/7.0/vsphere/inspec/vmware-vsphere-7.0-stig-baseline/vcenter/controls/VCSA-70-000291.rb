control 'VCSA-70-000291' do
  title 'The vCenter Server must limit membership to the TrustedAdmins SSO group.'
  desc  "
    The vSphere TrustedAdmins group grants additional rights to administer the vSphere Trust Authority feature.

    In order to force accountability and non-repudiation, the SSO group TrustedAdmins must be severely restricted.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Groups.

    Click the next page arrow until you see the \"TrustedAdmins\" group.

    Click \"TrustedAdmins\".

    Review the members of the group and ensure that only authorized accounts are present.

    Note: These accounts act as root on the Photon operating system and have the ability to severely damage vCenter, inadvertently or otherwise.

    If there are any accounts present as members of TrustedAdmins that are not authorized, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Groups.

    Click the next page arrow until you see the \"TrustedAdmins\" group.

    Click \"TrustedAdmins\".

    Click the three vertical dots next to the name of each unauthorized account.

    Select \"Remove Member\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000291'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
