control 'VCSA-70-000289' do
  title 'The vCenter Server must use a limited privilege account when adding an LDAP identity source.'
  desc  'When adding an LDAP identity source to vSphere SSO the account used to bind to AD must be minimally privileged. This account only requires read rights to the base DN specified. Any other permissions inside or outside of that OU are unnecessary and violate least privilege.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider.

    Click the \"Identity Sources\" tab.

    For each identity source with of type \"Active Directory over LDAP\", highlight the item and click \"Edit\".

    If the account that is configured to bind to the LDAPS server is not one with minimal privileges, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider.

    Click the \"Identity Sources\" tab.

    For each identity source that has been configured with a highly privileged AD account, highlight the item and click \"Edit\".

    Change the username and password to one with read only rights to the base DN and complete the dialog.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000289'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
