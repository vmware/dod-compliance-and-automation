control 'VCSA-70-000289' do
  title 'The vCenter Server must use a limited privilege account when adding a Lightweight Directory Access Protocol (LDAP) identity source.'
  desc 'When adding an LDAP identity source to vSphere Single Sign-On (SSO), the account used to bind to Active Directory must be minimally privileged. This account only requires read rights to the base domain name specified. Any other permissions inside or outside of that organizational unit are unnecessary and violate least privilege.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider.

Click the "Identity Sources" tab.

For each identity source with a type of "Active Directory over LDAP", highlight the item and click "Edit".

If the account that is configured to bind to the LDAP server is not one with minimal privileges, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider.

Click the "Identity Sources" tab.

For each identity source that has been configured with a highly privileged Active Directory account, highlight the item and click "Edit".

Change the username and password to one with read-only rights to the base DN and complete the dialog.'
  impact 0.5
  tag check_id: 'C-60044r885716_chk'
  tag severity: 'medium'
  tag gid: 'V-256369'
  tag rid: 'SV-256369r885718_rule'
  tag stig_id: 'VCSA-70-000289'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-59987r885717_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
