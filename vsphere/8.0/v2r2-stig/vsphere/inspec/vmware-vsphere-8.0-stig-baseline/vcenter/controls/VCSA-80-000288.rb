control 'VCSA-80-000288' do
  title 'The vCenter Server must use secure Lightweight Directory Access Protocol (LDAPS) when adding an LDAP identity source.'
  desc 'LDAP is an industry standard protocol for querying directory services such as Active Directory. This protocol can operate in clear text or over a Secure Sockets Layer (SSL)/Transport Layer Security (TLS) encrypted tunnel. To protect confidentiality of LDAP communications, secure LDAP (LDAPS) must be explicitly configured when adding an LDAP identity source in vSphere Single Sign-On (SSO).

When configuring an identity source and supplying an SSL certificate, vCenter will enforce LDAPS. The server URLs do not need to be explicitly provided if an SSL certificate is uploaded.'
  desc 'check', 'If LDAP is not used as an identity provider, this is not applicable.

From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider.

Click the "Identity Sources" tab.

For each identity source of type "Active Directory over LDAP", if the "Server URL" does not indicate "ldaps://", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider.

Click the "Identity Sources" tab.

For each identity source of type "Active Directory over LDAP" where LDAPS is not configured, highlight the item and click "Edit".

Ensure the primary and secondary server URLs, if specified, are configured for "ldaps://".

At the bottom, click the "Browse" button, select the AD LDAP cert previously exported to your local computer, click "Open", and "Save" to complete modifications.

Note: With LDAPS, the server must be a specific domain controller and its specific certificate or the domain alias with a certificate that is valid for that URL.'
  impact 0.5
  tag check_id: 'C-62695r934521_chk'
  tag severity: 'medium'
  tag gid: 'V-258955'
  tag rid: 'SV-258955r961863_rule'
  tag stig_id: 'VCSA-80-000288'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62604r934522_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
