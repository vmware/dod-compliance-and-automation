control 'VCSA-70-000288' do
  title 'The vCenter Server must use secure Lightweight Directory Access Protocol (LDAPS) when adding an LDAP identity source.'
  desc  "
    LDAP is an industry standard protocol for querying directory services such as Active Directory. This protocol can operate in clear text or over a Secure Sockets Layer (SSL)/Transport Layer Security (TLS) encrypted tunnel. To protect confidentiality of LDAP communications, secure LDAP (LDAPS) must be explicitly configured when adding an LDAP identity source in vSphere Single Sign-On (SSO).

    When configuring an identity source and supplying an SSL certificate, vCenter will enforce LDAPS. The server URLs do not need to be explicitly provided if an SSL certificate is uploaded.
  "
  desc  'rationale', ''
  desc  'check', "
    If LDAP is not used as an identity provider, this is not applicable.

    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider.

    Click the \"Identity Sources\" tab.

    For each identity source of type \"Active Directory over LDAP\", if the \"Server URL\" does not indicate \"ldaps://\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider.

    Click the \"Identity Sources\" tab.

    For each identity source of type \"Active Directory over LDAP\" where LDAPS is not configured, highlight the item and click \"Edit\".

    Ensure the primary and secondary server URLs, if specified, are configured for \"ldaps://\".

    At the bottom, click the \"Browse\" button, select the AD LDAP cert previously exported to the local computer, click \"Open\", and \"Save\" to complete modifications.

    Note: With LDAPS, the server must be a specific domain controller and its specific certificate or the domain alias with a certificate that is valid for that URL.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-256368'
  tag rid: 'SV-256368r885715_rule'
  tag stig_id: 'VCSA-70-000288'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
