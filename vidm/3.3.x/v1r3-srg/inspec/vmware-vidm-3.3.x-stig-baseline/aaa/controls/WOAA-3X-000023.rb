control 'WOAA-3X-000023' do
  title 'Workspace ONE Access must be configured to use secure protocols when connecting to directory services.'
  desc  "
    Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

    Application communication sessions are protected utilizing transport encryption protocols, such as TLS. TLS provides a means to authenticate sessions and encrypt application traffic. Session authentication can be single (one-way) or mutual (two-way) in nature. Single authentication authenticates the server for the client, whereas mutual authentication provides a means for both the client and the server to authenticate each other.

    This requirement addresses communications protection at the application session, versus the network packet, and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    On the VMware Identity Manager console Identity & Access Management tab, select Manage.

    For each Directory that is of type \"Active Directory over LDAP/IWA\" verify the setting \"This Directory requires all connections to use STARTTLS\" is configured.

    For each Directory that is of type \"LDAP\" verify the setting \"This Directory requires all connections to use SSL\" is configured.

    If either directory type is not configured to use secure connection, this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    On the VMware Identity Manager console Identity & Access Management tab, select Manage.

    Click on the name of the directory that needs to be configured.

    If the directory is of type \"Active Directory over LDAP/IWA\" enable the \"This Directory requires all connections to use STARTTLS\" setting and supply the necessary certificate then click save.

    If the directory is of type \"LDAP\" enable the \"This Directory requires all connections to use SSL\" setting and supply the necessary certificate then click save.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000142-AAA-000010'
  tag gid: 'V-WOAA-3X-000023'
  tag rid: 'SV-WOAA-3X-000023'
  tag stig_id: 'WOAA-3X-000023'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
