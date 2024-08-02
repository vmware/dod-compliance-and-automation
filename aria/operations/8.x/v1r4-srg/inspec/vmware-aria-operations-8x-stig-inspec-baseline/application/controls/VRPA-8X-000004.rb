control 'VRPA-8X-000004' do
  title 'VMware Aria Operations must use multifactor authentication for network access to privileged accounts.'
  desc  "
    Multifactor authentication creates a layered defense and makes it more difficult for an unauthorized person to access the application server.  If one factor is compromised or broken, the attacker still has at least one more barrier to breach before successfully breaking into the target.  Unlike a simple username/password scenario where the attacker could gain access by knowing both the username and password without the user knowing his account was compromised, multifactor authentication adds the requirement that the attacker must have something from the user, such as a token, or to biometrically be the user.

    Multifactor authentication is defined as: using two or more factors to achieve authentication.

    Factors include:
    (i) something a user knows (e.g., password/PIN);
    (ii) something a user has (e.g., cryptographic identification device, token); or
    (iii) something a user is (e.g., biometric). A CAC or PKI Hardware Token meets this definition.

    A privileged account is defined as an information system account with authorizations of a privileged user.  These accounts would be capable of accessing the web management interface.

    When accessing the application server via a network connection, administrative access to the application server must be PKI Hardware Token enabled.
  "
  desc  'rationale', ''
  desc  'check', "
    Navigate to the vRealize Operations Manager login page in a new browser session.

    If your CAC is inserted but you are not prompted to select a certificate or enter your PIN, this is a finding.
  "
  desc 'fix', "
    Multifactor authentication can be enabled in two ways for vRealize Operations Manager by using either vSphere SSO or VMware Identity Manager as an authentication source and then configuring those sources appropriately.

    To configure authentication sources in vRealize Operations Manager perform the following:

    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Authentication Sources.

    Click Add and choose either SSO SAML or VMware Identity Manager as the source type.

    Fill in the environment specific details and complete the configuration.

    The authentication source must then be appropriately configured to support multifactor authentication.

    For vCenter refer to the vCenter STIG and for vIDM refer to the accompanying white paper.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000149-AS-000102'
  tag gid: 'V-VRPA-8X-000004'
  tag rid: 'SV-VRPA-8X-000004'
  tag stig_id: 'VRPA-8X-000004'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
