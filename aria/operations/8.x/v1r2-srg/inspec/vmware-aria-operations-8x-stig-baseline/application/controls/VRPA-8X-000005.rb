control 'VRPA-8X-000005' do
  title 'vRealize Operations Manager must utilize encryption when using LDAP for authentication.'
  desc  "
    Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

    Application servers have the capability to utilize LDAP directories for authentication. If LDAP connections are not protected during transmission, sensitive authentication credentials can be stolen. When the application server utilizes LDAP, the LDAP traffic must be encrypted.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Authentication Sources.

    If any \"Source Type\" of \"Active Directory\" or \"Open LDAP\" does not have the SSL/TLS box checked, this is a finding.
  "
  desc 'fix', "
    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Authentication Sources.

    For each entry of \"Active Directory\" or \"Open LDAP\" that is not using SSL/TLS, click the three vertical dots next to the \"Source Display Name\" and click \"Edit\".

    Select the \"Use SSL/TLS\" check box and click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000172-AS-000121'
  tag gid: 'V-VRPA-8X-000005'
  tag rid: 'SV-VRPA-8X-000005'
  tag stig_id: 'VRPA-8X-000005'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
