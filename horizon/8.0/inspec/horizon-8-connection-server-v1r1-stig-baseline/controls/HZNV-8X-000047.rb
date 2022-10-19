control 'HZNV-8X-000047' do
  title 'The Horizon Connection Server must perform full path validation on server-to-server TLS connection certificates.'
  desc  "
    The Horizon Connection Server performs certificate revocation checking on its own certificate and on those of the security servers paired to it. Each instance also checks the certificates of vCenter and VDI machines whenever it establishes a connection to them. If a SAML 2.0 authenticator is configured for use by a Connection Server instance, the Connection Server also performs certificate revocation checking on the SAML 2.0 server certificate.

    By default, all certificates in the chain are checked except the root certificate. This must be changed so that the full path, including the root, is validated.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, launch the Registry Editor.

    Traverse the registry tree to \"HKLM\\Software\\VMware, Inc.\\VMware VDM\\Security\".

    Locate the \"CertificateRevocationCheckType\" key.

    If the \"CertificateRevocationCheckType\" key does not exist, this is a finding.

    If the \"CertificateRevocationCheckType\" key does not have a value of \"3\", this is a finding.
  "
  desc 'fix', "
    On the Horizon Connection Server, launch the Registry Editor.

    Traverse the registry tree to \"HKLM\\Software\\VMware, Inc.\\VMware VDM\\Security\".

    If the \"CertificateRevocationCheckType\" key exists:

    > Right click \"CertificateRevocationCheckType\", select \"Modify...\" and set the value to \"3\" (without quotes).

    > Click \"OK\".

    If the \"CertificateRevocationCheckType\" key does not exist:

    > Right-click on the \"Security\" folder and select \"New\" then \"DWORD (32 bit) Value\".

    > Set the name to \"CertificateRevocationCheckType\" (without quotes).

    > Right-click \"CertificateRevocationCheckType\", select \"Modify...\" and set the value to \"3\" (without quotes).

    > Click \"OK\".

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000175-AS-000124'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000047'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (a)']

  horizonhelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\\VMware VDM\\Security') do
    it { should have_property 'CertificateRevocationCheckType' }
    its('CertificateRevocationCheckType') { should cmp '3' }
  end
end
