control 'HZNV-8X-000140' do
  title 'The PCoIP Secure Gateway must be configured with a DoD-issued TLS certificate.'
  desc  "
    The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority (CA). If the CA used for verifying the certificate is not a DoD-approved CA, trust of the CA will not be established.

    The PCoIP Secure Gateway supports the replacement of the default, self-signed certificate with one issued by a DoD CA. This is accomplished through the normal Windows Server certificate management tools. For simplicity, it is recommended to use the same certificate as previously configured for the Connection Server itself via the certificate with the \"vdm\" friendly name.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, launch the Registry Editor.

    Traverse the registry tree to \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Teradici\\SecurityGateway\".

    Locate the \"SSLCertWinCertFriendlyName\" key.

    If \"SSLCertWinCertFriendlyName\" does not exist, this is a finding.

    If \"SSLCertWinCertFriendlyName\" is set to \"vdm\", this is not a finding.

    If \"SSLCertWinCertFriendlyName\" is present, but the value is not set to \"vdm\", perform the following steps:

    > Note the value of \"SSLCertWinCertFriendlyName\". This is the friendly name of the PCoIP Secure Gateway certificate.

    > On the Horizon Connection Server, open \"certlm.msc\" or \"certmgr.msc\" (Certificate Management - Local Computer).

    > Select Personal >> Certificates.

    > In the right pane, locate the certificate with the \"Friendly Name\" of the previously noted value of \"SSLCertWinCertFriendlyName\".

    > For this certificate, locate the issuer in the \"Issued By\" column.

    If the PCoIP Secure Gateway certificate is not \"Issued By\" a trusted DoD CA, this is a finding.

    Note: If the PCoIP Secure Gateway is not enabled, this is not applicable.
  "
  desc 'fix', "
    On the Horizon Connection Server, launch the Registry Editor.

    Traverse the registry tree to \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Teradici\\SecurityGateway\".

    Option One - Use the same certificate as the Connection Server:

    > Create a new String (REG_SZ) key named \"SSLCertWinCertFriendlyName\".

    > Set its value to \"vdm\".

    Option Two - Use a different certificate for the PCoIP Secure Gateway:

    > Create a new String (REG_SZ) key named \"SSLCertWinCertFriendlyName\".

    > Set its value (\"pcoip\", for example).

    > Obtain a web server certificate from a DoD CA, specifying the common name as the Horizon Connection server FQDN, the signing algorithm as \"SHA256\" and the key strength of at least \"1024 bits\".

    > Export the certificate and private key to a password-protected PFX bundle.

    > Right-click on the Personal >> Certificates folder.

    > Select All Tasks >> Import.

    > Click \"Next\", then \"Browse...\", then navigate to the .pfx bundle and click \"Open\".

    > Click \"Next\", supply the password, select \"Mark this key as exportable\" and \"Include all extended properties\", then click \"Next\", \"Next\" and \"Finish\".

    > Right-click the newly imported certificate and select \"Properties\".

    > Change the \"Friendly name\" to what was set earlier (\"pcoip\", for example). This name must be exact in name and case, as set above. Click \"OK\".

    Restart the \"VMware Horizon View PCoIP Secure Gateway\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000140'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  # Get the cert name from the registry, if there
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Teradici\\SecurityGateway') do
    it { should have_property 'SSLCertWinCertFriendlyName' }
  end

  regval = registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Teradici\\SecurityGateway').SSLCertWinCertFriendlyName.to_s

  unless regval.nil?
    certinfo = powershell("Get-ChildItem Cert:\\LocalMachine\\My\\* | Select Subject, FriendlyName, Issuer | Where-Object {$_.FriendlyName -eq '#{regval}'} | ConvertTo-Json")

    json = JSON.parse(certinfo.stdout)

    allowed = input('allowedCertAuth')

    describe allowed do
      it { should include json['Issuer'].upcase }
    end
  end
end
