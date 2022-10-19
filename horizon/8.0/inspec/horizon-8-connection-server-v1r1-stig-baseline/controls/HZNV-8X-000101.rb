control 'HZNV-8X-000101' do
  title 'The Horizon Connection Server must be configured with a DoD-issued TLS certificate.'
  desc  "
    Machines on a DoD network must only accept PKI certificates obtained from a DoD-approved internal or external certificate authority (CA). If the CA used for verifying the certificate is not DoD-approved, trust of the CA will not be established.

    The Horizon Connection Server supports the replacement of the default, self-signed certificate with one issued by a DoD CA. This is accomplished through the normal Windows Server certificate management tools.

    Follow VMware documentation for replacing the Horizon Connection Server certificate, with the end result being a certificate that is configured with the \"vdm\" friendly name.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, open \"certlm.msc\" or \"certmgr.msc\" (Certificate Management - Local Computer).

    Select Personal >> Certificates.

    In the right pane, locate the certificate with the \"Friendly Name\" of \"vdm\".

    For this certificate, locate the issuer in the \"Issued By\" column.

    If the Horizon Connection Server broker certificate is not \"Issued By\" a trusted DoD CA, this is a finding.
  "
  desc 'fix', "
    Obtain a web server certificate from a DoD authority, specifying the common name as the Horizon Connection server FQDN, the signing algorithm as \"SHA256\", and the key strength of at least \"1024 bits\".

    Export the certificate and private key to a password-protected PFX bundle.

    On the Horizon Connection Server, open \"certlm.msc\" or \"certmgr.msc\" (Certificate Management - Local Computer).

    Rename the existing certificate, if it exists:

    > Select Personal >> Certificates, then in the right pane, locate the certificate with the \"Friendly Name\" of \"vdm\".

    > Right-click this certificate, select \"Properties\", and change the \"Friendly name\" to \"vdm-original\" or something similar.

    > Click \"OK\".

    Import the new certificate:

    > Right click on the Personal >> Certificates folder.

    > Select All Tasks >> Import.

    > Click \"Next\", then \"Browse...\", navigate to the .pfx bundle and click \"Open\".

    > Click \"Next\", supply the password, select \"Mark this key as exportable\" and \"Include all extended properties\", then click \"Next\", \"Next\", then Finish\".

    > Right-click on the newly imported certificate, select \"Properties\", then change the \"Friendly name\" to \"vdm\" (this name must match exactly in name and case).

    > Click \"OK\".

    Restart the Connection Server or the \"VMware Horizon View Connection Server\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000427-AS-000264'
  tag satisfies: ['SRG-APP-000514-AS-000137']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000101'
  tag cci: ['CCI-002450', 'CCI-002470']
  tag nist: ['SC-13', 'SC-23 (5)']

  horizonhelper.setconnection

  certinfo = powershell("Get-ChildItem Cert:\\LocalMachine\\My\\* | Select Subject, FriendlyName, Issuer | Where-Object {$_.FriendlyName -eq 'vdm'} | ConvertTo-Json")

  json = JSON.parse(certinfo.stdout)

  allowed = input('allowedCertAuth')

  describe allowed do
    it { should include json['Issuer'].upcase }
  end
end
