control 'HZNV-8X-000127' do
  title 'The Horizon Connection Server must validate client and administrator certificates.'
  desc  "
    The Horizon Connection Server can be configured to check the revocation status of PKI certificates over both OCSP and CRL. This capability is disabled by default and must be enabled post-deployment.

    There are also a number of other configurations that are supported, including OCSP and CRL location override but those will be site and architecture specific.

    The recommended configuration is OCSP with failover to CRL and override the AIA locations via a local OCSP responder, if present.

    Example settings:

    enableRevocationChecking=true
    ocspCRLFailover=true
    ocspSendNonce=true
    enableOCSP=true
    allowCertCRLs=false
    crlLocation=http://<crl.myagency.mil>
    ocspURL=http://<ca.myagency.mil/ocsp>
    ocspSigningCert=<ca.myagency.mil.cer>

    Set enableRevocationChecking to true to enable smart card certificate revocation checking.
    Set ocspCRLFailover to enable CRL checking if OCSP fails.
    Set ocspSendNonce to true to prevent OCSP repeated responses.
    Set enableOCSP to true to enable OCSP certificate revocation checking.
    Set allowCertCRLs to false to disable pulling the CRL distribution point from the certificate.
    Set crlLocation to the URL to use for the CRL distribution point.
    Set ocspURL to the URL of the OCSP Responder.
    Set ocspSigningCert to the location of the file that contains the OCSP Responder's signing certificate.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    If a file named \"locked.properties\" does not exist in this path, this is a finding.

    Open the \"locked.properties\" file in a text editor.

    If \"enableRevocationChecking\" does not exist, or the value of \"enableRevocationChecking\" is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    Create or open \"locked.properties\" in a text editor.

    Add or change the following line:

    enableRevocationChecking=true

    Add or configure the remaining items per the discussion, based on site architecture.

    Save and close the file.

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000175-AS-000124'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000127'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (a)']

  horizonhelper.setconnection

  describe file("#{input('sslConfFolderPath')}\\locked.properties") do
    it { should exist }
  end

  unless !file("#{input('sslConfFolderPath')}\\locked.properties").exist?
    file_content = parse_config_file("#{input('sslConfFolderPath')}\\locked.properties")
    describe file_content['enableRevocationChecking'] do
      it { should cmp 'true' }
    end
  end
end
