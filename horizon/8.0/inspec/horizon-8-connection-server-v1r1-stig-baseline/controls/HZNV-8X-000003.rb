control 'HZNV-8X-000003' do
  title 'The Horizon Connection Server must be configured to only support TLS 1.2 connections.'
  desc  "
    Preventing the disclosure of transmitted information requires that the application server take measures to employ strong cryptographic mechanisms to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

    TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for Government systems.

    According to NIST and as of publication, TLS 1.1 must not be used and TLS 1.2 must be configured.

    Note: Mandating TLS 1.2 may affect certain client types. Test and implement carefully.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    If a file named \"locked.properties\" does not exist in this path, confirm with the SA if TLS 1.2 was enforced at a global level via ADSI EDIT. If no such global change was made, this is a finding.

    Open or create the \"locked.properties\" file in a text editor.

    Ensure the \"secureProtocols.1\" and \"preferredSecureProtocol\" settings are set as follows:

    secureProtocols.1=TLSv1.2
    preferredSecureProtocol=TLSv1.2

    If there is a \"secureProtocols.2\" or \"secureProtocols.3\" setting, this is a finding.

    If the \"secureProtocols.1\" and \"preferredSecureProtocol\" are not set exactly as above, this is a finding.
  "
  desc 'fix', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    Open or create the \"locked.properties\" file in a text editor.

    Remove any \"secureProtocols.2\" or \"secureProtocols.3\" settings.

    Add or change the following lines:

    secureProtocols.1=TLSv1.2
    preferredSecureProtocol=TLSv1.2

    Save and close the file.

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag satisfies: ['SRG-APP-000014-AS-000009', 'SRG-APP-000156-AS-000106', 'SRG-APP-000172-AS-000120', 'SRG-APP-000439-AS-000155', 'SRG-APP-000440-AS-000167', 'SRG-APP-000442-AS-000259']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000003'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-001453', 'CCI-001941', 'CCI-002418', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'IA-2 (8)', 'IA-5 (1) (c)', 'SC-8', 'SC-8 (1)', 'SC-8 (2)']

  horizonhelper.setconnection

  if file("#{input('sslConfFolderPath')}\\locked.properties").exist?
    file_content = parse_config_file("#{input('sslConfFolderPath')}\\locked.properties")
    describe 'Checking for secureProtocols.2' do
      subject { file_content['secureProtocols.2'] }
      it { should cmp nil }
    end
    describe 'Checking for secureProtocols.3' do
      subject { file_content['secureProtocols.3'] }
      it { should cmp nil }
    end
    describe 'Checking for secureProtocols.1' do
      subject { file_content['secureProtocols.1'] }
      it { should cmp 'TLSv1.2' }
    end
    describe 'Checking for preferredSecureProtocol' do
      subject { file_content['preferredSecureProtocol'] }
      it { should cmp 'TLSv1.2' }
    end
  else
    describe file("#{input('sslConfFolderPath')}\\locked.properties") do
      it { should exist }
    end
  end
end
