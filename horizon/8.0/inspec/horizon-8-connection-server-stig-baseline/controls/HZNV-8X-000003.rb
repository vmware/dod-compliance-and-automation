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
    On the Horizon Connection Server, navigate to \"<install_directory>\\sslgateway\\conf\".

    If a file named \"locked.properties\" exists in this path, open the file in a text editor.

    If the \"locked.properties\" file contains entries for \"secureProtocols\" or \"preferredSecureProtocol\", ensure the values are set as follows:

    secureProtocols=TLSv1.2
    preferredSecureProtocol=TLSv1.2

    If the \"secureProtocols\" and \"preferredSecureProtocol\" are not set exactly as above, this is a finding.

    If no \"locked.properties\" file exists, or it exists but does not contain the \"secureProtocols\" or \"preferredSecureProtocol\" settings, then open the \"config.properties\" file in a text editor.

    Ensure the values for \"secureProtocols.1\" and \"preferredSecureProtocol\" are set as follows:

    secureProtocols.1=TLSv1.2
    preferredSecureProtocol=TLSv1.2

    If the \"secureProtocols.1\" and \"preferredSecureProtocol\" are not set exactly as above, this is a finding.

    NOTE: \"<install_directory>\" defaults to \"%PROGRAMFILES%\\VMware\\VMware View\\Server\\\" unless changed during install.
  "
  desc 'fix', "
    FIPS mode can only be implemented during installation.

    Re-deploy the Virtual Machine and install the Horizon Connection Server with the FIPS mode option selected.

    Note: The Connection Server can only be installed in FIPS mode if Windows Server itself is running in FIPS mode. If not installed in FIPS mode initially, the recommendation is to re-deploy the Virtual Machine, enable FIPS mode in Windows, and install the Connection Server rather than uninstalling and reinstalling the Connection Server software, as LDAP issues may occur between installation types.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag satisfies: ['SRG-APP-000014-AS-000009', 'SRG-APP-000156-AS-000106', 'SRG-APP-000172-AS-000120', 'SRG-APP-000439-AS-000155', 'SRG-APP-000440-AS-000167', 'SRG-APP-000442-AS-000259']
  tag gid: 'V-HZNV-8X-000003'
  tag rid: 'SV-HZNV-8X-000003'
  tag stig_id: 'HZNV-8X-000003'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-001453', 'CCI-001941', 'CCI-002418', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'IA-2 (8)', 'IA-5 (1) (c)', 'SC-8', 'SC-8 (1)', 'SC-8 (2)']

  horizonhelper.setconnection

  # check in following order:
  # 1. locked.properties exist? if so, does it contain values for both properties?
  # 2. if "no" to either question, check "config.properties", values should be there.

  secureFound = false
  preferredFound = false

  if file("#{input('sslConfFolderPath')}\\locked.properties").exist?
    locked_content = parse_config_file("#{input('sslConfFolderPath')}\\locked.properties")

    unless locked_content['secureProtocols'].nil?
      secureFound = true
      describe 'Checking locked.properties for secureProtocols' do
        subject { locked_content['secureProtocols'] }
        it { should cmp 'TLSv1.2' }
      end
    end

    unless locked_content['preferredSecureProtocol'].nil?
      preferredFound = true
      describe 'Checking locked.properties for preferredSecureProtocol' do
        subject { locked_content['preferredSecureProtocol'] }
        it { should cmp 'TLSv1.2' }
      end
    end

  end

  unless secureFound && preferredFound
    config_content = parse_config_file("#{input('sslConfFolderPath')}\\config.properties")

    unless secureFound
      describe 'Checking config.properties for secureProtocols.1' do
        subject { config_content['secureProtocols.1'] }
        it { should cmp 'TLSv1.2' }
      end
    end

    unless preferredFound
      describe 'Checking config.properties for preferredSecureProtocol' do
        subject { config_content['preferredSecureProtocol'] }
        it { should cmp 'TLSv1.2' }
      end
    end

  end
end
