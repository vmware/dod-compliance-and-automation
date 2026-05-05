control 'VCFT-9X-000003' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must implement cryptography mechanisms to protect the integrity of the remote access session.'
  desc  "
    Encryption is critical for protection of remote access sessions. If encryption is not being used for integrity, malicious users may gain the ability to modify the application server configuration. The use of cryptography for ensuring integrity of remote access sessions mitigates that risk.

    Application servers utilize a web management interface and scripted commands when allowing remote access. Web access requires the use of TLS, and scripted access requires using ssh or some other form of approved cryptography. Application servers must have a capability to enable a secure remote admin capability.

    FIPS 140-2 approved TLS versions must be enabled, and non-FIPS-approved SSL versions must be disabled.

    NIST SP 800-52 specifies the preferred configurations for government systems.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # xmllint --xpath \"//Connector[not(@redirectPort)]/@sslEnabledProtocols\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    Example result:

    sslEnabledProtocols=\"TLSv1.2,TLSv1.3\"

    If the value of \"sslEnabledProtocols\" is not configured to include only \"TLSv1.2\" or \"TLSv1.3\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/etc/3rd_config/server.xml

    Configure the <Connector> node for port 443 with the property 'sslEnabledProtocols=\"TLSv1.2,TLSv1.3\"'.

    Example:
        <Connector
             ...
             sslEnabledProtocols=\"TLSv1.2,TLSv1.3\"
             ...
        />

    Restart the service with the following command:

    # systemctl restart loginsight.service

    Note: The configuration in \"/usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml\" is generated when the service restarts based on the contents of the \"/usr/lib/loginsight/application/etc/3rd_config/server.xml\" file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag satisfies: ['SRG-APP-000172-AS-000120', 'SRG-APP-000439-AS-000155', 'SRG-APP-000440-AS-000167', 'SRG-APP-000441-AS-000258', 'SRG-APP-000442-AS-000259']
  tag gid: 'V-VCFT-9X-000003'
  tag rid: 'SV-VCFT-9X-000003'
  tag stig_id: 'VCFT-9X-000003'
  tag cci: ['CCI-000197', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'SC-8', 'SC-8 (1)', 'SC-8 (2)']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")
  sslEnabledProtocols = xmlconf['//Connector[not(@redirectPort)]/@sslEnabledProtocols']

  if !sslEnabledProtocols.empty?
    # splitting here since this is an array but its only a single element with a comma separated string of protocols
    sslEnabledProtocols[0].split(',').each do |protocol|
      describe protocol do
        it { should be_in input('tlsProtocols') }
      end
    end
  else
    describe 'Enabled SSL Protocols' do
      subject { sslEnabledProtocols }
      it { should_not be_empty }
    end
  end
end
