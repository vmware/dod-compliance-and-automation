control 'HZNV-8X-000125' do
  title 'The Blast Secure Gateway must be configured to only support TLS 1.2 connections.'
  desc  "
    Preventing the disclosure of transmitted information requires that the application server take measures to employ strong cryptographic mechanisms to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

    TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for Government systems.

    According to NIST and as of publication, TLS 1.1 must not be used and TLS 1.2 will be configured.

    Note: Mandating TLS 1.2 may affect certain client types. Test and implement carefully. If the Horizon Connection Server is set to \"Do not use Blast Secure Gateway\", this control does not apply.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\appblastgateway\".

    If a file named \"absg.properties\" does not exist in this path, this is a finding.

    Open \"absg.properties\" in a text editor, and find the \"localHttpsProtocolLow\" and \"localHttpsProtocolHigh\" settings.

    Ensure they are set as follows:

    localHttpsProtocolLow=tls1.2
    localHttpsProtocolHigh=tls1.2

    If the \"localHttpsProtocolLow\" or \"localHttpsProtocolHigh\" settings do not exist, or are not exactly as above, this is a finding.

    Note: If the Horizon Connection Server is set to \"Do not use Blast Secure Gateway\", this control does not apply.
  "
  desc 'fix', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\appblastgateway\".

    Open or create the \"absg.properties\" file in a text editor.

    Add or update the following lines:

    localHttpsProtocolLow=tls1.2
    localHttpsProtocolHigh=tls1.2

    Save and close the file.

    Restart the \"VMware Horizon View Blast Secure Gateway\" service for changes to take effect.

    Note: If the Horizon Connection Server is set to \"Do not use Blast Secure Gateway\", this control does not apply.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000125'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithsession('view-vlsi/rest/v1/ConnectionServer/list')
  csinfo = JSON.parse(result.stdout)

  blastdisabled = false

  csinfo['value'].each do |cs|
    next unless cs['general']['fqhn'].upcase == horizonhelper.getinput('fqdn').upcase
    if cs['general']['bypassAppBlastGateway']
      blastdisabled = true
    end
  end

  if blastdisabled
    describe 'Blast Gateway Not In Use' do
      skip 'Blast Gateway Not In Use'
    end
  else
    describe file("#{input('blastGWFolderPath')}\\absg.properties") do
      it { should exist }
    end

    unless !file("#{input('blastGWFolderPath')}\\absg.properties").exist?
      file_content = parse_config_file("#{input('blastGWFolderPath')}\\absg.properties")
      describe file_content['localHttpsProtocolLow'] do
        it { should cmp 'tls1.2' }
      end
      describe file_content['localHttpsProtocolHigh'] do
        it { should cmp 'tls1.2' }
      end
    end
  end
end
