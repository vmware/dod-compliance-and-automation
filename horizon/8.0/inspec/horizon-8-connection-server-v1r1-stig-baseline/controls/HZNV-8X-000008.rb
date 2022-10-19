control 'HZNV-8X-000008' do
  title 'The Horizon Connection Server must require DoD PKI for administrative logins.'
  desc  "
    The Horizon Connection Server console supports CAC login as required for cryptographic non-repudiation. CAC login can be configured as disabled, optional, or required, but for maximum assurance it must be set to \"required\".

    In some circumstance, setting the CAC login as \"optional\" may be appropriate in order to support a \"break glass\" scenario where PKI is failing, but an emergency access account configured with a username and password can be utilized.
  "
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server Console. From the left pane, navigate to Settings >> Servers. In the right pane, select the \"Connection Servers\" tab. For each Connection Server listed, select the server and click \"Edit\". Click the \"Authentication\" tab. Scroll down to \"Horizon Administrator Authentication\". Find the currently configured value in the drop down next to \"Smart card authentication for administrators\".

    If \"Smart card authentication for administrators\" is not set to \"Required\", this is a finding.

    Note: If another form of DoD approved PKI is used, and configured to be required for administrative logins, this is not a finding.
  "
  desc  'fix', "
    Log in to Horizon Connection Server Console and copy all root and intermediate certificates, in the required base-64 '.cer' format, to a folder named '<install_drive>:\\Certs'.

    If  the \"<Install Drive>:\\Certs” folder does not exist, create it.

    Copy the provided make_keystore.txt to the Horizon Connection Server into the \"<install_drive>\\VMware\\VMware View\\Server\\sslgateway\\conf\" folder. Rename \"make_keystore.txt\" to “makekeystore.ps1”.  The \"make_keystore.txt\" content is provided in this STIG package.

    Launch PowerShell as an administrator on the Horizon Connection Server and execute the following commands:

    cd \"<install_drive>\\VMware\\VMware View\\Server\\sslgateway\\conf\"
    Set-ExecutionPolicy unrestricted
    (type 'Y' when prompted)
    .\\make_keystore.ps1 -CertDir <install_drive>:\\Certs -Password <store password> -KeyStore keystore -LockedProperties locked.properties

    Copy the created \"locked.properties\" and \"keystore\" files to any Horizon Connection Server that shares the same trusted issuers. Omit this step if multiple connection servers are not utilized.

    Log in to the Horizon Connection Server Console. From the left pane, navigate to Settings >> Servers.

    In the right pane, select the \"Connection Servers\" tab.

    For each Connection Server listed, select the server and click \"Edit\".

    Select the \"Authentication\" tab. Scroll down to \"View Administrator Authentication\". Select \"Required\" for the \"Smart card authentication for administrators\". Click \"OK\". Repeat for all other Horizon Connection Servers.

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000080-AS-000045'
  tag satisfies: ['SRG-APP-000149-AS-000102', 'SRG-APP-000151-AS-000103', 'SRG-APP-000153-AS-000104', 'SRG-APP-000177-AS-000126', 'SRG-APP-000391-AS-000239', 'SRG-APP-000392-AS-000240', 'SRG-APP-000403-AS-000248']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000008'
  tag cci: ['CCI-000166', 'CCI-000187', 'CCI-000765', 'CCI-000767', 'CCI-000770', 'CCI-001953', 'CCI-001954', 'CCI-002010']
  tag nist: ['AU-10', 'IA-2 (1)', 'IA-2 (12)', 'IA-2 (3)', 'IA-2 (5)', 'IA-5 (2) (c)', 'IA-8 (1)']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithsession('view-vlsi/rest/v1/ConnectionServer/list')

  cslist = JSON.parse(result.stdout)

  cslist['value'].each do |cs|
    if cs['general']['fqhn'].upcase == horizonhelper.getinput('fqdn').upcase
      describe 'CS fqdn matched - ' + cs['general']['fqhn'] do
        subject { cs['authentication']['smartCardSupportForAdmin'] }
        it { should cmp 'ON' }
      end
    else
      describe 'CS not matched - ' + cs['general']['fqhn'] do
        skip 'CS fqdn not matched - ' + cs['general']['fqhn']
      end
    end
  end
end
