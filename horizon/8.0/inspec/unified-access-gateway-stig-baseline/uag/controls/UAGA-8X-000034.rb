control 'UAGA-8X-000034' do
  title 'The UAG must not have unnecessary services and functions enabled.'
  desc  "
    Information systems are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the necessary core functionality for each component. Unnecessary capabilities or services are often overlooked and therefore may increase the attack surface.

    The primary function of the UAG is to proxy connections to a Horizon Connection Server. There are multiple methods that clients can use to connect to a Horizon Connection Server, including PCOIP, Blast, HTML Access, and secure Tunnels. The UAG is capable of proxying all of the access methods to the Horizon Connection Server. Any of the methods that are not utilized in the environment must not be enabled.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings >> Edge Service Settings >> Toggle the icon to \"Show\">> Click the gear icon for \"Horizon Settings\".

    Check the status of the following toggle items:

    Enable PCOIP
    Enable Blast
    Enable Tunnel
    Enable UDP Tunnel Server
    Disable HTML Access

    If any item is enabled, but not in use in the environment, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings >> Edge Service Settings >> Toggle the icon to \"Show\">> Click the gear icon for \"Horizon Settings\".

    For each item below, enable or disable the toggle based on desired environment settings:

    Enable PCOIP
    Enable Blast
    Enable Tunnel
    Enable UDP Tunnel Server
    Disable HTML Access

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000131-ALG-000085'
  tag satisfies: ['SRG-NET-000131-ALG-000086', 'SRG-NET-000132-ALG-000087', 'SRG-NET-000313-ALG-000010']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000034'
  tag cci: ['CCI-000381', 'CCI-000382', 'CCI-002314']
  tag nist: ['AC-17 (1)', 'CM-7 a', 'CM-7 b']

  result = uaghelper.runrestcommand('rest/v1/config/edgeservice')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    svclist = jsoncontent['edgeServiceSettingsList']

    found = false
    svclist.each do |svc|
      next unless svc['identifier'] == 'VIEW'
      found = true
      next unless svc['proxyDestinationUrl'].include?(input('connectionserver'))
      describe 'Checking Enable PCOIP Setting' do
        subject { svc['pcoipEnabled'] }
        it { should cmp input('allowPCOIP') }
      end
      describe 'Checking Enable BLAST Setting' do
        subject { svc['blastEnabled'] }
        it { should cmp input('allowBLAST') }
      end
      describe 'Checking Enable TUNNEL Setting' do
        subject { svc['tunnelEnabled'] }
        it { should cmp input('allowTUNNEL') }
      end
      describe 'Checking Enable UDP TUNNEL Setting' do
        subject { svc['udpTunnelServerEnabled'] }
        it { should cmp input('allowUDPTUNNEL') }
      end
      describe 'Checking Disable HTML Access Setting' do
        subject { svc['disableHtmlAccess'] }
        it { should cmp input('disableHTMLACCESS') }
      end
    end

    unless found
      describe 'No Connection Server configuration found' do
        subject { found }
        it { should cmp true }
      end
    end
  end
end
