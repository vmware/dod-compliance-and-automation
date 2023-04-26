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

    Navigate to General Settings >> Edge Service Settings >> Toggle the icon to \"Show\".

    Check the status of the non-Horizon Edge Services, including:

    Reverse Proxy Settings (not supported in FIPS mode)
    Tunnel Settings
    Secure Email Gateway Settings
    Content Gateway Settings (not supported in FIPS mode)

    If any non-Horizon Edge Service is enabled, but not in use in the environment, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings >> Edge Service Settings >> Toggle the icon to \"Show\" >> Click the gear icon for \"Horizon Settings\".

    For each item below, enable or disable the toggle based on desired environment settings:

    Enable PCOIP
    Enable Blast
    Enable Tunnel
    Enable UDP Tunnel Server
    Disable HTML Access

    Click \"Save\".

    Navigate to General Settings >> Edge Service Settings >> Toggle the icon to \"Show\".

    For each non-Horizon Edge Service, click the gear icon, then enable or disable the toggle based on desired environment settings:

    Reverse Proxy Settings (not supported in FIPS mode)
    Tunnel Settings
    Secure Email Gateway Settings
    Content Gateway Settings (not supported in FIPS mode)

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000131-ALG-000085'
  tag satisfies: ['SRG-NET-000131-ALG-000086', 'SRG-NET-000132-ALG-000087', 'SRG-NET-000313-ALG-000010']
  tag gid: 'V-UAGA-8X-000034'
  tag rid: 'SV-UAGA-8X-000034'
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

    # It's ok if a service is "allowed" to be enabled, but is actually currently disabled
    # We really want to find the ones that are NOT allowed to be enabled, but actually are
    # So lots of if/then checks
    svclist.each do |svc|
      if svc['identifier'].eql? 'VIEW'
        found = false
        if svc['enabled'].eql? true
          if svc['pcoipEnabled'].eql? true
            found = true
            describe 'Checking Enable PCOIP Setting' do
              subject { svc['pcoipEnabled'] }
              it { should cmp input('allowPCOIP') }
            end
          end
          if svc['blastEnabled'].eql? true
            found = true
            describe 'Checking Enable BLAST Setting' do
              subject { svc['blastEnabled'] }
              it { should cmp input('allowBLAST') }
            end
          end
          if svc['tunnelEnabled'].eql? true
            found = true
            describe 'Checking Enable TUNNEL Setting' do
              subject { svc['tunnelEnabled'] }
              it { should cmp input('allowTUNNEL') }
            end
          end
          if svc['udpTunnelServerEnabled'].eql? true
            found = true
            describe 'Checking Enable UDP TUNNEL Setting' do
              subject { svc['udpTunnelServerEnabled'] }
              it { should cmp input('allowUDPTUNNEL') }
            end
          end
          if svc['disableHtmlAccess'].eql? true
            found = true
            describe 'Checking Disable HTML Access Setting' do
              subject { svc['disableHtmlAccess'] }
              it { should cmp input('disableHTMLACCESS') }
            end
          end
          unless found
            describe 'No Horizon Gateways enabled' do
              skip 'No Horizon Gateways enabled'
            end
          end
        else
          describe 'Horizon Gateway not enabled' do
            skip 'Horizon Gateway not enabled'
          end
        end
      elsif svc['identifier'].eql? 'TUNNEL_GATEWAY'
        if svc['enabled'].eql? true
          describe 'Checking Tunnel Gateway Setting' do
            subject { svc['enabled'] }
            it { should cmp input('allowTUNNELGATEWAY') }
          end
        else
          describe 'Tunnel Gateway not enabled' do
            skip 'Tunnel Gateway not enabled'
          end
        end
      elsif svc['identifier'].eql? 'SEG'
        if svc['enabled'].eql? true
          describe 'Checking Secure Email Gateway Setting' do
            subject { svc['pcoipEnabled'] }
            it { should cmp input('allowSECUREEMAILGATEWAY') }
          end
        else
          describe 'Secure Email Gateway not enabled' do
            skip 'Secure Email Gateway not enabled'
          end
        end
      end
    end
  end
end
