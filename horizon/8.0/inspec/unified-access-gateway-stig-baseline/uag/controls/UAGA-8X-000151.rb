control 'UAGA-8X-000151' do
  title 'The UAG must implement HTTP Strict Transport Security (HSTS) to protect the integrity of remote sessions.'
  desc  'HTTP Strict Transport Security (HSTS) instructs web browsers to only use secure connections for all future requests when communicating with a web site. Doing so helps prevent SSL protocol attacks, SSL stripping, cookie hijacking, and other attempts to circumvent SSL protection.'
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings and set the \"Edge Service Settings\" toggle to \"SHOW\".

    Click the gear icon to view the Horizon Settings >> Click \"More\" at the bottom of the dialog.

    If the \"Response Security Headers\" do not contain an entry for \"Strict-Transport-Security\", this is a finding.

    Note: The default UAG Strict-Transport-Security value is \"max-age=63072000; includeSubdomains; preload\".
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings and set the \"Edge Service Settings\" toggle to \"SHOW\".

    Click the gear icon to view the Horizon Settings >> Click \"More\" at the bottom of the dialog.

    Ensure the \"Strict-Transport-Security\" value is set to \"max-age=63072000; includeSubdomains; preload\".

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000512-ALG-000066'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000151'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = uaghelper.runrestcommand('rest/v1/config/edgeservice')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    jsoncontent['edgeServiceSettingsList'].each do |cs|
      next unless cs['proxyDestinationUrl'].include?(input('connectionserver'))
      describe 'Checking Connection Server Strict-Transport-Security' do
        subject { cs['securityHeaders']['Strict-Transport-Security'] }
        it { should include 'max-age' }
      end
    end
  end
end
