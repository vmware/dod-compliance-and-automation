control 'UAGA-8X-000152' do
  title 'The UAG must protect against MIME type sniffing by setting the X-Content-Type-Options Security Header.'
  desc  "
    MIME type sniffing is a technique used by some web browsers to examine the content of a particular asset, in order to determine the asset's file format. This technique is useful in the event that there is not enough metadata information present for a particular asset, thus leaving the possibility that the browser interprets the asset type incorrectly.

    Although MIME type sniffing can be useful to determine an asset's correct file format, it can also cause a security vulnerability. This vulnerability can be quite dangerous both for site owners as well as site visitors. This is because an attacker can leverage MIME type sniffing to send an XSS (Cross Site Scripting) attack.

    Setting the X-Content-Type-Options Security Header prevents browsers from guessing the MIME type by telling the browser that MIME types are deliberately configured on the server.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings and set the \"Edge Service Settings\" toggle to \"SHOW\".

    Click the gear icon to view the Horizon Settings >> Click \"More\" at the bottom of the dialog.

    If the \"Response Security Headers\" do not contain an entry for \"X-Content-Type-Options\" with a value of \"nosniff\", this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings and set the \"Edge Service Settings\" toggle to \"SHOW\".

    Click the gear icon to view the Horizon Settings >> Click \"More\" at the bottom of the dialog.

    Add or edit the \"X-Content-Type-Options\" setting and ensure it has a value of \"nosniff\".

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000512-ALG-000066'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000152'
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
      describe 'Checking Connection Server X-Content-Type-Options' do
        subject { cs['securityHeaders']['X-Content-Type-Options'] }
        it { should cmp 'nosniff' }
      end
    end
  end
end
