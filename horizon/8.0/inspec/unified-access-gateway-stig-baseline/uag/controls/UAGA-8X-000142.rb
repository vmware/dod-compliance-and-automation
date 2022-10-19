control 'UAGA-8X-000142' do
  title 'The UAG must prevent rendering inside a frame or iframe on another site by including the X-Frame-Options Security Header.'
  desc  "
    Clickjacking, also known as a “UI redress attack”, is when an attacker uses multiple transparent or opaque layers to trick a user into clicking on a button or link on another page when they were intending to click on the top level page. Thus, the attacker is “hijacking” clicks meant for the original page and routing them to another page, most likely owned by another application, domain, or both.

    Using a similar technique, keystrokes can also be hijacked. With a carefully crafted combination of stylesheets, iframes, and text boxes, a user can be led to believe they are typing in the password to their email or bank account, but are instead typing into an invisible frame controlled by the attacker.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings and set the \"Edge Service Settings\" toggle to \"SHOW\".

    Click the gear icon to view the Horizon Settings >> Click \"More\" at the bottom of the dialog.

    If the \"Response Security Headers\" do not contain an entry for \"X-Frame-Options\" with a value of \"SAMEORIGIN\", this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings and set the \"Edge Service Settings\" toggle to \"SHOW\".

    Click the gear icon to view the Horizon Settings >> Click \"More\" at the bottom of the dialog.

    Add or edit the \"X-Frame-Options\" entry and ensure it has a value of \"SAMEORIGIN\".

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000512-ALG-000066'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000142'
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
      describe 'Checking Connection Server X-Frame-Options' do
        subject { cs['securityHeaders']['X-Frame-Options'] }
        it { should cmp 'SAMEORIGIN' }
      end
    end
  end
end
