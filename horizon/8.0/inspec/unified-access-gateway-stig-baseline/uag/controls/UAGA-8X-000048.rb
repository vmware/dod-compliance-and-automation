control 'UAGA-8X-000048' do
  title 'The UAG must only allow packages signed from a trusted signature authority to be installed.'
  desc  "
    Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

    The UAG allows for updates to be downloaded and installed with three options: \"Don't Apply Updates\", \"Apply Updates on Next Boot\", or \"Apply Updates on Every Boot\". The recommended strategy is for an administrator to determine when updates should be applied, and manually configure the value to \"Apply Updates on Next Boot\". With this setting, once updates are applied, the UAG reverts the setting back to \"Don't Apply Updates\" automatically.

    Additional configuration items include the URL for OS packages, the URL for Appliance packages, and a means for uploading trusted certificates for the package sources. If the OS or Appliance package URLs are changed from the default location of \"packages.vmware.com\", then trusted certificates must be uploaded in order for the UAG to pull and validate the packages from a local source.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> Appliance Updates Settings.

    Click the \"Gear\" icon to check the settings.

    Verify the \"OS Updates URL\" and \"Appliance Updates URL\" are set to allowed locations for package update sources.

    If either URL has been changed from its default value of \"packages.vmware.com\", and a trusted certificate has not been uploaded for each changed value, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> Appliance Updates Settings.

    Click the \"Gear\" icon to check the settings.

    Option 1:

    > Revert any changed URL locations back to their default by clearing the field and clicking \"Save\".

    Option 2:

    > For each changed URL (OS or Appliance) upload a trusted certificate and click \"Save\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000228-ALG-000108'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000048'
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']

  result = uaghelper.runrestcommand('rest/v1/config/settings')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe 'Checking Package Update Settings' do
      if !jsoncontent['packageUpdatesSettings'].nil?
        if !jsoncontent['packageUpdatesSettings']['packageUpdatesOSURL'].nil? || !jsoncontent['packageUpdatesSettings']['packageUpdatesURL'].nil?
          describe 'Checking for Trusted Certificate for alternate package locations' do
            subject { jsoncontent['packageUpdatesSettings']['trustedCertificates'] }
            it { should_not cmp nil }
          end
        else
          describe 'No alternate package locations defined' do
            skip 'No alternate package locations defined, trusted cert not required'
          end
        end
      else
        describe 'No alternate package locations defined' do
          skip 'No alternate package locations defined, trusted cert not required'
        end
      end
    end
  end
end
