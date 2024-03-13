control 'VCSA-80-000295' do
  title 'The vCenter server must require authentication for published content libraries.'
  desc  'In the vSphere Client, you can create a local or a subscribed content library. By using content libraries, you can store and manage content in one vCenter Server instance. Alternatively, you can distribute content across vCenter Server instances to increase consistency and facilitate the deployment workloads at scale. When publishing a content library it can be protected by requiring authentication for subscribers.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Content Libraries.

    Review the \"Password Protected\" column.

    If a content library is published and is not password protected, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Content Libraries.

    Select the target content library.

    Select \"Actions\" then \"Edit Settings\".

    Click the checkbox to \"Enable user authentication for access to this content library\".

    Enter and confirm a password for the content library. Click \"Ok\".

    Note: Any subscribed content libraries will need to be updated to enable authentication and provide the password.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCSA-80-000295'
  tag rid: 'SV-VCSA-80-000295'
  tag stig_id: 'VCSA-80-000295'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-ContentLibrary | Select-Object -ExpandProperty Id'
  libraries = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  setimpact = true
  if !libraries.empty?
    libraries.each do |library|
      libinfo = powercli_command("Invoke-GetLibraryIdContent #{library} | ConvertTo-Json").stdout
      libinfojson = JSON.parse(libinfo)
      if libinfojson['publish_info']['published'] == true
        describe "Authentication should be enabled on Content Library: #{libinfojson['name']}" do
          subject { libinfojson }
          its(['publish_info', 'authentication_method']) { should cmp 'BASIC' }
        end
        setimpact = false
      else
        describe "Publishing not enabled on Content Library: #{libinfojson['name']}. This control is not applicable." do
          skip "Publishing not enabled on Content Library: #{libinfojson['name']}. This control is not applicable."
        end
      end
    end
  else
    describe '' do
      skip 'No content libraries found. This control is not applicable.'
    end
  end
  unless !setimpact
    impact 0.0
  end
end
