control 'VCFA-9X-000336' do
  title 'The VMware Cloud Foundation vCenter Server must require authentication for published content libraries.'
  desc  'In the vSphere Client, you can create a local or a subscribed content library. By using content libraries, you can store and manage content in one vCenter Server instance. Alternatively, you can distribute content across vCenter Server instances to increase consistency and facilitate the deployment workloads at scale. When publishing a content library it can be protected by requiring authentication for subscribers.'
  desc  'rationale', ''
  desc  'check', "
    If Content Libraries are not used, this is not applicable.

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
  tag gid: 'V-VCFA-9X-000336'
  tag rid: 'SV-VCFA-9X-000336'
  tag stig_id: 'VCFA-9X-000336'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-ContentLibrary | Select-Object -ExpandProperty Id'
  libraries = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if !libraries.blank?
    libraries.each do |library|
      libinfo = powercli_command("Invoke-GetLibraryIdContent -LibraryId #{library} -Confirm:$false | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue").stdout.strip
      libinfojson = JSON.parse(libinfo)
      if !libinfojson['PublishInfo'].blank? && libinfojson['PublishInfo']['Published'] == true
        describe "Authentication should be enabled on Content Library: #{libinfojson['Name']}" do
          subject { libinfojson }
          its(['PublishInfo', 'AuthenticationMethod']) { should cmp 'BASIC' }
        end
      elsif !libinfojson['PublishInfo'].blank? && libinfojson['PublishInfo']['Published'] == false
        describe "Publishing not enabled on Content Library: #{libinfojson['Name']}. Authentication not required." do
          subject { libinfojson }
          its(['PublishInfo', 'Published']) { should cmp false }
        end
      else
        describe "Subscribed content library: #{libinfojson['Name']} found. Publishing should not be enabled." do
          subject { libinfojson }
          its(['PublishInfo']) { should be_blank }
        end
      end
    end
  else
    impact 0.0
    describe 'No content libraries found. This is not applicable.' do
      skip 'No content libraries found. This is not applicable.'
    end
  end
end
