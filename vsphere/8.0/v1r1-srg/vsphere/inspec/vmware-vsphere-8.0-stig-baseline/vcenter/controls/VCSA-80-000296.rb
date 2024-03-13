control 'VCSA-80-000296' do
  title 'The vCenter server must enable the OVF security policy for content libraries.'
  desc  "
    In the vSphere Client, you can create a local or a subscribed content library. By using content libraries, you can store and manage content in one vCenter Server instance. Alternatively, you can distribute content across vCenter Server instances to increase consistency and facilitate the deployment workloads at scale.

    You can protect the OVF items by applying default OVF security policy to a content library. The OVF security policy enforces strict validation on OVF items when you deploy or update the item, import items, or synchronize OVF and OVA templates. To make sure that the OVF and OVA templates are signed by a trusted certificate, you can add the OVF signing certificate from a trusted CA.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Content Libraries.

    Review the \"Security Policy\" column.

    If a content library does not have the \"OVF default policy\" enabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Content Libraries.

    Select the target content library.

    Select \"Actions\" then \"Edit Settings\".

    Click the checkbox to \"Apply Security Policy\". Click \"OK\".

    Note: If you disable the security policy of a content library, you cannot reuse the existing OVF items.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCSA-80-000296'
  tag rid: 'SV-VCSA-80-000296'
  tag stig_id: 'VCSA-80-000296'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-ContentLibrary | Select-Object -ExpandProperty Id'
  libraries = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  setimpact = true
  if !libraries.empty?
    libraries.each do |library|
      libinfo = powercli_command("Invoke-GetLibraryIdContent #{library} | ConvertTo-Json").stdout
      libinfojson = JSON.parse(libinfo)
      describe "OVF security policy should be enabled on Content Library: #{libinfojson['name']}" do
        subject { libinfojson }
        its(['security_policy_id']) { should_not be nil }
      end
      setimpact = false
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
