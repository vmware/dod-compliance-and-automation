control 'VCFA-9X-000340' do
  title 'The VMware Cloud Foundation vCenter Server must remove unauthorized port mirroring sessions on distributed switches.'
  desc  'The vSphere Distributed Virtual Switch can enable port mirroring sessions allowing traffic to be mirrored from one source to a destination. If port mirroring is configured unknowingly this could allow an attacker to observe network traffic of virtual machines.'
  desc  'rationale', ''
  desc  'check', "
    If distributed switches are not used, this is not applicable.

    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Configure >> Settings >> Port Mirroring.

    Review any configured \"Port Mirroring\" sessions.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDSwitch | select Name,@{N=\"Port Mirroring Sessions\";E={$_.ExtensionData.Config.VspanSession.Name}}

    If there are any unauthorized port mirroring sessions configured, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Configure >> Settings >> Port Mirroring.

    Select the unauthorized \"Port Mirroring\" session and click \"Remove\". Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000340'
  tag rid: 'SV-VCFA-9X-000340'
  tag stig_id: 'VCFA-9X-000340'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vcenter_portMirrorSessions = input('vcenter_portMirrorSessions')
  command = 'Get-VDSwitch | Select -ExpandProperty Name'
  vdswitches = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if vdswitches.blank?
    impact 0.0
    describe 'No distributed switches found to audit. This is not applicable.' do
      skip 'No distributed switches found to audit. This is not applicable.'
    end
  else
    vdswitches.each do |vds|
      command = "(Get-VDSwitch -Name \"#{vds}\").ExtensionData.Config.VspanSession | ConvertTo-Json -Depth 1 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      if result == 'null'
        describe "Port mirror sessions found on distributed switch: #{vds}" do
          subject { result }
          it { should cmp 'null' }
        end
      else
        resultjson = json(content: result)
        resultjson.each do |session|
          describe "Port mirroring session: #{session['Name']} on distributed switch: #{vds}" do
            subject { session['Name'] }
            it { should be_in vcenter_portMirrorSessions }
          end
        end
      end
    end
  end
end
