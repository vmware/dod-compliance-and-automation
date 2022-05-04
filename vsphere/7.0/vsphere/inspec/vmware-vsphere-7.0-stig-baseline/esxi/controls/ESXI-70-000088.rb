control 'ESXI-70-000088' do
  title 'The ESXi host must configure a session timeout for the vSphere API.'
  desc  "
    The vSphere API (VIM) allows for remote, programmatic administration of the ESXi host. Authenticated API sessions are no different from a risk perspective than authenticated UI sessions and they need similar protections.

    One of these protections is a basic inactivity timeout, after which the session will be invalidated and reauthentication will be required by the application accessing the API. This is set to 30 seconds by default but can be disabled, thus leaving API sessions open indefinitely. The 30 second default must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"Config.HostAgent.vmacore.soap.sessionTimeout\" value and verify it is set to \"30\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout

    If the \"Config.HostAgent.vmacore.soap.sessionTimeout\" setting is not set to \"30\", this is a finding
  "
  desc  'fix', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"Config.HostAgent.vmacore.soap.sessionTimeout\" value and set it to \"30\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout | Set-AdvancedSetting -Value \"30\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000088'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '30' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
