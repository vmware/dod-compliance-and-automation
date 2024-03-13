control 'ESXI-70-000074' do
  title 'The ESXi host must exclusively enable Transport Layer Security (TLS) 1.2 for all endpoints.'
  desc 'TLS 1.0 and 1.1 are deprecated protocols with well-published shortcomings and vulnerabilities. TLS 1.2 should be enabled on all interfaces and SSLv3, TL 1.1, and 1.0 disabled, where supported.

Mandating TLS 1.2 may break third-party integrations and add-ons to vSphere. Test these integrations carefully after implementing TLS 1.2 and roll back where appropriate.

On interfaces where required functionality is broken with TLS 1.2, this finding is not applicable until such time as the third-party software supports TLS 1.2.

Modify TLS settings in the following order:
1. vCenter.
2. ESXi.

'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.ESXiVPsDisabledProtocols" value and verify it is set to the following:

tlsv1,tlsv1.1,sslv3

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols

If the "UserVars.ESXiVPsDisabledProtocols" setting is not set to "tlsv1,tlsv1.1,sslv3" or the setting does not exist, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.ESXiVPsDisabledProtocols" value and set it to the following:

tlsv1,tlsv1.1,sslv3

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Set-AdvancedSetting -Value "tlsv1,tlsv1.1,sslv3"

Reboot the host for changes to take effect.'
  impact 0.7
  tag check_id: 'C-60104r886066_chk'
  tag severity: 'high'
  tag gid: 'V-256429'
  tag rid: 'SV-256429r886068_rule'
  tag stig_id: 'ESXI-70-000074'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60047r886067_fix'
  tag satisfies: ['SRG-OS-000480-VMM-002000', 'SRG-OS-000425-VMM-001710']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'sslv3,tlsv1,tlsv1.1' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
