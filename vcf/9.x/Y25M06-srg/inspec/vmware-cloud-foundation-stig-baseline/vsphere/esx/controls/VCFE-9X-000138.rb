control 'VCFE-9X-000138' do
  title 'The ESX host must enable bidirectional Challenge-Handshake Authentication Protocol (CHAP) authentication for Internet Small Computer Systems Interface (iSCSI) traffic.'
  desc  'When enabled, vSphere performs bidirectional authentication of both the iSCSI target and host. When not authenticating both the iSCSI target and host, there is potential for a man-in-the-middle attack, in which an attacker might impersonate either side of the connection to steal data. Bidirectional authentication mitigates this risk.'
  desc  'rationale', ''
  desc  'check', "
    If iSCSI is not used, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> Storage >> Storage Adapters.

    Select the iSCSI adapter >> Properties >> Authentication >> Method.

    View the CHAP configuration and verify CHAP is required for target and host authentication.

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-VMHostHba | Where {$_.Type -eq \"iscsi\"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties

    If iSCSI is used and CHAP is not set to \"required\" for both the target and host, this is a finding.

    If iSCSI is used and unique CHAP secrets are not used for each host, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> Storage >> Storage Adapters.

    Select the iSCSI adapter >> Properties >> Authentication.

    Click \"Edit...\". Set \"Authentication Method\" to \"Use bidirectional CHAP\" and enter a unique secret for each traffic flow direction.

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-VMHostHba | Where {$_.Type -eq \"iscsi\"} | Set-VMHostHba -ChapType Required -ChapName \"chapname\" -ChapPassword \"password\" -MutualChapEnabled $true -MutualChapName \"mutualchapname\" -MutualChapPassword \"mutualpassword\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000379-VMM-001550'
  tag gid: 'V-VCFE-9X-000138'
  tag rid: 'SV-VCFE-9X-000138'
  tag stig_id: 'VCFE-9X-000138'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']

  vmhostName = input('esx_vmhostName')
  cluster = input('esx_cluster')
  allhosts = input('esx_allHosts')
  vmhosts = []

  unless vmhostName.blank?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless cluster.blank?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if vmhosts.blank?
    describe 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.' do
      skip 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.'
    end
  else
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostHba | Where {$_.Type -eq 'iscsi'}"
      iscsi_hbas = powercli_command(command).stdout

      if iscsi_hbas.blank?
        impact 0.0
        describe 'There are no iSCSI HBAs present so this control is Not Applicable' do
          skip 'There are no iSCSI HBAs present so this control is Not Applicable'
        end
      else
        command1 = "Get-VMHost -Name #{vmhost} | Get-VMHostHba | Where {$_.Type -eq 'iscsi'} | Select-Object -ExpandProperty AuthenticationProperties | Select-Object -ExpandProperty MutualChapEnabled"
        command2 = "Get-VMHost -Name #{vmhost} | Get-VMHostHba | Where {$_.Type -eq 'iscsi'} | Select-Object -ExpandProperty AuthenticationProperties | Select-Object -ExpandProperty ChapType"
        describe powercli_command(command1) do
          its('stdout.strip') { should cmp 'True' }
        end
        describe powercli_command(command2) do
          its('stdout.strip') { should cmp 'Required' }
        end
      end
    end
  end
end
