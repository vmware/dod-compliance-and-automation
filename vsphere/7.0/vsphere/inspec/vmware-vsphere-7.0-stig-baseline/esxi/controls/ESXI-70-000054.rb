control 'ESXI-70-000054' do
  title 'The ESXi host must enable bidirectional Challenge-Handshake Authentication Protocol (CHAP) authentication for Internet Small Computer Systems Interface (iSCSI) traffic.'
  desc  'When enabled, vSphere performs bidirectional authentication of both the iSCSI target and host. When not authenticating both the iSCSI target and host, there is potential for a man-in-the-middle attack, in which an attacker might impersonate either side of the connection to steal data. Bidirectional authentication mitigates this risk.'
  desc  'rationale', ''
  desc  'check', "
    If iSCSI is not used, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> Storage >> Storage Adapters.

    Select the iSCSI adapter >> Properties >> Authentication >> Method.

    View the CHAP configuration and verify CHAP is required for target and host authentication.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-VMHostHba | Where {$_.Type -eq \"iscsi\"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties

    If iSCSI is used and CHAP is not set to \"required\" for both the target and host, this is a finding.

    If iSCSI is used and unique CHAP secrets are not used for each host, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> Storage >> Storage Adapters.

    Select the iSCSI adapter >> Properties >> Authentication.

    Click \"Edit...\". Set \"Authentication Method\" to \"Use bidirectional CHAP\" and enter a unique secret for each traffic flow direction.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-VMHostHba | Where {$_.Type -eq \"iscsi\"} | Set-VMHostHba -ChapType Required -ChapName \"chapname\" -ChapPassword \"password\" -MutualChapEnabled $true -MutualChapName \"mutualchapname\" -MutualChapPassword \"mutualpassword\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-256415'
  tag rid: 'SV-256415r886026_rule'
  tag stig_id: 'ESXI-70-000054'
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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostHba | Where {$_.Type -eq 'iscsi'}"
      iscsi_hbas = powercli_command(command).stdout

      if iscsi_hbas.empty?
        impact 0.0
        describe 'There are no iSCSI HBAs present so this control is not applicable' do
          skip 'There are no iSCSI HBAs present so this control is not applicable'
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
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
