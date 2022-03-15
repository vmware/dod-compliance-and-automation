control 'ESXI-67-000054' do
  title "The ESXi host must enable bidirectional CHAP authentication for iSCSI
traffic."
  desc  "When enabled, vSphere performs bidirectional authentication of both
the iSCSI target and host. There is a potential for a MiTM attack, when not
authenticating both the iSCSI target and host, in which an attacker might
impersonate either side of the connection to steal data. Bidirectional
authentication mitigates this risk."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi host and go to Configure >>
Storage >> Storage Adapters.

    Select the iSCSI adapter >> Properties >> Authentication method, view the
CHAP configuration, and verify CHAP is required for target and host
authentication.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-VMHostHba | Where {$_.Type -eq \"iscsi\"} | Select
AuthenticationProperties -ExpandProperty AuthenticationProperties

    If iSCSI is not used, this is not a finding.

    If iSCSI is used and CHAP is not set to \"required\" for both the target
and host, this is a finding.

    If iSCSI is used and unique CHAP secrets are not used for each host, this
is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the ESXi host and go to Configure >>
Storage >> Storage Adapters.

    Select the iSCSI adapter >> Properties >> Authentication and click the
\"Edit\" button.

    Set Authentication method to “Use bidirectional CHAP” and enter a unique
secret for each traffic flow direction.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-VMHostHba | Where {$_.Type -eq \"iscsi\"} | Set-VMHostHba
-ChapType Required -ChapName \"chapname\" -ChapPassword \"password\"
-MutualChapEnabled $true -MutualChapName \"mutualchapname\" -MutualChapPassword
\"mutualpassword\"
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239308'
  tag rid: 'SV-239308r674853_rule'
  tag stig_id: 'ESXI-67-000054'
  tag fix_id: 'F-42500r674852_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VMHostHba | Where {$_.Type -eq 'iscsi'}"
  iscsi_hbas = powercli_command(command).stdout

  if iscsi_hbas.empty?
    describe '' do
      skip 'There are no iSCSI HBAs present so this control is not applicable'
    end
  end

  unless iscsi_hbas.empty?
    command1 = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VMHostHba | Where {$_.Type -eq 'iscsi'} | Select-Object -ExpandProperty AuthenticationProperties | Select-Object -ExpandProperty MutualChapEnabled"
    command2 = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VMHostHba | Where {$_.Type -eq 'iscsi'} | Select-Object -ExpandProperty AuthenticationProperties | Select-Object -ExpandProperty ChapType"

    describe powercli_command(command1) do
      its('stdout.strip') { should cmp 'True' }
    end

    describe powercli_command(command2) do
      its('stdout.strip') { should cmp 'Required' }
    end

  end
end
