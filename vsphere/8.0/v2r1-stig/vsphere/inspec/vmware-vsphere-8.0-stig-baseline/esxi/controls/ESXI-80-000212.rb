control 'ESXI-80-000212' do
  title 'The ESXi host must disable Simple Network Management Protocol (SNMP) v1 and v2c.'
  desc 'If SNMP is not being used, it must remain disabled. If it is being used, the proper trap destination must be configured. If SNMP is not properly configured, monitoring information can be sent to a malicious host that can use this information to plan an attack.'
  desc 'check', 'From an ESXi shell, run the following command:

# esxcli system snmp get

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHostSnmp | Select *

If SNMP is not in use and is enabled, this is a finding.

If SNMP is enabled and is not using v3 targets with authentication, this is a finding.

Note: SNMP v3 targets can only be viewed and configured via the "esxcli" command.'
  desc 'fix', 'To disable SNMP from an ESXi shell, run the following command:

# esxcli system snmp set -e no

or

From a PowerCLI command prompt while connected to the ESXi Host:

Get-VMHostSnmp | Set-VMHostSnmp -Enabled $false'
  impact 0.5
  tag check_id: 'C-62507r933360_chk'
  tag severity: 'medium'
  tag gid: 'V-258767'
  tag rid: 'SV-258767r959010_rule'
  tag stig_id: 'ESXI-80-000212'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62416r933361_fix'
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
    if "#{input('snmpEnabled')}" == 'false'
      vmhosts.each do |vmhost|
        command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.snmp.get.Invoke() | Select-Object -ExpandProperty enable"
        describe powercli_command(command) do
          its('stdout.strip') { should cmp 'false' }
        end
      end
    else
      describe 'SNMP Enabled' do
        skip 'Manually verify SNMP v3 is configured correctly and v2 is not used.'
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
