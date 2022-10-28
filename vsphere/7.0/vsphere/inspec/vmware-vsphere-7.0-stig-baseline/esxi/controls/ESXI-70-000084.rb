control 'ESXI-70-000084' do
  title 'The ESXi host must enable audit logging.'
  desc  "
    ESXi offers both local and remote audit recordkeeping to meet the requirements of the NIAP Virtualization Protection Profile and Server Virtualization Extended Package. Local records are stored on any accessible local or VMFS path. Remote records are sent to the global syslog servers configured elsewhere.

    To operate in the NIAP validated state, ESXi must enable and properly configure this audit system. This system is disabled by default.

    Note: Audit records can be viewed locally via the \" /bin/auditLogReader\" utility over SSH or at the ESXi shell.
  "
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # esxcli system auditrecords get

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    $esxcli = Get-EsxCli -v2
    $esxcli.system.auditrecords.get.invoke()|Format-List

    Example result:

    Audit Record Storage Active: true
    Audit Record Storage Capacity: 100
    Audit Record Storage Directory: /scratch/auditLog
    Audit Remote Host Enabled: true

    Note: The \"Audit Record Storage Directory\" may differ from the default above but it must still be located on persistent storage.

    If audit record storage is not active and configured, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, run the following command(s):

    Optional: Set the audit log location to persistent storage. This is set to '/scratch/auditLog' by default and does not normally need to be changed.

    # esxcli system auditrecords local set --directory=\"/full/path/here\"

    Mandatory:

    # esxcli system auditrecords local set --size=100
    # esxcli system auditrecords local enable
    # esxcli system auditrecords remote enable
    # esxcli system syslog reload

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.auditrecords.local.set.CreateArgs()
    *Optional* $arguments.directory = \"/full/path/here\"
    $arguments.size=\"100\"
    $esxcli.system.auditrecords.local.set.Invoke($arguments)
    $esxcli.system.auditrecords.local.enable.Invoke()
    $esxcli.system.auditrecords.remote.enable.Invoke()

  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000084'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.auditrecords.get.invoke() | Select-Object -ExpandProperty AuditRecordStorageActive"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end

      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.auditrecords.get.invoke() | Select-Object -ExpandProperty AuditRecordStorageCapacity"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp >= '4' }
        its('stdout.strip') { should cmp <= '100' }
      end

      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.auditrecords.get.invoke() | Select-Object -ExpandProperty AuditRemoteHostEnabled"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
