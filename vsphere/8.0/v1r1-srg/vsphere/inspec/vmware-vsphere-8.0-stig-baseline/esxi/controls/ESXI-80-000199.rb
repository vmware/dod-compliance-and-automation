control 'ESXI-80-000199' do
  title 'The ESXi host must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic.'
  desc  "
    Virtual machines (VMs) might share virtual switches and VLANs with the IP-based storage configurations. IP-based storage includes vSAN, iSCSI, and NFS. This configuration might expose IP-based storage traffic to unauthorized VM users. IP-based storage frequently is not encrypted. It can be viewed by anyone with access to this network.

    To restrict unauthorized users from viewing the IP-based storage traffic, the IP-based storage network must be logically separated from any other traffic. Configuring the IP-based storage adaptors on separate VLANs or network segments from other VMkernels and VMs will limit unauthorized users from viewing the traffic.
  "
  desc  'rationale', ''
  desc  'check', "
    If IP-based storage is not used, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> Networking >> VMkernel adapters.

    Review each VMkernel adapter that is used for IP-based storage traffic and view the \"Enabled services\".

    Review the VLAN associated with each VMkernel that is used for IP-based storage traffic. Verify with the system administrator that they are dedicated for that purpose and are logically separated from other functions.

    If any services are enabled on an NFS or iSCSI IP-based storage VMkernel adapter, this is a finding.

    If any services are enabled on a vSAN VMkernel adapter other than vSAN, this is a finding.

    If any IP-based storage networks are not isolated from other traffic types, this is a finding.
  "
  desc 'fix', "
    Configuration of an IP-Based VMkernel will be unique to each environment.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> Networking >> VMkernel adapters.

    Select the VMkernel used for IP-based storage and click \"Edit\". On the \"Port\" properties tab, uncheck all services. Click \"OK\".

    Note: For VMkernels used for vSAN leave the vSAN service enabled and uncheck all others.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> Networking >> Virtual switches.

    Find the port group that is dedicated to IP-based storage and click the '...' button next to the name. Click \"Edit Settings\".

    On the \"Properties\" tab, change the \"VLAN ID\" to one dedicated for IP-based storage traffic. Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag gid: 'V-ESXI-80-000199'
  tag rid: 'SV-ESXI-80-000199'
  tag stig_id: 'ESXI-80-000199'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

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
      # Check for iSCSI HBAs
      commandiscsihbas = "Get-VMHost -Name #{vmhost} | Get-VMHostHba | Where {$_.Type -eq 'iscsi'}"
      iscsi_hbas = powercli_command(commandiscsihbas).stdout

      # Check for vSAN VMkernels
      commandvsanvmks = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.VsanTrafficEnabled -eq \"True\"} | Select-Object -ExpandProperty DeviceName"
      vsanvmks = powercli_command(commandvsanvmks).stdout

      # Check for NFS Datastores
      commandnfs = "Get-VMHost -Name #{vmhost} | Get-Datastore | Where {$_.Type -eq 'NFS'} | Select-Object -ExpandProperty Name"
      nfsds = powercli_command(commandnfs).stdout

      if iscsi_hbas.empty? && vsanvmks.empty? && nfsds.empty?
        describe '' do
          skip "The ESXi host #{vmhost} is not using IP-based storage, so this control is N/A."
        end
      else
        # Do any iSCSI VMKs have any services enabled?
        commandivmks = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.iscsi.networkportal.list.Invoke() | Select-Object -ExpandProperty Vmknic"
        ivmks = powercli_command(commandivmks).stdout
        ivmks.split.each do |ivmk|
          commandvsck = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -Name #{ivmk} | Where-Object {$_.ManagementTrafficEnabled -eq \"True\" -or $_.VsanTrafficEnabled -eq \"True\" -or $_.FaultToleranceLoggingEnabled -eq \"True\" -or $_.VMotionEnabled -eq \"True\" -or $_.VSphereReplicationEnabled -eq \"True\" -or $_.VSphereReplicationNFCEnabled -eq \"True\" -or $_.VSphereBackupNFCEnabled -eq \"True\"} | Select-Object -ExpandProperty DeviceName"
          describe powercli_command(commandvsck) do
            its('stdout.strip') { should be_empty }
          end
        end
        # Does the vSAN VMK have any other services enabled?
        vsanvmks.split.each do |vmk|
          commandvsck = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -Name #{vmk} | Where-Object {$_.ManagementTrafficEnabled -eq \"True\" -or $_.FaultToleranceLoggingEnabled -eq \"True\" -or $_.VMotionEnabled -eq \"True\" -or $_.VSphereReplicationEnabled -eq \"True\" -or $_.VSphereReplicationNFCEnabled -eq \"True\" -or $_.VSphereBackupNFCEnabled -eq \"True\"} | Select-Object -ExpandProperty DeviceName"
          describe powercli_command(commandvsck) do
            its('stdout.strip') { should be_empty }
          end
        end
        # Do any VMKs used for NFS storage have any services enabled?
        unless nfsds.empty?
          describe '' do
            skip "The ESXi host #{vmhost} has NFS datastores and requires manual validation."
          end
        end
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
