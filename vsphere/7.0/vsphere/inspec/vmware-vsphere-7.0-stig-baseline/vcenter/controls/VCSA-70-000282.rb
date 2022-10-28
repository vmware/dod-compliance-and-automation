control 'VCSA-70-000282' do
  title 'The vCenter Server must configure the vSAN Datastore name to a unique name.'
  desc  'A vSAN Datastore name by default is "vsanDatastore". If more than one vSAN cluster is present in vCenter, both datastores will have the same name by default, potentially leading to confusion and manually misplaced workloads.'
  desc  'rationale', ''
  desc  'check', "
    If no clusters are enabled for vSAN, this is Not Applicable.

    From the vSphere Client, go to Host and Clusters >> Select a vSAN Enabled Cluster >> Datastores.

    Review the datastores and identify any datastores with \"vSAN\" as the datastore type.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command(s):

    If($(Get-Cluster | where {$_.VsanEnabled} | Measure).Count -gt 0){
    Write-Host \"vSAN Enabled Cluster found\"
    Get-Cluster | where {$_.VsanEnabled} | Get-Datastore | where {$_.type -match \"vsan\"}
    }
    else{
    Write-Host \"vSAN is not enabled, this finding is not applicable\"
    }

    If vSAN is Enabled and a datastore is named \"vsanDatastore\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Host and Clusters >> Select a vSAN Enabled Cluster >> Datastores.

    Right-click on the datastore named \"vsanDatastore\" and select \"Rename\".

    Rename the datastore based on site-specific naming standards.

    Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command(s):

    If($(Get-Cluster | where {$_.VsanEnabled} | Measure).Count -gt 0){
    Write-Host \"vSAN Enabled Cluster found\"
    $Clusters = Get-Cluster | where {$_.VsanEnabled}
    Foreach ($clus in $clusters){
     $clus | Get-Datastore | where {$_.type -match \"vsan\"} | Set-Datastore -Name $(($clus.name) + \"_vSAN_Datastore\")
    }
    }
    else{
    Write-Host \"vSAN is not enabled, this finding is not applicable\"
    }
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000282'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-Cluster | Where-Object {$_.VsanEnabled} | Get-Datastore | Where-Object {$_.type -match "vsan"} | Select-Object -ExpandProperty Name'
  vsandatastores = powercli_command(command).stdout.strip.split("\n")

  if vsandatastores.empty?
    describe '' do
      skip 'No VSAN datastores found to check.'
    end
  else
    vsandatastores.each do |ds|
      describe '' do
        subject { ds }
        it { should_not cmp 'vsanDatastore' }
      end
    end
  end
end
