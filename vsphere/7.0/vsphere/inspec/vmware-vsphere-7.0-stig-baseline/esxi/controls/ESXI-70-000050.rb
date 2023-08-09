control 'ESXI-70-000050' do
  title 'The ESXi host must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic.'
  desc 'Virtual machines (VMs) might share virtual switches and VLANs with the IP-based storage configurations. IP-based storage includes vSAN, iSCSI, and NFS. This configuration might expose IP-based storage traffic to unauthorized VM users. IP-based storage frequently is not encrypted. It can be viewed by anyone with access to this network.

To restrict unauthorized users from viewing the IP-based storage traffic, the IP-based storage network must be logically separated from any other traffic. Configuring the IP-based storage adaptors on separate VLANs or network segments from other VMkernels and VMs will limit unauthorized users from viewing the traffic.'
  desc 'check', 'If IP-based storage is not used, this is not applicable.

From the vSphere Client, select the ESXi host and go to Configure >> Networking >> VMkernel adapters.

Select each IP-based storage VMkernel adapter and view the enabled services.

If any services are enabled on an NFS or iSCSI IP-based storage VMkernel adapter, this is a finding.

If any services are enabled on a vSAN VMkernel adapter other than vSAN, this is a finding.

From the vSphere Client, select the ESXi host and go to Configure >> Networking >> VMkernel adapters.

Review the VLANs associated with any IP-based storage VMkernels and verify they are dedicated for that purpose and are logically separated from other functions.

If any IP-based storage networks are not isolated from other traffic types, this is a finding.'
  desc 'fix', 'Configuration of an IP-based VMkernel will be unique to each environment.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> VMkernel adapters.

Select the VMkernel used for IP-based storage and click "Edit...". On the "Port" properties tab, uncheck all services. Click "OK".

Note: For VMkernels used for vSAN, leave the vSAN service enabled and uncheck all others.

From the vSphere Client, go to Hosts and Clusters >> select the ESXi Host >> Configure >> Networking >> Virtual switches.

Find the port group that is dedicated to IP-based storage and click the "..." button next to the name. Click "Edit Settings".

On the "Properties" tab, change the "VLAN ID" to one dedicated for IP-based storage traffic. Click "OK".'
  impact 0.5
  tag check_id: 'C-60088r886018_chk'
  tag severity: 'medium'
  tag gid: 'V-256413'
  tag rid: 'SV-256413r886020_rule'
  tag stig_id: 'ESXI-70-000050'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-60031r886019_fix'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
