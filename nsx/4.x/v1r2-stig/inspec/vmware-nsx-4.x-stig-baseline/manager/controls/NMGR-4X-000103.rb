control 'NMGR-4X-000103' do
  title 'The NSX Managers must be deployed on separate physical hosts.'
  desc 'SDN relies heavily on control messages between a controller and the forwarding devices for network convergence. The controller uses node and link state discovery information to calculate and determine optimum pathing within the SDN network infrastructure based on application, business, and security policies. Operating in the proactive flow instantiation mode, the SDN controller populates forwarding tables to the SDN-aware forwarding devices. At times, the SDN controller must function in reactive flow instantiation mode; that is, when a forwarding device receives a packet for a flow not found in its forwarding table, it must send it to the controller to receive forwarding instructions.

With total dependence on the SDN controller for determining forwarding decisions and path optimization within the SDN infrastructure for both proactive and reactive flow modes of operation, having a single point of failure is not acceptable. A controller failure with no failover backup leaves the network in an unmanaged state. Hence, it is imperative that the SDN controllers are deployed as clusters on separate physical hosts to guarantee high network availability.'
  desc 'check', 'This check must be performed in vCenter.

From the vSphere Client, go to Administration >> Hosts and Clusters >> Select the cluster where the NSX Managers are deployed >> Configure >> Configuration >> VM/Host Rules.

If the NSX Manager cluster does not have rules applied to it that separate the nodes onto different physical hosts, this is a finding.'
  desc 'fix', 'This fix must be performed in vCenter.

From the vSphere Client, go to Administration >> Hosts and Clusters >> Select the cluster where the NSX Managers are deployed >> Configure >> Configuration >> VM/Host Rules.

Click "Add" to create a new rule.

Provide a name and select "Separate Virtual Machines" under Type.

Add the three NSX Manager virtual machines to the list and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware NSX 4.x Manager NDM'
  tag check_id: 'C-69276r994298_chk'
  tag severity: 'medium'
  tag gid: 'V-265359'
  tag rid: 'SV-265359r994300_rule'
  tag stig_id: 'NMGR-4X-000103'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-69184r994299_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
