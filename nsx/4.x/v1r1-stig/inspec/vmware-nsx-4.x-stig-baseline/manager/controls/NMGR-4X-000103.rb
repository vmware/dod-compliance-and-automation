control 'NMGR-4X-000103' do
  title 'The NSX Managers must be deployed on separate physical hosts.'
  desc 'SDN relies heavily on control messages between a controller and the forwarding devices for network convergence. The controller uses node and link state discovery information to calculate and determine optimum pathing within the SDN network infrastructure based on application, business, and security policies. Operating in the proactive flow instantiation mode, the SDN controller populates forwarding tables to the SDN-aware forwarding devices. At times, the SDN controller must function in reactive flow instantiation mode; that is, when a forwarding device receives a packet for a flow not found in its forwarding table, it must send it to the controller to receive forwarding instructions.

With total dependence on the SDN controller for determining forwarding decisions and path optimization within the SDN infrastructure for both proactive and reactive flow modes of operation, having a single point of failure is not acceptable. A controller failure with no failover backup leaves the network in an unmanaged state. Hence, it is imperative that the SDN controllers are deployed as clusters on separate physical hosts to guarantee high network availability.'
  desc 'check', '
    This check must be performed in vCenter.

    From the vSphere Client, go to Administration >> Hosts and Clusters >> Select the cluster where the NSX Managers are deployed >> Configure >> Configuration >> VM/Host Rules.

    If the NSX Manager cluster does not have rules applied to it that separate the nodes onto different physical hosts, this is a finding.
  '
  desc 'fix', '
    This fix must be performed in vCenter.

    From the vSphere Client, go to Administration >> Hosts and Clusters >> Select the cluster where the NSX Managers are deployed >> Configure >> Configuration >> VM/Host Rules.

    Click "Add" to create a new rule.

    Provide a name and select "Separate Virtual Machines" under Type.

    Add the three NSX Manager virtual machines to the list and click "OK".
  '
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag gid: 'V-263229'
  tag rid: 'SV-263229r977454_rule'
  tag stig_id: 'NMGR-4X-000103'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
