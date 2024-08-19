control 'NT0R-4X-000054' do
  title 'The NSX Tier-0 Gateway router must be configured to implement message authentication for all control plane protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information. This includes Border Gateway Protocol (BGP), Routing Information Protocol (RIP), Open Shortest Path First (OSPF), Enhanced Interior Gateway Routing Protocol (EIGRP), Intermediate System to Intermediate System (IS-IS) and Label Distribution Protocol (LDP).)
  desc 'check', 'If the Tier-0 Gateway is not using BGP or OSPF, this is Not Applicable.

Since the router does not reveal if a BGP password is configured, interview the router administrator to determine if a password is configured on BGP neighbors.

If BGP neighbors do not have a password configured, this is a finding.

To verify OSPF areas are using authentication, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

For every Tier-0 Gateway expand the "Tier-0 Gateway".

Expand "OSPF", click the number next to "Area Definition", and view the "Authentication" field for each area.

If OSPF area definitions do not have Password or MD5 set for authentication, this is a finding.'
  desc 'fix', 'To set authentication for BGP neighbors, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways, and expand the target Tier-0 gateway.

Expand BGP. Next to BGP Neighbors, click on the number present to open the dialog, then select "Edit" on the target BGP Neighbor.

Under Timers & Password, enter a password up to 20 characters, and then click "Save".

To set authentication for OSPF Area definitions, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways, and expand the target Tier-0 gateway.

Expand OSPF. Next to "Area Definition", click on the number present to open the dialog, and then select "Edit" on the target OSPF Area.

Change the Authentication drop-down to Password or MD5, enter a Key ID and/or Password, and then click "Save".'
  impact 0.7
  tag check_id: 'C-67203r977674_chk'
  tag severity: 'high'
  tag gid: 'V-263303'
  tag rid: 'SV-263303r979592_rule'
  tag stig_id: 'NT0R-4X-000054'
  tag gtitle: 'SRG-NET-000230-RTR-000001'
  tag fix_id: 'F-67111r977675_fix'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
