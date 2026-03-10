control 'UBTU-22-251030' do
  title 'Ubuntu 22.04 LTS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Check the firewall configuration for any unnecessary or prohibited functions, ports, protocols, and/or services by using the following command:

     $ sudo ufw show raw
     Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
          pkts      bytes target     prot opt in     out     source               destination

     Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
         pkts      bytes target     prot opt in     out     source               destination

     Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
         pkts      bytes target     prot opt in     out     source               destination

Ask the system administrator for the site or program PPSM CLSA. Verify the services allowed by the firewall match the PPSM CLSA.

If there are any additional ports, protocols, or services that are not included in the PPSM CLSA, this is a finding.

If there are any ports, protocols, or services that are prohibited by the PPSM CAL, this is a finding.'
  desc 'fix', 'Add all ports, protocols, or services allowed by the PPSM CLSA by using the following command:

     $ sudo ufw allow <direction> <port/protocol/service>

Where the direction is "in" or "out" and the port is the one corresponding to the protocol or service allowed.

To deny access to ports, protocols, or services, use:

     $ sudo ufw deny <direction> <port/protocol/service>'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64247r953365_chk'
  tag severity: 'medium'
  tag gid: 'V-260518'
  tag rid: 'SV-260518r958480_rule'
  tag stig_id: 'UBTU-22-251030'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-64155r953366_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  describe 'Status listings for any allowed services, ports, or applications must be documented with the organization' do
    skip 'Status listings checks must be preformed manually'
  end
end
