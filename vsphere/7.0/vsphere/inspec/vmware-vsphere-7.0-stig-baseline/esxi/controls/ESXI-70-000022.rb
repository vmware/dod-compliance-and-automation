control 'ESXI-70-000022' do
  title 'The ESXi host Secure Shell (SSH) daemon must be configured to not allow gateway ports.'
  desc  'SSH Transmission Control Protocol (TCP) connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server. This function can provide convenience similar to a virtual private network (VPN) with the similar risk of providing a path to circumvent firewalls and network Access Control Lists (ACLs). Gateway ports allow remote forwarded ports to bind to nonloopback addresses on the server.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # /usr/lib/vmware/openssh/bin/sshd -T|grep gatewayports

    Expected result:

    gatewayports no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, add or correct the following line in \"/etc/ssh/sshd_config\":

    GatewayPorts no
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-256391'
  tag rid: 'SV-256391r885954_rule'
  tag stig_id: 'ESXI-70-000022'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
