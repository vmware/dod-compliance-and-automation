control 'ESXI-70-000022' do
  title "The ESXi host SSH daemon must be configured to not allow gateway
ports."
  desc  "SSH TCP connection forwarding provides a mechanism to establish TCP
connections proxied by the SSH server. This function can provide similar
convenience to a Virtual Private Network (VPN) with the similar risk of
providing a path to circumvent firewalls and network ACLs. Gateway ports allow
remote forwarded ports to bind to non-loopback addresses on the server."
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # /usr/lib/vmware/openssh/bin/sshd -T|grep gatewayports

    Expected result:

    gatewayports no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, add or correct the following line in
\"/etc/ssh/sshd_config\":

    GatewayPorts no
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000022'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
