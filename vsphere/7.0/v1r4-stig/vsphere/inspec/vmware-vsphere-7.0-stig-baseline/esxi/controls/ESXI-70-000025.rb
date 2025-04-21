control 'ESXI-70-000025' do
  title 'The ESXi host Secure Shell (SSH) daemon must not permit tunnels.'
  desc 'OpenSSH has the ability to create network tunnels (layer 2 and layer 3) over an SSH connection. This function can provide similar convenience to a virtual private network (VPN) with the similar risk of providing a path to circumvent firewalls and network Access Control Lists (ACLs).'
  desc 'check', 'From an ESXi shell, run the following command:

# /usr/lib/vmware/openssh/bin/sshd -T|grep permittunnel

Expected result:

permittunnel no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

PermitTunnel no'
  impact 0.5
  tag check_id: 'C-60068r885958_chk'
  tag severity: 'medium'
  tag gid: 'V-256393'
  tag rid: 'SV-256393r885960_rule'
  tag stig_id: 'ESXI-70-000025'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60011r885959_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
