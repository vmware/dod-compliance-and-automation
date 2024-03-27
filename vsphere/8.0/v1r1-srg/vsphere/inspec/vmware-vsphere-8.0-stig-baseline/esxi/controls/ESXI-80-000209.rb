control 'ESXI-80-000209' do
  title 'The ESXi host Secure Shell (SSH) daemon must not permit tunnels.'
  desc  'OpenSSH has the ability to create network tunnels (layer 2 and layer 3) over an SSH connection. This function can provide similar convenience to a virtual private network (VPN) with the similar risk of providing a path to circumvent firewalls and network Access Control Lists (ACLs).'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # /usr/lib/vmware/openssh/bin/sshd -T | grep permittunnel

    Expected result:

    permittunnel no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, add or update the following line in \"/etc/ssh/sshd_config\":

    PermitTunnel no
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-ESXI-80-000209'
  tag rid: 'SV-ESXI-80-000209'
  tag stig_id: 'ESXI-80-000209'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
