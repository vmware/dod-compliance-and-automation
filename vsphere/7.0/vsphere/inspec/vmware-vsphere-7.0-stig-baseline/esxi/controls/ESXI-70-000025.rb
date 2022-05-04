control 'ESXI-70-000025' do
  title 'The ESXi host SSH daemon must not permit tunnels.'
  desc  'OpenSSH has the ability to create network tunnels (layer 2 and layer 3) over an SSH connection. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network Access Control Lists (ACLs).'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # /usr/lib/vmware/openssh/bin/sshd -T|grep permittunnel

    Expected result:

    permittunnel no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, add or correct the following line in \"/etc/ssh/sshd_config\":

    PermitTunnel no
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000025'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
