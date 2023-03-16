control 'ESXI-70-000082' do
  title 'The ESXi host Secure Shell (SSH) daemon must disable port forwarding.'
  desc  'While enabling Transmission Control Protocol (TCP) tunnels is a valuable function of sshd, this feature is not appropriate for use on the ESXi hypervisor.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # /usr/lib/vmware/openssh/bin/sshd -T|grep allowtcpforwarding

    Expected result:

    allowtcpforwarding no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, add or correct the following line in \"/etc/ssh/sshd_config\":

    AllowTcpForwarding no
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-256434'
  tag rid: 'SV-256434r886083_rule'
  tag stig_id: 'ESXI-70-000082'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
