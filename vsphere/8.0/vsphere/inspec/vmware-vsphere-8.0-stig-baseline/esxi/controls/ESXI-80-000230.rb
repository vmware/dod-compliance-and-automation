control 'ESXI-80-000230' do
  title 'The ESXi host Secure Shell (SSH) daemon must disable port forwarding.'
  desc  'While enabling Transmission Control Protocol (TCP) tunnels is a valuable function of sshd, this feature is not appropriate for use on the ESXi hypervisor.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # /usr/lib/vmware/openssh/bin/sshd -T | grep allowtcpforwarding

    Expected result:

    allowtcpforwarding no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, add or update the following line in \"/etc/ssh/sshd_config\":

    AllowTcpForwarding no
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-ESXI-80-000230'
  tag rid: 'SV-ESXI-80-000230'
  tag stig_id: 'ESXI-80-000230'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
