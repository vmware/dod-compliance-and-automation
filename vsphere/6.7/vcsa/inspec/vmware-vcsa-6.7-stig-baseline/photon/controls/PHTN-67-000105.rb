control 'PHTN-67-000105' do
  title "The Photon operating system must not respond to IPv4 Internet Control
Message Protocol (ICMP) echoes sent to a broadcast address."
  desc  "Responding to broadcast (ICMP) echoes facilitates network mapping and
provides a vector for amplification attacks."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # /sbin/sysctl -a --pattern ignore_broadcasts

    Expected result:

    net.ipv4.icmp_echo_ignore_broadcasts = 1

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/sysctl.conf with a text editor.

    Add or update the following line:

    net.ipv4.icmp_echo_ignore_broadcasts=1

    Run the following command to load the new setting:

    # /sbin/sysctl --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239176'
  tag rid: 'SV-239176r816658_rule'
  tag stig_id: 'PHTN-67-000105'
  tag fix_id: 'F-42346r816657_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should eq 1 }
  end
end
