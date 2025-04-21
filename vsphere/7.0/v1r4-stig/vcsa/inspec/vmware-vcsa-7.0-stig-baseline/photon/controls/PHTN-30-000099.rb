control 'PHTN-30-000099' do
  title 'The Photon operating system must not respond to IPv4 Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'At the command line, run the following command:

# /sbin/sysctl -a --pattern ignore_broadcasts

Expected result:

net.ipv4.icmp_echo_ignore_broadcasts = 1

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, run the following commands:

# sed -i -e "/^net.ipv4.icmp_echo_ignore_broadcasts/d" /etc/sysctl.conf
# echo net.ipv4.icmp_echo_ignore_broadcasts=1>>/etc/sysctl.conf
# /sbin/sysctl --load'
  impact 0.5
  tag check_id: 'C-60243r887376_chk'
  tag severity: 'medium'
  tag gid: 'V-256568'
  tag rid: 'SV-256568r887378_rule'
  tag stig_id: 'PHTN-30-000099'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60186r887377_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should eq 1 }
  end
end
