control 'PHTN-40-000224' do
  title 'The Photon operating system must not respond to IPv4 Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'At the command line, run the following command to verify ICMP echoes sent to a broadcast address are ignored:

# /sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts

Example result:

net.ipv4.icmp_echo_ignore_broadcasts = 1

If the "net.ipv4.icmp_echo_ignore_broadcasts" kernel parameter is not set to "1", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/sysctl.d/zz-stig-hardening.conf

Add or update the following line:

net.ipv4.icmp_echo_ignore_broadcasts = 1

At the command line, run the following command to load the new configuration:

# /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

Note: If the file zz-stig-hardening.conf does not exist, it must be created.'
  impact 0.5
  tag check_id: 'C-62627r933720_chk'
  tag severity: 'medium'
  tag gid: 'V-258887'
  tag rid: 'SV-258887r933722_rule'
  tag stig_id: 'PHTN-40-000224'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62536r933721_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should cmp 1 }
  end
end
