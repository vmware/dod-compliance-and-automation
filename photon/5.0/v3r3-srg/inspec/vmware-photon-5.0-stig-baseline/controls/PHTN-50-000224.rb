control 'PHTN-50-000224' do
  title 'The Photon operating system must not respond to IPv4 Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc  'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify ICMP echoes sent to a broadcast address are ignored:

    # /sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts

    Example result:

    net.ipv4.icmp_echo_ignore_broadcasts = 1

    If the \"net.ipv4.icmp_echo_ignore_broadcasts\" kernel parameter is not set to \"1\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/sysctl.d/zz-stig-hardening.conf

    Add or update the following line:

    net.ipv4.icmp_echo_ignore_broadcasts = 1

    At the command line, run the following command to load the new configuration:

    # /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

    Note: If the file zz-stig-hardening.conf does not exist it must be created.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000224'
  tag rid: 'SV-PHTN-50-000224'
  tag stig_id: 'PHTN-50-000224'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should cmp 1 }
  end
end
