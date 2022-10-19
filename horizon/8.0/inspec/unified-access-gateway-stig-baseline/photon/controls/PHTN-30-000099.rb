control 'PHTN-30-000099' do
  title 'The Photon operating system must not respond to IPv4 Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc  'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # /sbin/sysctl -a --pattern ignore_broadcasts

    Expected result:

    net.ipv4.icmp_echo_ignore_broadcasts = 1

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command(s):

    # sed -i -e \"/^net.ipv4.icmp_echo_ignore_broadcasts/d\" /etc/sysctl.conf
    # echo net.ipv4.icmp_echo_ignore_broadcasts=1>>/etc/sysctl.conf
    # /sbin/sysctl --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000099'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should eq 1 }
  end
end
