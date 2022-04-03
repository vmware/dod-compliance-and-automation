control 'PHTN-67-000110' do
  title "The Photon operating system must use a reverse-path filter for IPv4
network traffic."
  desc  "Enabling reverse path filtering drops packets with source addresses
that should not have been able to be received on the interface they were
received on. It should not be used on systems that are routers for complicated
networks but is helpful for end hosts and routers serving small networks."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # /sbin/sysctl -a --pattern
\"net.ipv4.conf.(all|default|eth.*)\\.rp_filter\"

    Expected result:

    net.ipv4.conf.all.rp_filter = 1
    net.ipv4.conf.default.rp_filter = 1
    net.ipv4.conf.eth0.rp_filter = 1

    If the output does not match the expected result, this is a finding.

    Note: The number of \"ethx\" lines returned is dependent on the number of
interfaces. Every \"ethx\" entry must be set to \"1\".
  "
  desc 'fix', "
    Open /etc/sysctl.conf with a text editor.

    Add or update the following lines:

    net.ipv4.conf.all.rp_filter = 1
    net.ipv4.conf.default.rp_filter = 1
    net.ipv4.conf.eth0.rp_filter = 1

    Run the following command to load the new setting:

    # /sbin/sysctl --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239181'
  tag rid: 'SV-239181r816668_rule'
  tag stig_id: 'PHTN-67-000110'
  tag fix_id: 'F-42351r816667_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should eq 1 }
  end

  describe kernel_parameter('net.ipv4.conf.default.rp_filter') do
    its('value') { should eq 1 }
  end

  describe kernel_parameter('net.ipv4.conf.eth0.rp_filter') do
    its('value') { should eq 1 }
  end
end
