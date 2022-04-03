control 'PHTN-67-000111' do
  title "The Photon operating system must not perform multicast packet
forwarding."
  desc  "Routing protocol daemons are typically used on routers to exchange
network topology information with other routers. If this software is used when
not required, system network information may be unnecessarily transmitted
across the network."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # /sbin/sysctl -a --pattern
\"net.ipv[4|6].conf.(all|default|eth.*).mc_forwarding\"

    Expected result:

    net.ipv4.conf.all.mc_forwarding = 0
    net.ipv4.conf.default.mc_forwarding = 0
    net.ipv4.conf.eth0.mc_forwarding = 0
    net.ipv6.conf.all.mc_forwarding = 0
    net.ipv6.conf.default.mc_forwarding = 0
    net.ipv6.conf.eth0.mc_forwarding = 0

    If the output does not match the expected result, this is a finding.

    Note: The number of \"ethx\" lines returned is dependent on the number of
interfaces. Every \"ethx\" entry must be set to \"0\".
  "
  desc 'fix', "
    Open /etc/sysctl.conf with a text editor.

    Add or update the following lines:

    net.ipv4.conf.all.mc_forwarding = 0
    net.ipv4.conf.default.mc_forwarding = 0
    net.ipv4.conf.eth0.mc_forwarding = 0
    net.ipv6.conf.all.mc_forwarding = 0
    net.ipv6.conf.default.mc_forwarding = 0
    net.ipv6.conf.eth0.mc_forwarding = 0

    Run the following command to load the new setting:

    # /sbin/sysctl --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239182'
  tag rid: 'SV-239182r816670_rule'
  tag stig_id: 'PHTN-67-000111'
  tag fix_id: 'F-42352r816669_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.mc_forwarding') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.default.mc_forwarding') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.eth0.mc_forwarding') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.all.mc_forwarding') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.default.mc_forwarding') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.eth0.mc_forwarding') do
    its('value') { should eq 0 }
  end
end
