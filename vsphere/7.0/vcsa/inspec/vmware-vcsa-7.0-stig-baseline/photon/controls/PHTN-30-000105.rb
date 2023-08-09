control 'PHTN-30-000105' do
  title 'The Photon operating system must not perform multicast packet forwarding.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', 'At the command line, run the following command:

# /sbin/sysctl -a --pattern "net.ipv[4|6].conf.(all|default|eth.*).mc_forwarding"

Expected result:

net.ipv4.conf.all.mc_forwarding = 0
net.ipv4.conf.default.mc_forwarding = 0
net.ipv4.conf.eth0.mc_forwarding = 0
net.ipv6.conf.all.mc_forwarding = 0
net.ipv6.conf.default.mc_forwarding = 0
net.ipv6.conf.eth0.mc_forwarding = 0

If the output does not match the expected result, this is a finding.

Note: The number of "ethx" lines returned is dependent on the number of interfaces. Every "ethx" entry must be set to "0".'
  desc 'fix', 'At the command line, run the following command:

# for SETTING in $(/sbin/sysctl -aN --pattern "net.ipv[4|6].conf.(all|default|eth.*).mc_forwarding"); do sed -i -e "/^${SETTING}/d" /etc/sysctl.conf;echo $SETTING=0>>/etc/sysctl.conf; done
# /sbin/sysctl --load'
  impact 0.5
  tag check_id: 'C-60249r887394_chk'
  tag severity: 'medium'
  tag gid: 'V-256574'
  tag rid: 'SV-256574r887396_rule'
  tag stig_id: 'PHTN-30-000105'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60192r887395_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.mc_forwarding') do
    its('value') { should cmp 0 }
  end

  describe kernel_parameter('net.ipv4.conf.default.mc_forwarding') do
    its('value') { should cmp 0 }
  end

  describe kernel_parameter('net.ipv4.conf.eth0.mc_forwarding') do
    its('value') { should cmp 0 }
  end

  describe.one do
    describe kernel_parameter('net.ipv6.conf.all.mc_forwarding') do
      its('value') { should cmp 0 }
    end
    describe kernel_parameter('net.ipv6.conf.all.mc_forwarding') do
      its('value') { should be nil }
    end
  end

  describe.one do
    describe kernel_parameter('net.ipv6.conf.default.mc_forwarding') do
      its('value') { should cmp 0 }
    end
    describe kernel_parameter('net.ipv6.conf.default.mc_forwarding') do
      its('value') { should be nil }
    end
  end

  describe.one do
    describe kernel_parameter('net.ipv6.conf.eth0.mc_forwarding') do
      its('value') { should cmp 0 }
    end
    describe kernel_parameter('net.ipv6.conf.eth0.mc_forwarding') do
      its('value') { should be nil }
    end
  end
end
