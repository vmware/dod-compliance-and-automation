control 'PHTN-40-000230' do
  title 'The Photon operating system must not perform multicast packet forwarding.'
  desc  'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify multicast packet forwarding is disabled:

    # /sbin/sysctl -a --pattern \"net.ipv[4|6].conf.(all|default).mc_forwarding\"

    Expected result:

    net.ipv4.conf.all.mc_forwarding = 0
    net.ipv4.conf.default.mc_forwarding = 0

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/sysctl.conf

    Add or update the following lines:

    net.ipv4.conf.all.mc_forwarding = 0
    net.ipv4.conf.default.mc_forwarding = 0

    At the command line, run the following command to load the new configuration:

    # /sbin/sysctl --load

    Note: If the file sysctl.conf doesn't exist it must be created.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-40-000230'
  tag rid: 'SV-PHTN-40-000230'
  tag stig_id: 'PHTN-40-000230'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.mc_forwarding') do
    its('value') { should cmp 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.mc_forwarding') do
    its('value') { should cmp 0 }
  end
end
