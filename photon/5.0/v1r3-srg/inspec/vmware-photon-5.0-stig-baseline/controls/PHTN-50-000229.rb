control 'PHTN-50-000229' do
  title 'The Photon operating system must use a reverse-path filter for IPv4 network traffic.'
  desc  'Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems that are routers for complicated networks but is helpful for end hosts and routers serving small networks.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify IPv4 traffic is using a reverse path filter:

    # /sbin/sysctl -a --pattern \"net.ipv4.conf.(all|default).rp_filter\"

    Expected result:

    net.ipv4.conf.all.rp_filter = 1
    net.ipv4.conf.default.rp_filter = 1

    If the \"rp_filter\" kernel parameters are not set to \"1\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/sysctl.d/zz-stig-hardening.conf

    Add or update the following lines:

    net.ipv4.conf.all.rp_filter = 1
    net.ipv4.conf.default.rp_filter = 1

    At the command line, run the following command to load the new configuration:

    # /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

    Note: If the file zz-stig-hardening.conf does not exist it must be created.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000229'
  tag rid: 'SV-PHTN-50-000229'
  tag stig_id: 'PHTN-50-000229'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should cmp 1 }
  end
  describe kernel_parameter('net.ipv4.conf.default.rp_filter') do
    its('value') { should cmp 1 }
  end
end
