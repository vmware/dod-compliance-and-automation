control 'PHTN-50-000228' do
  title 'The Photon operating system must log IPv4 packets with impossible addresses.'
  desc  'The presence of "martian" packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify martian packets are logged:

    # /sbin/sysctl -a --pattern \"net.ipv4.conf.(all|default).log_martians\"

    Expected result:

    net.ipv4.conf.all.log_martians = 1
    net.ipv4.conf.default.log_martians = 1

    If the \"log_martians\" kernel parameters are not set to \"1\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/sysctl.d/zz-stig-hardening.conf

    Add or update the following lines:

    net.ipv4.conf.all.log_martians = 1
    net.ipv4.conf.default.log_martians = 1

    At the command line, run the following command to load the new configuration:

    # /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

    Note: If the file zz-stig-hardening.conf does not exist it must be created.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000228'
  tag rid: 'SV-PHTN-50-000228'
  tag stig_id: 'PHTN-50-000228'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should cmp 1 }
  end
  describe kernel_parameter('net.ipv4.conf.default.log_martians') do
    its('value') { should cmp 1 }
  end
end
