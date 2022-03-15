control 'PHTN-67-000109' do
  title "The Photon operating system must log IPv4 packets with impossible
addresses."
  desc  "The presence of \"martian\" packets (which have impossible addresses)
as well as spoofed packets, source-routed packets, and redirects could be a
sign of nefarious network activity. Logging these packets enables this activity
to be detected."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # /sbin/sysctl -a --pattern
\"net.ipv4.conf.(all|default|eth.*).log_martians\"

    Expected result:

    net.ipv4.conf.all.log_martians = 1
    net.ipv4.conf.default.log_martians = 1
    net.ipv4.conf.eth0.log_martians = 1

    If the output does not match the expected result, this is a finding.

    Note: The number of \"ethx\" lines returned is dependent on the number of
interfaces. Every \"ethx\" entry must be set to \"1\".
  "
  desc 'fix', "
    Open /etc/sysctl.conf with a text editor.

    Add or update the following lines:

    net.ipv4.conf.all.log_martians = 1
    net.ipv4.conf.default.log_martians = 1
    net.ipv4.conf.eth0.log_martians = 1

    Run the following command to load the new setting:

    # /sbin/sysctl --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239180'
  tag rid: 'SV-239180r816666_rule'
  tag stig_id: 'PHTN-67-000109'
  tag fix_id: 'F-42350r816665_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should eq 1 }
  end

  describe kernel_parameter('net.ipv4.conf.default.log_martians') do
    its('value') { should eq 1 }
  end

  describe kernel_parameter('net.ipv4.conf.eth0.log_martians') do
    its('value') { should eq 1 }
  end
end
