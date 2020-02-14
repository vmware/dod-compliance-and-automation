control "PHTN-10-000109" do
  title "The Photon operating system must log IPv4 packets with impossible
addresses."
  desc  "The presence of \"martian\" packets (which have impossible addresses)
as well as spoofed packets, source-routed packets, and redirects could be a
sign of nefarious network activity. Logging these packets enables this activity
to be detected."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000109"
  tag stig_id: "PHTN-10-000109"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# /sbin/sysctl -a --pattern \"net.ipv4.conf.(all|default|eth.*).log_martians\"

Expected result:

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.eth0.log_martians = 1

If the output does not match the expected result, this is a finding.

Note: The number of ethx lines returned is dependant on the number of
interfaces. Every ethx entry must be set to 1."
  desc 'fix', "At the command line, execute the following command:

# for SETTING in $(/sbin/sysctl -aN --pattern
\"net.ipv4.conf.(all|default|eth.*).log_martians\"); do sed -i -e
\"/^${SETTING}/d\" /etc/sysctl.conf;echo $SETTING=1>>/etc/sysctl.conf; done"

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

