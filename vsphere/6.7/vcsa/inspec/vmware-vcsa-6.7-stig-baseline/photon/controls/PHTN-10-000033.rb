control "PHTN-10-000033" do
  title "The Photon operating system must disable the loading of unnecessary
kernel modules."
  desc  "To support the requirements and principles of least functionality, the
operating system must provide only essential capabilities and limit the use of
modules, protocols, and/or services to only those required for the proper
functioning of the product."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000096-GPOS-00050"
  tag gid: nil
  tag rid: "PHTN-10-000033"
  tag stig_id: "PHTN-10-000033"
  tag cci: "CCI-000382"
  tag nist: ["CM-7 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# modprobe --showconfig | grep \"^install\" | grep \"/bin\"

Expected result:

install sctp /bin/false
install dccp /bin/false
install dccp_ipv4 /bin/false
install dccp_ipv6 /bin/false
install ipx /bin/false
install appletalk /bin/false
install decnet /bin/false
install rds /bin/false
install tipc /bin/false
install bluetooth /bin/false
install usb-storage /bin/false
install ieee1394 /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false

If the output does not match the expected result, this is a finding."
  desc 'fix', "Open  /etc/modprobe.d/modprobe.conf with a text editor and set the
contents as follows:

install sctp /bin/false
install dccp /bin/false
install dccp_ipv4 /bin/false
install dccp_ipv6 /bin/false
install ipx /bin/false
install appletalk /bin/false
install decnet /bin/false
install rds /bin/false
install tipc /bin/false
install bluetooth /bin/false
install usb-storage /bin/false
install ieee1394 /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
"

  describe command('modprobe --showconfig | grep "^install sctp " | grep "/bin"') do
    its('stdout.strip.strip') {should eq "install sctp /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install dccp " | grep "/bin"') do
    its('stdout.strip') {should eq "install dccp /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install dccp_ipv4" | grep "/bin"') do
    its('stdout.strip') {should eq "install dccp_ipv4 /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install dccp_ipv6" | grep "/bin"') do
    its('stdout.strip') {should eq "install dccp_ipv6 /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install ipx" | grep "/bin"') do
    its('stdout.strip') {should eq "install ipx /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install appletalk" | grep "/bin"') do
    its('stdout.strip') {should eq "install appletalk /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install decnet" | grep "/bin"') do
    its('stdout.strip') {should eq "install decnet /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install rds" | grep "/bin"') do
    its('stdout.strip') {should eq "install rds /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install tipc" | grep "/bin"') do
    its('stdout.strip') {should eq "install tipc /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install bluetooth" | grep "/bin"') do
    its('stdout.strip') {should eq "install bluetooth /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install usb_storage" | grep "/bin"') do
    its('stdout.strip') {should eq "install usb_storage /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install ieee1394" | grep "/bin"') do
    its('stdout.strip') {should eq "install ieee1394 /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install cramfs" | grep "/bin"') do
    its('stdout.strip') {should eq "install cramfs /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install freevxfs" | grep "/bin"') do
    its('stdout.strip') {should eq "install freevxfs /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install jffs2" | grep "/bin"') do
    its('stdout.strip') {should eq "install jffs2 /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install hfs " | grep "/bin"') do
    its('stdout.strip') {should eq "install hfs /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install hfsplus" | grep "/bin"') do
    its('stdout.strip') {should eq "install hfsplus /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install squashfs" | grep "/bin"') do
    its('stdout.strip') {should eq "install squashfs /bin/false"}
  end

  describe command('modprobe --showconfig | grep "^install udf" | grep "/bin"') do
    its('stdout.strip') {should eq "install udf /bin/false"}
  end

end

