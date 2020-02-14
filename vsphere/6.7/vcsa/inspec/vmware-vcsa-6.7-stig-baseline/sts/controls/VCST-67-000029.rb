control "VCST-67-000029" do
  title "The Security Token Service must disable the shutdown port."
  desc  "An attacker has at least two reasons to stop a web server. The first
is to cause a DoS, and the second is to put in place changes the attacker made
to the web server configuration. If the Tomcat shutdown port feature is
enabled, a shutdown signal can be sent to the Security Token Service through
this port. To ensure availability, the shutdown port must be disabled."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000435-WSR-000147"
  tag gid: nil
  tag rid: "VCST-67-000029"
  tag stig_id: "VCST-67-000029"
  tag cci: "CCI-002385"
  tag nist: ["SC-5", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep 'base.shutdown.port'
/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Expected result:

base.shutdown.port=-1

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Open /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties in a
text editor.

Add or modify the following setting:

base.shutdown.port=-1"

  describe parse_config_file('/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties').params['base.shutdown.port'] do
    it { should eq '-1' }
  end

end