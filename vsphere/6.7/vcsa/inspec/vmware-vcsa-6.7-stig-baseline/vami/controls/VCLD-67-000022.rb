control "VCLD-67-000022" do
  title "VAMI must prevent hosted applications from exhausting system
resources."
  desc  "When it comes to DoS attacks, most of the attention is paid to
ensuring that systems and applications are not victims of these attacks. While
it is true that those accountable for systems want to ensure they are not
affected by a DoS attack, they also need to ensure their systems and
applications are not used to launch such an attack against others. To that
extent, a variety of technologies exist to limit, or in some cases, eliminate
the effects of DoS attacks. Limiting system resources that are allocated to any
user to a bare minimum may also reduce the ability of users to launch some DoS
attacks. Applications and application developers must take the steps needed to
ensure users cannot use these applications to launch DoS attacks against other
systems and networks.

    An example would be preventing Lighttpd from keeping idle connections open
for too long."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000141-WSR-000086"
  tag gid: nil
  tag rid: "VCLD-67-000022"
  tag stig_id: "VCLD-67-000022"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

grep '^server.max-keep-alive-idle' /opt/vmware/etc/lighttpd/lighttpd.conf

If the \"server.max-keep-alive-idle\" is not set to \"30\", this is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf file.

Configure the lighttpd.conf file with the following:

server.max-keep-alive-idle = 30"

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['server.max-keep-alive-idle'] do
    it { should eq '30' }
  end

end

