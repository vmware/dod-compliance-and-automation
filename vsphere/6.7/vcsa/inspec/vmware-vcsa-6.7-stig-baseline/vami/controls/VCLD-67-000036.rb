control "VCLD-67-000036" do
  title "VAMI must disable IP forwarding."
  desc  "IP forwarding permits Lighttpd to forward packets from one network
interface to another. The ability to forward packets between two networks is
only appropriate for systems acting as routers.  Lighttpd is not implemented as
a router.

    With the url.redirect configuration parameter, Lighttpd can be configured
to forward IPv4 packets.  This configuration parameter is prohibited, unless
Lighttpd is redirecting packets to localhost, 127.0.0.1."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000516-WSR-000174"
  tag gid: nil
  tag rid: "VCLD-67-000036"
  tag stig_id: "VCLD-67-000036"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

/opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf|grep -E 'url.redirect'

If any values are returned, this is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Delete all lines that are returned containing url.redirect entries."

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['url.redirect'] do
    it { should eq nil }
  end

end

