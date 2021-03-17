# encoding: UTF-8

control 'VCLD-70-000014' do
  title "VAMI must have resource mappings set to disable the serving of certain
file types."
  desc  "Resource mapping is the process of tying a particular file type to a
process in the web server that can serve that type of file to a requesting
client and to identify which file types are not to be delivered to a client.

    By not specifying which files can and which files cannot be served to a
user, VAMI could potentially deliver sensitive files.

  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep \"url.access-deny\"|sed
's: ::g'

    Expected result:

    url.access-deny=(\"~\",\".inc\")
    url.access-deny=(\"\")

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

    Add or reconfigure the following value:

    url.access-deny=(\"~\",\".inc\")
    url.access-deny=(\"\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000014'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']



end

