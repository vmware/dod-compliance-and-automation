# encoding: UTF-8

control 'VCLD-70-000012' do
  title "VAMI must explicitly disable Multipurpose Internet Mail Extensions
(MIME) mime mappings based on \"Content-Type\"."
  desc  "Controlling what a user of a hosted application can access is part of
the security posture of the web server. Any time a user can access more
functionality than is needed for the operation of the hosted application poses
a security issue. A user with too much access can view information that is not
needed for the user's job role, or the user could use the function in an
unintentional manner.

    A MIME tells the web server what type of program various file types and
extensions are and what external utilities or programs are needed to execute
the file type. A limited number of MIME types must be configured manually and
automatic mapping must be disabled.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep
\"mimetype.use-xattr\"|sed 's: ::g'

    Expected result:

    mimetype.use-xattr=\"disable\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /opt/vmware/etc/lighttpd/lighttpd.conf

    Add or reconfigure the following value:

    mimetype.use-xattr        = \"disable\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000012'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe parse_config(runtime).params['mimetype.use-xattr'] do
    it { should cmp "#{input('mimetypeUseXattr')}" }
  end

end

