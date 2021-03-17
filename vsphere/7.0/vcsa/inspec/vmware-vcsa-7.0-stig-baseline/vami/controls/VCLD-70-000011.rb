# encoding: UTF-8

control 'VCLD-70-000011' do
  title "VAMI must have Multipurpose Internet Mail Extensions (MIME) that
invoke OS shell programs disabled."
  desc  "Controlling what a user of a hosted application can access is part of
the security posture of the web server. Any time a user can access more
functionality than is needed for the operation of the hosted application poses
a security issue. A user with too much access can view information that is not
needed for the user's job role, or the user could use the function in an
unintentional manner.

    A MIME tells the web server what type of program various file types and
extensions are and what external utilities or programs are needed to execute
the file type. There is no reason for VAMI to have MIME types configured for
shell scripts.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk
'/mimetype\\.assign/,/\\)/'|grep -E \"\\.sh|\\.csh\"

    If the command returns any value, this is a finding.
  "
  desc  'fix', "
    Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

    Remove any lines that reference \".sh\" or \".csh\" from the
mimetype.assign section.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000011'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']

  describe command("/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk '/mimetype\.assign/,/\)/'|grep -E \"\\.sh|\\.csh\"").stdout do
    it { should eq "" }
  end

end

