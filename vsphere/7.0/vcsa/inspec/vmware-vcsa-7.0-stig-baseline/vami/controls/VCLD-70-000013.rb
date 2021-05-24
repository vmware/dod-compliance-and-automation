# encoding: UTF-8

control 'VCLD-70-000013' do
  title 'VAMI must remove all mappings to unused scripts.'
  desc  "Scripts allow server-side processing on behalf of the hosted
application user or as processes needed in the implementation of hosted
applications. Removing scripts not needed for application operation or deemed
vulnerable helps to secure the web server. To assure scripts are not added to
the web server and run maliciously, those script mappings that are not needed
or used by the web server for hosted application operation must be removed."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk
'/cgi\\.assign/,/\\)/'|sed -e 's/^[ ]*//'

    Expected result:

    cgi.assign=(
    \".pl\"=>\"/usr/bin/perl\",
    \".cgi\"=>\"/usr/bin/perl\",
    \".rb\"=>\"/usr/bin/ruby\",
    \".erb\"=>\"/usr/bin/eruby\",
    \".py\"=>\"/usr/bin/python\",
    #5
    )

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /opt/vmware/etc/lighttpd/lighttpd.conf

    Configure the \"cgi.assign\" section to the following:

        cgi.assign                        = (
            \".pl\"  => \"/usr/bin/perl\",
            \".cgi\" => \"/usr/bin/perl\",
            \".rb\"  => \"/usr/bin/ruby\",
            \".erb\" => \"/usr/bin/eruby\",
            \".py\"  => \"/usr/bin/python\",
            # 5
        )
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000013'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']
end

