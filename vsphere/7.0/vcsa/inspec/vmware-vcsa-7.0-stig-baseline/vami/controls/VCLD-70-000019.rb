# encoding: UTF-8

control 'VCLD-70-000019' do
  title 'VAMI must set the enconding for all text mime types to UTF-8.'
  desc  "Invalid user input occurs when a user inserts data or characters into
a hosted application's data entry field and the hosted application is
unprepared to process that data. This results in unanticipated application
behavior, potentially leading to an application compromise. Invalid user input
is one of the primary methods employed when attempting to compromise an
application.

    An attacker can also enter Unicode into hosted applications in an effort to
break out of the document home or root home directory or to bypass security
checks.

  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk
'/mimetype\\.assign/,/\\)/'|grep \"text/\"|grep -v \"'charset=utf-8'\"|sed -e
's/^[ ]*//'

    If the command returns any value, this is a finding.
  "
  desc  'fix', "
    Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

    Navigate to the \"mimetype.assign\" block. Replace all the mappings whose
assigned type is \"text/*\" with mappings for utf-8 encoding, as follows:

    \".css\"     => \"text/css\",

    \".html\"    => \"text/html\",

    \".htm\"     => \"text/html\",

    \".js\"      => \"text/javascript\",

    \".asc\"     => \"text/plain\",

    \".c\"       => \"text/plain\",

    \".cpp\"     => \"text/plain\",

    \".log\"     => \"text/plain\",

    \".conf\"    => \"text/plain\",

    \".text\"    => \"text/plain\",

    \".txt\"     => \"text/plain\",

    \".spec\"    => \"text/plain\",

    \".dtd\"     => \"text/xml\",

    \".xml\"     => \"text/xml\",
      \".log\"          =>      \"text/plain; charset=utf-8\",
      \".conf\"         =>      \"text/plain; charset=utf-8\",
      \".text\"         =>      \"text/plain; charset=utf-8\",
      \".txt\"          =>      \"text/plain; charset=utf-8\",
      \".spec\"         =>      \"text/plain; charset=utf-8\",
      \".dtd\"          =>      \"text/xml; charset=utf-8\",
      \".xml\"          =>      \"text/xml; charset=utf-8\",
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000019'
  tag fix_id: nil
  tag cci: 'CCI-001310'
  tag nist: ['SI-10']


  
end

