control "VCLD-67-000028" do
  title "VAMI must set the enconding for all text mime types to UTF-8."
  desc  "Invalid user input occurs when a user inserts data or characters into
a hosted application's data entry field and the hosted application is
unprepared to process that data. This results in unanticipated application
behavior, potentially leading to an application compromise. Invalid user input
is one of the primary methods employed when attempting to compromise an
application.

    An attacker can also enter Unicode into hosted applications in an effort to
break out of the document home or root home directory or to bypass security
checks."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000251-WSR-000157"
  tag gid: nil
  tag rid: "VCLD-67-000028"
  tag stig_id: "VCLD-67-000028"
  tag cci: "CCI-001310"
  tag nist: ["SI-10", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

grep 'text/' /opt/vmware/etc/lighttpd/lighttpd.conf | grep -v 'charset=utf-8'

If any value is returned, this is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Navigate to the \"mimetype.assign\" block. Replace all the mappings whose
assigned type is \"text/*\" with to include mappings for utf-8 encoding, as
follows:

  \".css\"          =>      \"text/css; charset=utf-8\",
  \".html\"         =>      \"text/html; charset=utf-8\",
  \".htm\"          =>      \"text/html; charset=utf-8\",
  \".js\"           =>      \"text/javascript; charset=utf-8\",
  \".asc\"          =>      \"text/plain; charset=utf-8\",
  \".c\"            =>      \"text/plain; charset=utf-8\",
  \".cpp\"          =>      \"text/plain; charset=utf-8\",
  \".log\"          =>      \"text/plain; charset=utf-8\",
  \".conf\"         =>      \"text/plain; charset=utf-8\",
  \".text\"         =>      \"text/plain; charset=utf-8\",
  \".txt\"          =>      \"text/plain; charset=utf-8\",
  \".spec\"         =>      \"text/plain; charset=utf-8\",
  \".dtd\"          =>      \"text/xml; charset=utf-8\",
  \".xml\"          =>      \"text/xml; charset=utf-8\","

  describe command("grep 'text/' /opt/vmware/etc/lighttpd/lighttpd.conf | grep -v 'charset=utf-8'") do
      its ('stdout') { should eq '' }
  end

end
