control "VCLD-67-000023" do
  title "VAMI must not have any symbolic links in the web content directory
tree."
  desc  "A web server is designed to deliver content and execute scripts or
applications on the request of a client or user.  Containing user requests to
files in the directory tree of the hosted web application and limiting the
execution of scripts and applications guarantees that the user is not accessing
information protected outside the application's realm.

    By checking that no symbolic links exist in the document root, the web
server is protected from users jumping outside the hosted application directory
tree and gaining access to the other directories, including the system root."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000141-WSR-000087"
  tag gid: nil
  tag rid: "VCLD-67-000023"
  tag stig_id: "VCLD-67-000023"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

find /opt/vmware/share/htdocs -type l

If any files are listed, this is a finding."
  desc 'fix', "At the command prompt, enter the following commands:

Note: Replace <file_name> for the name of any files that were returned.

unlink <file_name>

Repeat the commands for each file that was listed."

  describe command('find /opt/vmware/share/htdocs -type l') do
      its ('stdout') { should eq '' }
  end

end

