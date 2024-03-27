control 'VCLU-70-000016' do
  title 'Lookup Service must not have any symbolic links in the web content directory tree.'
  desc "A web server is designed to deliver content and execute scripts or applications on the request of a client or user. Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees the user is not accessing information protected outside the application's realm.

By checking that no symbolic links exist in the document root, the web server is protected from users jumping outside the hosted application directory tree and gaining access to the other directories, including the system root."
  desc 'check', 'At the command prompt, run the following command:

# find /usr/lib/vmware-vsphere-ui/server/static/ -type l -ls

If the command produces any output, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

Note: Replace <file_name> for the name of any files that were returned.

# unlink <file_name>

Repeat the commands for each file that was returned.'
  impact 0.5
  tag check_id: 'C-60396r888752_chk'
  tag severity: 'medium'
  tag gid: 'V-256721'
  tag rid: 'SV-256721r888754_rule'
  tag stig_id: 'VCLU-70-000016'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag fix_id: 'F-60339r888753_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("find '#{input('appPath')}' -type l -ls") do
    its('stdout.strip') { should eq '' }
  end
end
