# encoding: UTF-8

control 'VCST-70-000016' do
  title "The Security Token Service must not have any symbolic links in the web
content directory tree."
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only
administrators, web managers, developers, auditors, and web authors require
accounts on the machine hosting the web server. The resources to which these
accounts have access must also be closely monitored and controlled. The
Security Token Service files must be adequately protected with correct
permissions as applied out of the box."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /usr/lib/vmware-sso/vmware-sts/webapps/ -type l -ls

    If the command produces any output, this is a finding.
  "
  desc  'fix', "
    At the command prompt, execute the following command(s):

    Note: Replace <file_name> for the name of any files that were returned.

    # unlink <file_name>

    Repeat the commands for each file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000016'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']

  describe command("find '#{input('appPath')}' -type l -ls") do
    its ('stdout.strip') { should eq '' }
  end

end

