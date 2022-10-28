control 'VCPF-70-000017' do
  title 'Performance Charts directory tree must have permissions in an "out-of-the-box" state.'
  desc  'Accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. Performance Charts files must be adequately protected with correct permissions as applied "out of the box".'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /usr/lib/vmware-perfcharts/tc-instance/webapps/ -xdev -type f -a '(' -not -user root -a -not -user perfcharts -o -not -group root ')' -exec ls -la {} \\;

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # chown perfcharts:cis <file_name>

    Repeat the command for each file that was returned.

    Note: Replace <file_name> for the name of the file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag satisfies: ['SRG-APP-000380-WSR-000072']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPF-70-000017'
  tag cci: ['CCI-001082', 'CCI-001813']
  tag nist: ['CM-5 (1)', 'SC-2']

  describe command("find '#{input('rootPath')}'/webapps/ -xdev -type f -a \'(\' -not -user root -a -not -user perfcharts -o -not -group root \')\' -exec ls -la {} \\;") do
    its('stdout.strip') { should cmp '' }
  end
end
