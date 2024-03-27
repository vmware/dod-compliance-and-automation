control 'VRPE-8X-000013' do
  title 'The vRealize Operations Manager Apache server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.'
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. Only the system administrator needs access to all the system's capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /etc/httpd -xdev -type f -a '(' '(' -not -user admin -o -not -group admin ')' -a '(' -not -user root -o -not -group root ')' ')' -exec stat -c %n:%a:%U:%G {} \\;

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command for each <file> returned in the check:

    # chown admin:admin <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag gid: 'V-VRPE-8X-000013'
  tag rid: 'SV-VRPE-8X-000013'
  tag stig_id: 'VRPE-8X-000013'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  describe command("find /etc/httpd -xdev -type f -a '(' '(' -not -user admin -o -not -group admin ')' -a '(' -not -user root -o -not -group root ')' ')'") do
    its('stdout.strip') { should cmp '' }
  end
end
