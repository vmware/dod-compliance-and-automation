control 'VCFH-9X-000043' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service directory tree must only be accessible by authorized accounts.'
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. Only the system administrator needs access to all the system's capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files."
  desc  'rationale', ''
  desc  'check', "
    Verify directory permissions are configured appropriately.

    At the command line, run the following:

    # find /storage/db/apache/proxy/web/ -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following:

    # chmod o-w <file>
    # chown root:root <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag satisfies: ['SRG-APP-000211-WSR-000031']
  tag gid: 'V-VCFH-9X-000043'
  tag rid: 'SV-VCFH-9X-000043'
  tag stig_id: 'VCFH-9X-000043'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  apache_document_dir = input('apache_document_dir')

  badfiles = command("find #{apache_document_dir} -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')'").stdout
  badfilesstderr = command("find #{apache_document_dir} -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')'").stderr

  if !badfiles.empty?
    badfiles.split.each do |badfile|
      describe file(badfile) do
        it { should_not be_writable.by('others') }
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
      end
    end
  else
    describe "Files found with incorrect permissions under #{apache_document_dir}" do
      subject { badfiles }
      it { should be_empty }
    end
    describe 'Find command should not have errors' do
      subject { badfilesstderr }
      it { should cmp '' }
    end
  end
end
