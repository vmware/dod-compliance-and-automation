control 'VCFH-9X-000080' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service configuration files must only be accessible to privileged users.'
  desc  "
    A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

    To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # find /etc/httpd -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned in the output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following:

    # chmod 644 <file>
    # chown root:root <file>

    Repeat the command for each file that was returned.

    Note: File permissions will vary by file type.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-WSR-000072'
  tag satisfies: ['SRG-APP-000340-WSR-000029']
  tag gid: 'V-VCFH-9X-000080'
  tag rid: 'SV-VCFH-9X-000080'
  tag stig_id: 'VCFH-9X-000080'
  tag cci: ['CCI-001813', 'CCI-002235']
  tag nist: ['AC-6 (10)', 'CM-5 (1) (a)']

  apache_config_dir = input('apache_config_dir')

  badfiles = command("find #{apache_config_dir} -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')'").stdout
  badfilesstderr = command("find #{apache_config_dir} -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')'").stderr

  if !badfiles.empty?
    badfiles.split.each do |badfile|
      describe file(badfile) do
        it { should_not be_writable.by('others') }
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
      end
    end
  else
    describe "Files found with incorrect permissions under #{apache_config_dir}" do
      subject { badfiles }
      it { should be_empty }
    end
    describe 'Find command should not have errors' do
      subject { badfilesstderr }
      it { should cmp '' }
    end
  end
end
