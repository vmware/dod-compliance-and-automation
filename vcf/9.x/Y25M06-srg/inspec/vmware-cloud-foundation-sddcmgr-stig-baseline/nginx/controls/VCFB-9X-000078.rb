control 'VCFB-9X-000078' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server configuration files must only be accessible to privileged users.'
  desc  "
    A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

    To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # find /etc/nginx -xdev -type f ! -name .htpasswd -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

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
  tag satisfies: ['SRG-APP-000211-WSR-000030', 'SRG-APP-000340-WSR-000029']
  tag gid: 'V-VCFB-9X-000078'
  tag rid: 'SV-VCFB-9X-000078'
  tag stig_id: 'VCFB-9X-000078'
  tag cci: ['CCI-001082', 'CCI-001813', 'CCI-002235']
  tag nist: ['AC-6 (10)', 'CM-5 (1) (a)', 'SC-2']

  conffiles = command('find /etc/nginx -xdev -type f ! -name .htpasswd').stdout
  if !conffiles.empty?
    conffiles.split.each do |fname|
      describe file(fname) do
        it { should_not be_writable.by('others') }
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
      end
    end
  else
    describe 'No conf files found...skipping.' do
      skip 'No conf files found...skipping.'
    end
  end
end
