control 'CFNG-4X-000018' do
  title 'The SDDC Manager NGINX service configuration files must only be accessible to privileged users.'
  desc  "
    A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

    To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    find /etc/nginx -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # chmod o-w <file>
    # chown root:root <file>

    Repeat the command for each file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-WSR-000072'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFNG-4X-000018'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1)']

  describe command('find /etc/nginx -xdev -type f -a \'(\' -perm -o+w -o -not -user root -o -not -group root \')\' -exec ls -ld {} \\;') do
    its('stdout.strip') { should eq '' }
  end
end
