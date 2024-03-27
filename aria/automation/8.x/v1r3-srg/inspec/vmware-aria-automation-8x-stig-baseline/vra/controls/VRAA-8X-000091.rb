control 'VRAA-8X-000091' do
  title 'The vRealize Automation ingress controller configuration files must only be accessible to privileged users.'
  desc  "
    A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

    To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged user access.
  "
  desc  'rationale', ''
  desc  'check', "
    From the command line interface, run the following command:

    # find /opt/charts/ingress-ctl -xdev -type f -a '(' -not -perm 644 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    From the command line interface, run the following command(s) for each <file> returned in the check:

    # chmod 644 <file>
    # chown root:root <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag gid: 'V-VRAA-8X-000091'
  tag rid: 'SV-VRAA-8X-000091'
  tag stig_id: 'VRAA-8X-000091'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1)']

  describe command('find /opt/charts/ingress-ctl -xdev -type f -a "(" -not -perm 644 -o -not -user root -o -not -group root ")" -exec ls -ld {} \;') do
    its('stdout') { should cmp '' }
  end
end
