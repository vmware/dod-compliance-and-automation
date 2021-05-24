# encoding: UTF-8

control 'VCST-70-000017' do
  title "The Security Token Service directory tree must have permissions in an
out-of-the-box state."
  desc  "Determining a safe state for failure and weighing that against a
potential denial of service for users depends on what type of application the
web server is hosting. For the Security Token Service, it is preferable that
the service abort startup on any initialization failure rather than continuing
in a degraded, and potentailly insecure state."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /usr/lib/vmware-sso/vmware-sts/ -xdev -type f -a '(' -not -user root
-o -not -group root ')' -exec ls -ld {} \\;

    If the command produces any output, this is a finding.
  "
  desc  'fix', "
    At the command prompt, execute the following command:

    # chown root:root <file_name>

    Repeat the command for each file that was returned.

    Note: Replace <file_name> for the name of the file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000017'
  tag fix_id: nil
  tag cci: 'CCI-001082'
  tag nist: ['SC-2']

  describe command("find '#{input('rootPath')}' -xdev -type f -a \'(\' -not -user root -o -not -group root \')\' -exec ls -ld {} \;") do
   its('stdout.strip') { should eq ''}
  end

end

