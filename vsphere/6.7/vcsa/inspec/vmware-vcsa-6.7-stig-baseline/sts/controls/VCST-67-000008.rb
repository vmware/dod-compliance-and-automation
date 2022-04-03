control 'VCST-67-000008' do
  title "The Security Token Service application files must be verified for
their integrity."
  desc  "Verifying that the Security Token Service application code is
unchanged from its shipping state is essential for file validation and
non-repudiation of the Security Token Service. There is no reason the MD5 hash
of the rpm original files should be changed after installation, excluding
configuration files.
  "
  desc  'rationale', ''
  desc  'check', "
    Connect to the PSC, whether external or embedded.

    At the command prompt, execute the following command:

    # rpm -V vmware-identity-sts|grep \"^..5......\"|grep -E
\"\\.war|\\.jar|\\.sh|\\.py\"

    If there is any output, this is a finding.
  "
  desc 'fix', "
    Connect to the PSC, whether external or embedded.

    Reinstall the VCSA or roll back to a snapshot.

    Modifying the Security Token Service installation files manually is not
supported by VMware.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag satisfies: ['SRG-APP-000131-WSR-000051', 'SRG-APP-000357-WSR-000150']
  tag gid: 'V-239659'
  tag rid: 'SV-239659r816702_rule'
  tag stig_id: 'VCST-67-000008'
  tag fix_id: 'F-42851r816701_fix'
  tag cci: ['CCI-001749', 'CCI-001849']
  tag nist: ['CM-5 (3)', 'AU-4']

  describe command('rpm -V vmware-identity-sts|grep "^..5......"|grep -E "\.war|\.jar|\.sh|\.py"') do
    its('stdout.strip') { should eq '' }
  end
end
