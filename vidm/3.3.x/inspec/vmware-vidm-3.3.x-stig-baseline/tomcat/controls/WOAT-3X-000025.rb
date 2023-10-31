control 'WOAT-3X-000025' do
  title 'The Workspace ONE Access webapps must not be modified from their shipping state.'
  desc  "Verifying that Workspace ONE Access application code is unchanged from it's shipping state is essential for file validation and non-repudiation of the Workspace ONE Access itself. There is no reason that the MD5 hash of the rpm original files should be changed after installation, excluding configuration files."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # for f in $(rpm -q --whatprovides /usr/local/horizon/war/*.war); do rpm -V $f|grep '\\.war'; done

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    Re-install or roll back to a snapshot.

    Modifying the WS1A installation files manually is not supported by VMware.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag gid: 'V-WOAT-3X-000025'
  tag rid: 'SV-WOAT-3X-000025'
  tag stig_id: 'WOAT-3X-000025'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command("for f in $(rpm -q --whatprovides /usr/local/horizon/war/*.war); do rpm -V $f|grep '.war'; done") do
    its('stdout.strip') { should cmp '' }
  end
end
