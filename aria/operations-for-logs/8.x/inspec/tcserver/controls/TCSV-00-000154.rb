control 'TCSV-00-000154' do
  title 'The tc Server manager webapp must be removed.'
  desc  'tc Server provides management functionality through either a default manager webapp or through local editing of the configuration files. The manager webapp files must be deleted, and administration must be performed through the local editing of the configuration files.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # ls -l $CATALINA_HOME/webapps/manager

    If the manager folder exists or contains any content, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # rm -rf $CATALINA_HOME/webapps/manager
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-TCSV-00-000154'
  tag rid: 'SV-TCSV-00-000154'
  tag stig_id: 'TCSV-00-000154'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Make sure the manager directory does not exist
  describe directory("#{input('catalinaHome')}/webapps/manager").exist? do
    it { should cmp 'false' }
  end
end
