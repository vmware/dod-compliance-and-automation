control 'TCSV-00-000088' do
  title 'tc Server binary file permissions must be restricted.'
  desc  "The standard configuration is to have the folder where tc Server is installed owned by a non-root user and group (normally 'tomcat' for the first instance, but can be different per instance). The $CATALINA_HOME environment variable should be set to the location of the root directory of the \"binary\" distribution of tc Server."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command (substituting 'tomcat' with the appropriate username):

    # find $CATALINA_HOME -follow -maxdepth 0 \\( ! -user tomcat ! -group tomcat \\) -ls

    If no folders are displayed, this is not a finding.

    If results indicate that $CATALINA_HOME folder ownership and group membership are not set to the specified user and group, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands (substituting 'tomcat' with the appropriate username):

    # find $CATALINA_HOME -maxdepth 0 \\( ! -user tomcat\\) | sudo xargs chown tomcat

    # find $CATALINA_HOME -maxdepth 0 \\( ! -group tomcat \\) | sudo xargs chgrp tomcat
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag gid: 'V-TCSV-00-000088'
  tag rid: 'SV-TCSV-00-000088'
  tag stig_id: 'TCSV-00-000088'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1)']

  describe file("#{input('catalinaHome')}") do
    its('owner') { should cmp "#{input('tcCoreUser')}" }
    its('group') { should cmp "#{input('tcCoreGroup')}" }
  end
end
