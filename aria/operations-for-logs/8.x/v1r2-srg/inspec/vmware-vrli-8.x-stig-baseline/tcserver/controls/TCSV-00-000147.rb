control 'TCSV-00-000147' do
  title '$CATALINA_BASE/work folder must be owned by tomcat user, group tomcat.'
  desc  'tc Server file permissions must be restricted. The standard configuration is to have all tc Server files owned by root with group tomcat. While root has read/write privileges, group only has read permissions, and world has no permissions. The exceptions are the logs, temp, and work directories that are owned by the tomcat user rather than root. This means that even if an attacker compromises the tc Server process, they cannot change the configuration, deploy new web applications, or modify existing web applications. The tc Server process runs with a umask of 0027 to maintain these permissions.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find $CATALINA_BASE/work -follow -maxdepth 0 \\( ! -user tomcat -o ! -group tomcat \\) -ls

    If no folders are displayed, this is not a finding.

    If results indicate the $CATALINA_BASE/work folder ownership and group membership is not set to tomcat:tomcat, this is a finding.

    Note: The name root and group name tomcat are used here as a reference, but technically can be named anything.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # find $CATALINA_BASE/work -maxdepth 0 \\( ! -user tomcat \\) | sudo xargs chown tomcat 2> /dev/null

    # find $CATALINA_BASE/work -maxdepth 0 \\( ! -group tomcat \\) | sudo xargs chgrp tomcat 2> /dev/null

    Note: The name root and group name tomcat are used here as a reference, but technically can be named anything.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag gid: 'V-TCSV-00-000147'
  tag rid: 'SV-TCSV-00-000147'
  tag stig_id: 'TCSV-00-000147'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1)']

  command("find '#{input('catalinaBase')}/work' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      its('owner') { should cmp "#{input('svcAccountName')}" }
      its('group') { should cmp "#{input('svcGroup')}" }
    end
  end
end
