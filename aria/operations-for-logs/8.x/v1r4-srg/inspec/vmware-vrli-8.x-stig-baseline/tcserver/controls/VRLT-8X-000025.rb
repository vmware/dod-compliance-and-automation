control 'VRLT-8X-000025' do
  title 'The VMware Aria Operations for Logs tc Server logs folder permissions must be set correctly.'
  desc  'The tc Server file permissions must be restricted. The standard configuration is to have all files owned by root with group tomcat. While root has read/write privileges, group only has read permissions, and world has no permissions. The exceptions are the logs, temp, and work directories that are owned by the tomcat user rather than root. This means that even if an attacker compromises the tc Server process, they cannot change the tc Server configuration, deploy new web applications, or modify existing web applications. The tc Server process runs with a umask of 0027 to maintain these permissions.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /usr/lib/loginsight/application/3rd_party/apache-tomcat/logs -follow -maxdepth 0 -type d \\( \\! -perm 750 \\) -ls

    If no folders are displayed, this is not a finding.

    If results indicate the /usr/lib/loginsight/application/3rd_party/apache-tomcat/logs folder permissions are not set to 750, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # find /usr/lib/loginsight/application/3rd_party/apache-tomcat/logs  -follow -maxdepth 0 -type d | sudo xargs chmod 750
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag satisfies: ['SRG-APP-000120-AS-000080']
  tag gid: 'V-VRLT-8X-000025'
  tag rid: 'SV-VRLT-8X-000025'
  tag stig_id: 'VRLT-8X-000025'
  tag cci: ['CCI-000162', 'CCI-000164']
  tag nist: ['AU-9']

  describe file("#{input('catalinaBase')}/logs") do
    it { should_not be_more_permissive_than('0750') }
  end
end
