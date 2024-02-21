control 'VRLT-8X-000026' do
  title 'The VMware Aria Operations for Logs tc Server files in the $CATALINA_BASE/logs folder must have their permissions set to 640.'
  desc  'The tc Server file permissions must be restricted. The standard configuration is to have all files owned by root. While root has read/write privileges, group only has read permissions, and world has no permissions. The exceptions are the logs, temp, and work directories. This means that even if an attacker compromises the tc Server process, they cannot change the configuration, deploy new web applications, or modify existing web applications. The tc Server process runs with a umask of 0027 to maintain these permissions.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /usr/lib/loginsight/application/3rd_party/apache-tomcat/logs/* -follow -maxdepth 0 -type f \\( \\! -perm 640 \\) -ls

    If no files are displayed, this is not a finding.

    If results indicate any of the file permissions contained in the /usr/lib/loginsight/application/3rd_party/apache-tomcat/logs folder are not set to 640, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # find /usr/lib/loginsight/application/3rd_party/apache-tomcat/logs/* -follow -maxdepth 0 -type f  | sudo xargs chmod 640
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000119-AS-000079'
  tag gid: 'V-VRLT-8X-000026'
  tag rid: 'SV-VRLT-8X-000026'
  tag stig_id: 'VRLT-8X-000026'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9']

  command("find '#{input('catalinaBase')}/logs' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_more_permissive_than('0640') }
    end
  end
end
