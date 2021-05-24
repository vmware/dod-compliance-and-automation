# encoding: UTF-8

control 'VCST-70-000018' do
  title "The Security Token Service must fail to a known safe state if system
initialization fails, shutdown fails, or aborts fail."
  desc  "Limiting the number of established connections to the Security Token
Service is a basic denal of service protection. Servers where the limit is too
high or unlimited can potentially run out of system resources and negatively
affect system availability."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep EXIT_ON_INIT_FAILURE
/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

    Expected result :

    org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

    Add or change the following line:

    org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000225-WSR-000140'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000018'
  tag fix_id: nil
  tag cci: 'CCI-001190'
  tag nist: ['SC-24']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['org.apache.catalina.startup.EXIT_ON_INIT_FAILURE'] do
    it { should eq 'true' }
  end

end

