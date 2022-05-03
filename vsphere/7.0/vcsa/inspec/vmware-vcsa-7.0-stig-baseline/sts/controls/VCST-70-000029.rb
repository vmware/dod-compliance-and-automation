control 'VCST-70-000029' do
  title 'The Security Token Service must disable the shutdown port.'
  desc  "
    An attacker has at least two reasons to stop a web server. The first is to cause a denial of service, and the second is to put in place changes the attacker made to the web server configuration.

    If the Tomcat shutdown port feature is enabled, a shutdown signal can be sent to the Security Token Service through this port. To ensure availability, the shutdown port must be disabled.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep 'base.shutdown.port' /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

    Expected result:

    base.shutdown.port=-1

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

    Add or modify the following setting:

    base.shutdown.port=-1

    Restart the service with the following command:

    # vmon-cli --restart sts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000029'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['base.shutdown.port'] do
    it { should eq "#{input('shutdownPort')}" }
  end
end
