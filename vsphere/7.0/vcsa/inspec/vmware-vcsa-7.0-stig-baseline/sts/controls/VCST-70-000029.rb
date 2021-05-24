# encoding: UTF-8

control 'VCST-70-000029' do
  title 'The Security Token Service must disable the shutdown port.'
  desc  "The secure flag is an option that can be set by the application server
when sending a new cookie to the user within an HTTP Response. The purpose of
the secure flag is to prevent cookies from being observed by unauthorized
parties due to the transmission of the cookie in clear text.

    By setting the secure flag, the browser will prevent the transmission of a
cookie over an unencrypted channel. The Security Token Service is configured to
only be accessible over a TLS tunnel, but this cookie flag is still a
recommended best practice.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep 'base.shutdown.port'
/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

    Expected result:

    base.shutdown.port=-1

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

    Add or modify the following setting:

    base.shutdown.port=-1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000029'
  tag fix_id: nil
  tag cci: 'CCI-002385'
  tag nist: ['SC-5']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['base.shutdown.port'] do
    it { should eq "#{input('shutdownPort')}" }
  end

end

