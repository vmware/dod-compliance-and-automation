control 'VCUI-67-000030' do
  title 'vSphere UI must set the secure flag for cookies.'
  desc  "The secure flag is an option that can be set by the application server
when sending a new cookie to the user within an HTTP Response. The purpose of
the secure flag is to prevent cookies from being observed by unauthorized
parties due to the transmission of a cookie in clear text. By setting the
secure flag, the browser will prevent the transmission of a cookie over an
unencrypted channel. vSphere UI is configured to only be accessible over a TLS
tunnel, but this cookie flag is still a recommended best practice."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed
's/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/session-config/cookie-config/secure' -

    Expected result:

    <secure>true</secure>

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/web.xml.

    Navigate to the /<web-apps>/<session-config>/<cookie-config> node and
configure it as follows:

        <cookie-config>
          <http-only>true</http-only>
          <secure>true</secure>
        </cookie-config>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000155'
  tag gid: 'V-239711'
  tag rid: 'SV-239711r679239_rule'
  tag stig_id: 'VCUI-67-000030'
  tag fix_id: 'F-42903r679238_fix'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  describe xml("#{input('webXmlPath')}") do
    its('/web-app/session-config/cookie-config/secure') { should cmp 'true' }
  end
end
