control 'VCUI-70-000032' do
  title 'vSphere UI must set the secure flag for cookies.'
  desc 'The secure flag is an option that can be set by the application server when sending a new cookie to the user within an HTTP response. The purpose of the secure flag is to prevent cookies from being observed by unauthorized parties due to the transmission of a cookie in clear text.

By setting the secure flag, the browser will prevent the transmission of a cookie over an unencrypted channel. vSphere UI is configured to only be accessible over a Transport Layer Security (TLS) tunnel, but this cookie flag is still a recommended best practice.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' -

Expected result:

<secure>true</secure>

If the output of the command does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-vsphere-ui/server/conf/web.xml

Navigate to the /<web-apps>/<session-config>/<cookie-config> node and configure it as follows.

    <cookie-config>
      <http-only>true</http-only>
      <secure>true</secure>
    </cookie-config>

Restart the service with the following command:

# vmon-cli --restart vsphere-ui'
  impact 0.5
  tag check_id: 'C-60484r889424_chk'
  tag severity: 'medium'
  tag gid: 'V-256809'
  tag rid: 'SV-256809r889426_rule'
  tag stig_id: 'VCUI-70-000032'
  tag gtitle: 'SRG-APP-000439-WSR-000155'
  tag fix_id: 'F-60427r889425_fix'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  describe xml("#{input('webXmlPath')}") do
    its('/web-app/session-config/cookie-config/secure') { should cmp 'true' }
  end
end
