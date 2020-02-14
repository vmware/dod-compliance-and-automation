control "VCUI-67-000030" do
  title "vSphere UI must set the secure flag for cookies."
  desc  "The secure flag is an option that can be set by the application server
when sending a new cookie to the user within an HTTP Response. The purpose of
the secure flag is to prevent cookies from being observed by unauthorized
parties due to the transmission of a the cookie in clear text. By setting the
secure flag, the browser will prevent the transmission of a cookie over an
unencrypted channel. vSphere UI is configured to only be accessible over a TLS
tunnel but this cookie flag is still a recommended best practice."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: nil
  tag gid: nil
  tag rid: "VCUI-67-000030"
  tag stig_id: "VCUI-67-000030"
  tag cci: nil
  tag nist: nil
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed
's/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/session-config/cookie-config/secure' -

Expected result:

<secure>true</secure>

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/web.xml

Navigate to the /<web-apps>/<session-config>/<cookie-config> node and configure
it as follows.



    <cookie-config>
      <http-only>true</http-only>
      <secure>true</secure>
    </cookie-config>"

  describe xml('/usr/lib/vmware-vsphere-ui/server/conf/web.xml') do
    its('/web-app/session-config/cookie-config/secure') { should cmp 'true' }
  end

end