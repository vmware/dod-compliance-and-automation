# encoding: UTF-8

control 'VCST-70-000030' do
  title 'The Security Token Service must set the secure flag for cookies.'
  desc  "The default servlet (or DefaultServlet) is a special servlet provided
with Tomcat which is called when no other suitable page is found in a
particular folder. The DefaultServlet serves static resources as well as
directory listings.

    The DefaultServlet is configured by default with the \"readonly\" parameter
set to \"true\" where HTTP commands like PUT and DELETE are rejected. Changing
this to false allows clients to delete or modify static resources on the server
and to upload new resources. DefaultServlet readonly must be set to true,
either literally or by absence (default).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/session-config/cookie-config/secure' -

    Expected result:

    <secure>true</secure>

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/web.xml

    Navigate to the /<web-apps>/<session-config>/<cookie-config> node and
configure it as follows.

        <cookie-config>
          <http-only>true</http-only>
          <secure>true</secure>
        </cookie-config>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000155'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000030'
  tag fix_id: nil
  tag cci: 'CCI-002418'
  tag nist: ['SC-8']

  describe xml("#{input('webXmlPath')}") do
    its('/web-app/session-config/cookie-config/secure') { should cmp 'true' }
  end

end

