# encoding: UTF-8

control 'VCST-70-000023' do
  title 'The Security Token Service must not show directory listings.'
  desc  "Web servers will often display error messages to client users,
displaying enough information to aid in the debugging of the error. The
information given back in error messages may display the web server type,
version, patches installed, plug-ins and modules installed, type of code being
used by the hosted application, and any backends being used for data storage.

    This information could be used by an attacker to blueprint what type of
attacks might be successful. As such, the Security Token Service must be
configured to not show server version information in error messages.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'//param-name[text()=\"listings\"]/parent::init-param' -

    Expected result:

    <init-param>
          <param-name>listings</param-name>
          <param-value>false</param-value>
    </init-param>

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/web.xml

    Set the <param-value> to \"false\" in all <param-name>listing</param-name>
nodes.

    Note: The setting should look like the following:

    <init-param>
          <param-name>listings</param-name>
          <param-value>false</param-value>
    </init-param>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000023'
  tag fix_id: nil
  tag cci: 'CCI-001312'
  tag nist: ['SI-11 a']

  describe.one do

    describe xml("#{input('webXmlPath')}") do
      its('/web-app/servlet/init-param[param-name="listings"]/param-value') { should eq [] }
    end

    describe xml("#{input('webXmlPath')}") do
      its('/web-app/servlet/init-param[param-name="listings"]/param-value') { should cmp "false" }
    end

  end


end

