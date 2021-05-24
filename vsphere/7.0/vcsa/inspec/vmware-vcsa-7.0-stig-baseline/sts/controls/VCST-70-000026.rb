# encoding: UTF-8

control 'VCST-70-000026' do
  title 'The Security Token Service must have the debug option disabled.'
  desc  "The Security Token Service produces a number of logs that must be
offloaded from the originating system. This information can then be used for
diagnostic, forensics, or other purposes relevant to ensuring the availability
and integrity of the hosted application."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'//param-name[text()=\"debug\"]/parent::init-param' -

    Expected result:

    <init-param>
    \t<param-name>debug</param-name>
    \t<param-value>0</param-value>
    </init-param>

    If the output of the command does not match the expected result, this is a
finding.

    If no lines is returned, this is NOT a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/web.xml

    Navigate to all <debug> nodes that are not set to \"0\".

    Set the <param-value> to \"0\" in all <param-name>debug</param-name> nodes.

    Note: The debug setting should look like the following:

    <init-param>
        <param-name>debug</param-name>
        <param-value>0</param-value>
    </init-param>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000026'
  tag fix_id: nil
  tag cci: 'CCI-001312'
  tag nist: ['SI-11 a']

  describe.one do

    describe xml("#{input('webXmlPath')}") do
      its('/web-app/servlet/init-param[param-name="debug"]/param-value') { should eq [] }
    end

    describe xml("#{input('webXmlPath')}") do
      its('/web-app/servlet/init-param[param-name="debug"]/param-value') { should cmp "0" }
    end

  end

end

