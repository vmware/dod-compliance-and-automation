# encoding: UTF-8

control 'VCST-70-000015' do
  title "The Security Token Service must be configured with memory leak
protection."
  desc  "A web server is designed to deliver content and execute scripts or
applications on the request of a client or user. Containing user requests to
files in the directory tree of the hosted web application and limiting the
execution of scripts and applications guarantees that the user is not accessing
information protected outside the application's realm.

    By checking that no symbolic links exist in the document root, the web
server is protected from users jumping outside the hosted application directory
tree and gaining access to the other directories, including the system root.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep JreMemoryLeakPreventionListener
/usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Expected result:

    <Listener
className=\"org.apache.catalina.core.JreMemoryLeakPreventionListener\"/>

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Navigate to the <Server> node.

    Add '<Listener
className=\"org.apache.catalina.core.JreMemoryLeakPreventionListener\"/>' to
the <Server> node.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000015'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']

  describe xml("#{input('serverXmlPath')}") do
    its('Server/Listener/attribute::className') { should include "#{input('memLeakListener')}" }
  end

end

