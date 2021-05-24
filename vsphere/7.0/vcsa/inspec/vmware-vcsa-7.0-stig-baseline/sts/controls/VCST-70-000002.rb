# encoding: UTF-8

control 'VCST-70-000002' do
  title "The Security Token Service must limit the number of concurrent
connections permitted."
  desc  "The \"maxPostSize\" value is the maximum size in bytes of the POST
which will be handled by the container FORM URL parameter parsing. Limit its
size to reduce exposure to a DOS attack.

    If \"maxPostSize\" is not set, the default value of 2097152 (2MB) is used.
Security Token Service is configured in it's shipping state to not set a value
for \"maxPostSize\".
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath
'/Server/Service/Executor[@name=\"tomcatThreadPool\"]/@maxThreads'
/usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Expected result:

    maxThreads=\"150\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Navigate to the <Executor> mode with the name of \"tomcatThreadPool\" and
configure with the value 'maxThreads=\"150\"' as follows:

    <Executor maxThreads=\"150\" minSpareThreads=\"50\"
name=\"tomcatThreadPool\" namePrefix=\"tomcat-http--\" />
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000002'
  tag fix_id: nil
  tag cci: 'CCI-000054'
  tag nist: ['AC-10']

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Executor[@name="tomcatThreadPool"]/@maxThreads']) { should cmp "#{input('maxThreads')}" }
  end

end

