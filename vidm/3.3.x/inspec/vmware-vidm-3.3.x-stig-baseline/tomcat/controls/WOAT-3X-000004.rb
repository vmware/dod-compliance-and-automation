control 'WOAT-3X-000004' do
  title 'Workspace ONE Access must protect cookies from XSS.'
  desc  'Cookies are a common way to save session state over the HTTP(S) protocol. If an attacker can compromise session data stored in a cookie, they are better able to launch an attack against the server and its applications. When you tag a cookie with the HttpOnly flag, it tells the browser that this particular cookie should only be accessed by the originating server. Any attempt to access the cookie from client script is strictly forbidden.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # for xml in $(find /opt/vmware/horizon/workspace/ -name context.xml); do echo $xml;xmllint --xpath '/Context/@useHttpOnly' $xml 2>/dev/null;done

    Expected result:

    /opt/vmware/horizon/workspace/webapps/hc/META-INF/context.xml
     useHttpOnly=\"true\"
    /opt/vmware/horizon/workspace/webapps/cfg/META-INF/context.xml
     useHttpOnly=\"true\"
    /opt/vmware/horizon/workspace/webapps/ROOT/META-INF/context.xml
    /opt/vmware/horizon/workspace/webapps/SAAS/META-INF/context.xml
     useHttpOnly=\"true\"
    /opt/vmware/horizon/workspace/conf/context.xml
     useHttpOnly=\"true\"

    If the output contains any entries of \"useHttpOnly=\"false\"\", this is a finding.
  "
  desc 'fix', "
    Open each file from the check with an incorrect setting in a text editor.

    Navigate to the <Context> node and configure it with the following value:

    useHttpOnly=\"true\"

    Example:

    <Context useHttpOnly=\"true\" crossContext=\"true\">
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag satisfies: ['SRG-APP-000223-WSR-000011', 'SRG-APP-000439-WSR-000154', 'SRG-APP-000439-WSR-000155']
  tag gid: 'V-WOAT-3X-000004'
  tag rid: 'SV-WOAT-3X-000004'
  tag stig_id: 'WOAT-3X-000004'
  tag cci: ['CCI-000054', 'CCI-001664', 'CCI-002418']
  tag nist: ['AC-10', 'SC-23 (3)', 'SC-8']

  command('find /opt/vmware/horizon/workspace/ -name context.xml').stdout.split.each do |fname|
    next unless fname != '/opt/vmware/horizon/workspace/webapps/ROOT/META-INF/context.xml'
    describe xml(fname) do
      its('/Context/@useHttpOnly') { should cmp 'true' }
    end
  end
end
