control 'VCLU-80-000124' do
  title 'The vCenter Lookup service must enable STRICT_SERVLET_COMPLIANCE.'
  desc  "
    Strict Servlet Compliance forces Tomcat to adhere to standards specifications including but not limited to RFC2109. RFC2109 sets the standard for HTTP session management. This setting affects several other settings that primarily pertain to cookie headers, cookie values, and sessions. Cookies will be parsed for strict adherence to specifications.

    Note that changing a number of these default settings may break some systems, as some browsers are unable to correctly handle the cookie headers that result from a strict adherence to the specifications.

    This one setting changes the default values for the following settings:

    org.apache.catalina.core.ApplicationContext.GET_RESOURCE_REQUIRE_SLASH
    org.apache.catalina.core.ApplicationDispatcher.WRAP_SAME_OBJECT
    org.apache.catalina.core.StandardHostValve.ACCESS_SESSION
    org.apache.catalina.session.StandardSession.ACTIVITY_CHECK
    org.apache.catalina.session.StandardSession.LAST_ACCESS_AT_START
    org.apache.tomcat.util.http.ServerCookie.ALWAYS_ADD_EXPIRES
    org.apache.tomcat.util.http.ServerCookie.FWD_SLASH_IS_SEPARATOR
    org.apache.tomcat.util.http.ServerCookie.PRESERVE_COOKIE_HEADER
    org.apache.tomcat.util.http.ServerCookie.STRICT_NAMING
    The \"resourceOnlyServlets\" attribute of any Context element.
    The \"tldValidation\" attribute of any Context element.
    The \"useRelativeRedirects\" attribute of any Context element.
    The \"xmlNamespaceAware\" attribute of any Context element.
    The \"xmlValidation\" attribute of any Context element.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # grep STRICT_SERVLET_COMPLIANCE /usr/lib/vmware-lookupsvc/conf/catalina.properties

    Example result:

    org.apache.catalina.STRICT_SERVLET_COMPLIANCE=true

    If there are no results, or if the \"org.apache.catalina.STRICT_SERVLET_COMPLIANCE\" is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-lookupsvc/conf/catalina.properties

    Add or change the following line:

    org.apache.catalina.STRICT_SERVLET_COMPLIANCE=true

    Restart the service with the following command:

    # vmon-cli --restart lookupsvc
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VCLU-80-000124'
  tag rid: 'SV-VCLU-80-000124'
  tag stig_id: 'VCLU-80-000124'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['org.apache.catalina.STRICT_SERVLET_COMPLIANCE'] do
    it { should cmp 'true' }
  end
end
