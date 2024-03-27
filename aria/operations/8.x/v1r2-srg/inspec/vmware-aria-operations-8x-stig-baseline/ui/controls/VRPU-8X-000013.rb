control 'VRPU-8X-000013' do
  title 'The UI service must initiate session logging upon startup.'
  desc  "
    An attacker can compromise a web server during the startup process. If logging is not initiated until all the web server processes are started, key information may be missed and not available during a forensic investigation. To ensure all relevant events are captured, the web server must begin logging once the first web server process is initiated.

    During start, Tomcat server reports system messages onto STDOUT and STDERR. These messages will be logged if the initialization script is configured correctly. Historically, the standard log file for these messages is called “catalina.out”.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -B10 -A2 '\"$CATALINA_OUT\" 2>&1 \"&\"' $CATALINA_HOME/bin/catalina.sh

    Verify that each start command within the 'elif [ \"$1\" = \"start\" ] ; then' block contains the text '>> \"$CATALINA_OUT\" 2>&1 \"&\"'

    If the command is not correct or is missing, this is a finding.
  "
  desc 'fix', "
    Edit the $CATALINA_HOME/bin/catalina.sh file.

    Navigate to and locate the start block : 'elif [ \"$1\" = \"start\" ] ; then'.

    Navigate to and locate both “eval” statements.

    Ensure both \"eval\" statements contain:

    org.apache.catalina.startup.Bootstrap \"$@\" start \\
    >> \"$CATALINA_OUT\" 2>&1 \"&\"

    EXAMPLE:
        eval $_NOHUP \"\\\"$_RUNJAVA\\\"\" \"\\\"$CATALINA_LOGGING_CONFIG\\\"\" $LOGGING_MANAGER \"$JAVA_OPTS\" \"$CATALINA_OPTS\" \\
          -D$ENDORSED_PROP=\"\\\"$JAVA_ENDORSED_DIRS\\\"\" \\
          -classpath \"\\\"$CLASSPATH\\\"\" \\
          -Djava.security.manager \\
          -Djava.security.policy==\"\\\"$CATALINA_BASE/conf/catalina.policy\\\"\" \\
          -Dcatalina.base=\"\\\"$CATALINA_BASE\\\"\" \\
          -Dcatalina.home=\"\\\"$CATALINA_HOME\\\"\" \\
          -Djava.io.tmpdir=\"\\\"$CATALINA_TMPDIR\\\"\" \\
          org.apache.catalina.startup.Bootstrap \"$@\" start \\
          >> \"$CATALINA_OUT\" 2>&1 \"&\"

    Restart the service:
    # systemctl restart vmware-vcops-web.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-AS-000053'
  tag gid: 'V-VRPU-8X-000013'
  tag rid: 'SV-VRPU-8X-000013'
  tag stig_id: 'VRPU-8X-000013'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  # look for the startup bootstrap line, and grab the 10 lines before and 2 lines after for comparison
  describe command("grep -B10 -A2 'org.apache.catalina.startup.Bootstrap \"$@\" start \' #{input('ui-tcCore')}/bin/catalina.sh") do
    its('stdout.strip') { should_not cmp '' }
  end
end
