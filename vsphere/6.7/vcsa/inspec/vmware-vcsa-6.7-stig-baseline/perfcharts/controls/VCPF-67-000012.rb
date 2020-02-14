control "VCPF-67-000012" do
  title "Performance Charts must have mappings set for Java servlet pages."
  desc  "Resource mapping is the process of tying a particular file type to a
process in the web server that can serve that type of file to a requesting
client and to identify which file types are not to be delivered to a client.

    By not specifying which files can and which files cannot be served to a
user, the web server could deliver to a user web server configuration files,
log files, password files, etc.

    As Tomcat is a java-based web server, the main file extension used is
*.jsp.  This check ensures that the *.jsp and *.jspx file types has been
properly mapped to servlets."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000141-WSR-000083"
  tag gid: nil
  tag rid: "VCPF-67-000012"
  tag stig_id: "VCPF-67-000012"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/servlet-mapping/servlet-name[text()=\"jsp\"]/parent::servlet-mapping'
-

Expected result:

<servlet-mapping>
    <servlet-name>jsp</servlet-name>
    <url-pattern>*.jsp</url-pattern>
    <url-pattern>*.jspx</url-pattern>
  </servlet-mapping>

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-perfcharts/tc-instance/conf/web.xml

Inside the <web-app> parent node, add the following:

<servlet-mapping>
    <servlet-name>jsp</servlet-name>
    <url-pattern>*.jsp</url-pattern>
    <url-pattern>*.jspx</url-pattern>
  </servlet-mapping>"

  list = ["*.jsp", "*.jspx"]
  describe xml('/usr/lib/vmware-perfcharts/tc-instance/conf/web.xml') do
    its('/web-app/servlet-mapping[servlet-name="jsp"]/url-pattern') { should be_in list }
  end

end

