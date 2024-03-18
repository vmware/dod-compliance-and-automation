control 'WOAT-3X-000034' do
  title 'Workspace ONE Access must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled..'
  desc  'MIME mappings tell Workspace ONE Access what type of program various file types and extensions are and what external utilities or programs are needed to execute the file type. By ensuring that various shell script MIME types are not included in web.xml, the server is protected against malicious users tricking the server into executing shell command files.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # for xml in $(find /opt/vmware/horizon/workspace/ -name web.xml); do echo $xml;grep -En '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)' $xml|wc -l;done

    If any discovered web.xml is followed by a line with non-zero number, this is a finding.
  "
  desc 'fix', "
    Open each file from the check with a non-zero count of found mime types in a text editor.

    Remove any and all of the following nodes lines,

        <mime-mapping>
            <extension>csh</extension>
            <mime-type>application/x-csh</mime-type>
        </mime-mapping>
    --
        <mime-mapping>
            <extension>sh</extension>
            <mime-type>application/x-sh</mime-type>
        </mime-mapping>
        <mime-mapping>
            <extension>shar</extension>
            <mime-type>application/x-shar</mime-type>
        </mime-mapping>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag gid: 'V-WOAT-3X-000034'
  tag rid: 'SV-WOAT-3X-000034'
  tag stig_id: 'WOAT-3X-000034'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  command('find /opt/vmware/horizon/workspace/ -name web.xml').stdout.split.each do |fname|
    describe command("grep -En '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)' '#{fname}'") do
      its('stdout.strip') { should cmp '' }
    end
  end
end
