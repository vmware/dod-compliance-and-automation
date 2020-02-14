control "PHTN-10-000070" do
  title "The Photon operating system must remove all software components after
updated versions have been installed."
  desc  "Previous versions of software components that are not removed from the
information system after updates have been installed may be exploited by
adversaries. Some information technology products may remove older versions of
software automatically from the information system."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000437-GPOS-00194"
  tag gid: nil
  tag rid: "PHTN-10-000070"
  tag stig_id: "PHTN-10-000070"
  tag cci: "CCI-002617"
  tag nist: ["SI-2 (6)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep -i \"^clean_requirements_on_remove\" /etc/tdnf/tdnf.conf

Expected result:

clean_requirements_on_remove=true

If the output does not match the expected result, this is a finding."
  desc 'fix', "Open /etc/tdnf/tdnf.conf with a text editor. Remove any existing
\"clean_requirements_on_remove\" line and ensure the following line is present:

clean_requirements_on_remove=true"

  describe command('grep -i "^clean_requirements_on_remove" /etc/tdnf/tdnf.conf') do
      its ('stdout.strip') { should cmp 'clean_requirements_on_remove=true' }
  end

end

