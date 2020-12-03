control 'V-219198' do
  title 'The Ubuntu operating system library files must have mode 0755 or less permissive.'
  desc  "If the operating system were to allow any user to make changes to software libraries,
  then those changes might be implemented without undergoing the appropriate testing and
  approvals that are part of a robust change management process.

  This requirement applies to operating systems with software libraries that are accessible
  and configurable, as in the case of interpreted languages. Software libraries also include
  privileged programs which execute with escalated privileges. Only qualified and authorized
  individuals must be allowed to obtain access to information system components for purposes
  of initiating changes, including upgrades and modifications.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000259-GPOS-00100"
  tag "gid": 'V-219198'
  tag "rid": "SV-219198r379246_rule"
  tag "stig_id": "UBTU-18-010133"
  tag "fix_id": "F-20922r304923_fix"
  tag "cci": [ "CCI-001499" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify the system-wide shared library files contained in the directories
    \"/lib\", \"/lib64\" and \"/usr/lib\" have mode 0755 or less permissive.

    Check that the system-wide shared library files have mode 0755 or less permissive with
    the following command:

    # sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;
    /usr/lib64/pkcs11-spy.so

    If any files are found to be group-writable or world-writable, this is a finding.
  "

  desc 'fix', "Configure the library files to be protected from unauthorized access. Run
    the following command:

    # sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' \;
  "

  if os.arch == 'x86_64'
    library_files = command('find /lib /lib32 lib64 /usr/lib /usr/lib32 -perm /022 -type f').stdout.strip.split("\n").entries
  else
    library_files = command('find /lib /usr/lib /usr/lib32 /lib32 -perm /022 -type f').stdout.strip.split("\n").entries
  end

  if library_files.count > 0
    library_files.each do |lib_file|
      describe file(lib_file) do
        it { should_not be_more_permissive_than('0755') }
      end
    end
  else
    describe 'Number of system-wide shared library files found that are less permissive than 0755' do
      subject { library_files }
      its('count') { should eq 0 }
    end
  end
end
