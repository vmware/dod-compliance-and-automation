control "V-219204" do
  title "The Ubuntu operating system must have system commands set to a mode of 0755 or
    less permissive."
  desc "If the Ubuntu operating system were to allow any user to make changes to software
    libraries, then those changes might be implemented without undergoing the appropriate
    testing and approvals that are part of a robust change management process.

    This requirement applies to Ubuntu operating systems with software libraries that are
    accessible and configurable, as in the case of interpreted languages. Software libraries
    also include privileged programs which execute with escalated privileges. Only qualified
    and authorized individuals must be allowed to obtain access to information system
    components for purposes of initiating changes, including upgrades and modifications.
  "

  impact 0.5
  tag "gtitle": "SRG-OS-000259-GPOS-00100"
  tag "gid": "V-219204"
  tag "rid": "SV-219204r379246_rule"
  tag "stig_id": "UBTU-18-010139"
  tag "fix_id": "F-20928r304941_fix"
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
  desc "check", "Verify the system commands contained in the following directories have mode
    0755 or less permissive:

    /bin
    /sbin
    /usr/bin
    /usr/sbin
    /usr/local/bin
    /usr/local/sbin

    Check that the system command files have mode 0755 or less permissive with the following
    command:

    # find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;

    If any files are found to be group-writable or world-writable, this is a finding.
  "
  desc "fix", "Configure the system commands to be protected from unauthorized access.
    Run the following command:

    # sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' \;
  "

  system_commands = command("find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f").stdout.strip.split("\n").entries
  valid_system_commands = Set[]

  if system_commands.count > 0
    system_commands.each do |sys_cmd|
      if file(sys_cmd).exist?
        valid_system_commands = valid_system_commands << sys_cmd
      end
    end
  end

  if valid_system_commands.count > 0
    valid_system_commands.each do |val_sys_cmd|
      describe file(val_sys_cmd) do
        it { should_not be_more_permissive_than("0755") }
      end
    end
  else
    describe "Number of system commands found in /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin or /usr/local/sbin, that are less permissive than 0755" do
      subject { valid_system_commands }
      its("count") { should eq 0 }
    end
  end
end
