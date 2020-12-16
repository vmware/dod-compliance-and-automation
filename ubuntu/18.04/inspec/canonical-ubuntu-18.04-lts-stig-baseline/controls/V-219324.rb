# encoding: UTF-8

control 'V-219324' do
  title "The Apparmor module must be configured to employ a deny-all,
permit-by-exception policy to allow the execution of authorized software
programs and limit the ability of non-privileged users to grant other users
direct access to the contents of their home directories/folders."
  desc  "Control of program execution is a mechanism used to prevent execution
of unauthorized programs. Some operating systems may provide a capability that
runs counter to the mission or provides users with functionality that exceeds
mission requirements. This includes functions and services installed at the
operating system level.

    Some of the programs, installed by default, may be harmful or may not be
necessary to support essential organizational operations (e.g., key missions,
functions). Removal of executable programs is not always possible; therefore,
establishing a method of preventing program execution is critical to
maintaining a secure system baseline.

    Methods for complying with this requirement include restricting execution
of programs in certain environments, while preventing execution in other
environments; or limiting execution of certain program functionality based on
organization-defined criteria (e.g., privileges, subnets, sandboxed
environments, or roles).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the Ubuntu operating system is configured to employ a deny-all,
permit-by-exception policy to allow the execution of authorized software
programs and access to user home directories.

    Check that \"Apparmor\" is configured to employ application whitelisting
and home directory access control with the following command:

    # sudo apparmor_status

    apparmor module is loaded.
    17 profiles are loaded.
    17 profiles are in enforce mode.
     /sbin/dhclient
     /usr/bin/lxc-start
     ...
    0 processes are in complain mode.
    0 processes are unconfined but have a profile defined.

    If the defined profiles do not match the organization's list of authorized
software, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to employ a deny-all,
permit-by-exception policy to allow the execution of authorized software
programs.

    Install \"Apparmor\" (if it is not installed) with the following command:

    # sudo apt-get install apparmor

    Enable \"Apparmor\" (if it is not already active) with the following
command:

    # sudo systemctl enable apparmor.service

    Start \"Apparmor\" with the following command:

    # sudo systemctl start apparmor.service

    Note: Apparmor must have properly configured profiles for applications and
home directories. All configurations will be based on the actual system setup
and organization and normally are on a per role basis. See the \"Apparmor\"
documentation for more information on configuring profiles.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag gid: 'V-219324'
  tag rid: 'SV-219324r508662_rule'
  tag stig_id: 'UBTU-18-010442'
  tag fix_id: 'F-21048r305301_fix'
  tag cci: ['SV-109975', 'V-100871', 'CCI-001774']
  tag nist: ['CM-7 (5) (b)']

  describe 'Manual test' do
    skip 'This control must be reviewed manually'
  end
end

