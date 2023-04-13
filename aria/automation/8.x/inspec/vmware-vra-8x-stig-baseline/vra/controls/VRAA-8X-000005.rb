control 'VRAA-8X-000005' do
  title 'vRealize Automation must use cryptographic mechanisms to protect the integrity of log tools.'
  desc  "
    Protecting the integrity of the tools used for logging purposes is a critical step in ensuring the integrity of log data. Log data includes all information (e.g., log records, log settings, and log reports) needed to successfully log information system activity.

    It is not uncommon for attackers to replace the log tools or inject code into the existing tools for the purpose of providing the capability to hide or erase system activity from the logs.

    To address this risk, log tools must be cryptographically signed in order to provide the capability to identify when the log tools have been modified, manipulated or replaced. An example is a checksum hash of the file or files.

    Application server log tools must use cryptographic mechanisms to protect the integrity of the tools or allow cryptographic protection mechanisms to be applied to their tools.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # rpm -V prelude-vracli

    If the command produces any output showing files have been modified, this is a finding.

    Note: In some cases \"tmp\" files may be created during package install, and later cleaned up, which rpm will report as \"missing\". These changes must be inspected on a case by case basis for determination if they should be considered findings or not.
  "
  desc  'fix', "
    The fix will vary on the file and the modification made. If the user or group has been changed, run the following command:

    # rpm --setugids prelude-vracli

    If the permissions have been changed, run the following command:

    # rpm --setperms prelude-vracli

    If the md5 hash has been changed, roll back to a previous backup or contact VMware support.

    The original files are not retained and cannot be included here.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000290-AS-000174'
  tag gid: 'V-VRAA-8X-000005'
  tag rid: 'SV-VRAA-8X-000005'
  tag stig_id: 'VRAA-8X-000005'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']

  # Find any modified files, ignoring missing tmp files...
  describe command('rpm -V prelude-vracli | grep -v "^missing\s*/tmp"') do
    its('stdout.strip') { should cmp '' }
  end
end
