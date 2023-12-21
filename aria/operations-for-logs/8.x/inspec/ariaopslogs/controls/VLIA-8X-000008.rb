control 'VLIA-8X-000008' do
  title 'VMware Aria Operations for Logs must notify the SA and ISSO when log record retention capacity is low.'
  desc  "
    If security personnel are not notified immediately upon storage volume utilization is high, they are unable to plan for storage capacity expansion.

    Although this may be part of the operating system function, for the enterprise events management system, this is most often a function managed through the application since it is a critical function and requires the use of a large amount of external storage.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> General.

    If the \"Retention Notification Threshold\" is not enabled and set to 1 month or more, this is a finding.
  "
  desc 'fix', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> General.

    Check the box next to \"Retention Notification Threshold\" and set the value to 1 month or more.

    Note: SMTP must be configured if using email notifications.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000359-AU-000120'
  tag gid: 'V-VLIA-8X-000008'
  tag rid: 'SV-VLIA-8X-000008'
  tag stig_id: 'VLIA-8X-000008'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag mitigations: 'We have a prioritized feature request to implement this in the near term. .'

  describe 'Retention Notification Threshold configuration is a manual check' do
    skip 'Ensuring the Retention Notification Threshold is configured is a manual check.'
  end
end
