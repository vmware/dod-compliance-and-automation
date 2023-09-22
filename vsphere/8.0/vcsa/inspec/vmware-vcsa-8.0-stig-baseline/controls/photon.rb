include_controls 'photon' do
  # SELinux is currently not available on VCSA.
  skip_control 'PHTN-40-000066'
  # VCSA currently cannot implement this control so it must be skipped.
  skip_control 'PHTN-40-000085'
  # Syslog configuration is done in the VAMI
  skip_control 'PHTN-40-000111'
  # NTP configuration is done in the VAMI
  skip_control 'PHTN-40-000121'
  # AIDE not supported yet
  skip_control 'PHTN-40-000127'
  skip_control 'PHTN-40-000237'
  # VCSA ships with rsyslog installed.
  skip_control 'PHTN-40-000241'
  # VCSA does not support this configuration at this time.
  skip_control 'PHTN-40-000245'
end
