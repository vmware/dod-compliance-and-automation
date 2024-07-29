include_controls 'photon' do
  # File permissions are different for Operations services
  # skip_control 'PHTN-40-000085'

  # Sudo users
  skip_control 'PHTN-50-000133'

  # Removed in favor of configuring via the product interfaces (UI/API)
  skip_control 'PHTN-50-000111'
  skip_control 'PHTN-50-000121'

  # AIDE will be implemented in a later release
  skip_control 'PHTN-50-000127'
  skip_control 'PHTN-50-000237'

  # Source requirement no longer present
  skip_control 'PHTN-50-000043'
  skip_control 'PHTN-50-000066'
  skip_control 'PHTN-50-000238'
  skip_control 'PHTN-50-000243'
end
