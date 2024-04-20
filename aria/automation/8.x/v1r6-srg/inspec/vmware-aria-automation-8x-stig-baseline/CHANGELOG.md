# Change Log  

## [8.x Version 1 Release 6] (2024-04-22)

#### Release Notes
- Replaced Photon 3 content with Photon 4 content.
- Removed Kubernetes content.
- Fixed DKER-CE-000116 control (rename from 115)
- Fixed DKER-CE-000132 control (rename from 131)

## [8.13.1 Version 1 Release 5] (2024-01-03)

#### Release Notes
- Updated documentation for Kubernetes manifest file changes.

## [8.12 Version 1 Release 4] (2023-10-30)

#### Release Notes
- Rebranding from vRealize Automation to VMware Aria Automation:
  - VRAA-8X-000002
  - VRAA-8X-000005
  - VRAA-8X-000007
  - VRAA-8X-000008 - fixed vracli command
  - VRAA-8X-000009
  - VRAA-8X-000012
  - VRAA-8X-000014
  - VRAA-8X-000046
  - VRAA-8X-000047
  - VRAA-8X-000074
  - VRAA-8X-000091
  - VRAA-8X-000106
  - VRAA-8X-000107
  - VRAA-8X-000123 - removed
  - VRAA-8X-000125 - fixed fips mode check
  - VRAA-8X-000126 - updated sshd config path
  - VRAA-8X-000127
  - VRAA-8X-000128
- Include Photon controls locally (instead of linking to Photon profile) to handle updated sshd config file path specific to Aria Automation.
- Updated inspec.yaml sshd command input in the Photon profile.
- Updated Photon controls with new sshd config file path:
  - PHTN-30-000003
  - PHTN-30-000006
  - PHTN-30-000008
  - PHTN-30-000009
  - PHTN-30-000037
  - PHTN-30-000038
  - PHTN-30-000064
  - PHTN-30-000078
  - PHTN-30-000079
  - PHTN-30-000080
  - PHTN-30-000081
  - PHTN-30-000082
  - PHTN-30-000083
  - PHTN-30-000084
  - PHTN-30-000085
  - PHTN-30-000086
  - PHTN-30-000087
  - PHTN-30-000112
  - PHTN-30-000115
  - PHTN-30-000119
  - PHTN-30-000120

## [8.11 Version 1 Release 3] (2023-04-06)

#### Release Notes
- General cleanup, linting fixes.
- Switched to Official DISA Kubernetes v1r8 STIG content.
- VRAA-8X-000125 - Changed check from 'strict' to 'enabled' for FIPS mode.
- VRAA-8X-000126 - Moved from Photon to vRA to handle input value.
- VRAA-8X-000127 - Moved from Photon to vRA to handle path changes.
- VRAA-8X-000128 - Moved from Photon to vRA to handle config file option.

## [8.9 Version 1 Release 2] (2022-12-15)

#### Release Notes
- Removed Traefik and RabbitMQ controls, merged relevant controls into Application control set.
- General cleanup of verbiage, InSpec content, updates to pass linting.
- VRAA-8X-000001, VRAA-8X-000003, VRAA-8X-000004, VRAA-8X-000006, VRAA-8X-000010 - handled by IDM STIG controls.
- VRAA-8X-000007 - Updated Check and Fix.
- VRAA-8X-000011 - Marked as Duplicate of VRAA-8X-000012.
- VRAA-8X-000014, VRAA-8X-000015, VRAA-8X-000047, VRAA-8X-000074, VRAA-8X-000091, VRAA-8X-000106, VRAA-8X-000107 - Moved from Traefik to vRA Application control.
- VRAA-8X-000046 - Moved from RabbitMQ to vRA Application control.
- VRAA-8X-000123 - Added control for disabling CEIP.
- VRAA-8X-000125 - Added control to ensure FIPS mode.

## [8.2 Version 1 Release 1] (2021-08-04)

#### Release Notes
- Initial release for vRA 8