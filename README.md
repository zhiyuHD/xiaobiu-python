# suning-biu-ha

Python client for Suning smart home SMS login and session management.

Used by the [ha-suning](https://github.com/FaintGhost/ha-suning) Home Assistant custom integration.

## Install

```bash
pip install suning-biu-ha
```

## Usage

```python
from suning_biu_ha import CaptchaRequiredError, SuningSmartHomeClient

client = SuningSmartHomeClient(state_path=".suning-session.json")

try:
    client.send_sms_code("13800000000")
except CaptchaRequiredError as error:
    print(error.risk_type, error.sms_ticket)

client.login_with_sms_code(phone_number="13800000000", sms_code="123456")
print(client.list_family_infos())
```

## CLI

```bash
# Interactive login
suning-biu-ha login --phone 13800000000 --state-file .suning-session.json

# Send SMS only
suning-biu-ha send-sms --phone 13800000000 --state-file .suning-session.json

# Check session
suning-biu-ha check --state-file .suning-session.json

# List families / devices
suning-biu-ha families --state-file .suning-session.json
suning-biu-ha devices --family-id 37790 --state-file .suning-session.json
```

## Requirements

- Python >= 3.12
- `cryptography`, `pydantic`, `requests`
