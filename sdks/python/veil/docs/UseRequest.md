# UseRequest


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**item** | **str** | Granted item name | 
**url** | **str** | Absolute URL. Host must match the item. | 
**method** | **str** |  | [optional] [default to 'GET']
**headers** | **Dict[str, str]** | Extra request headers. Never the vault secret. | [optional] 
**body** | **str** | Request body. Never the vault secret. Use --body-file on the CLI. | [optional] 
**body_b64** | **bytes** | Base64 request body for binary payloads. Takes precedence over body. Never the vault secret. | [optional] 

## Example

```python
from veil.models.use_request import UseRequest

# TODO update the JSON string below
json = "{}"
# create an instance of UseRequest from a JSON string
use_request_instance = UseRequest.from_json(json)
# print the JSON string representation of the object
print(UseRequest.to_json())

# convert the object into a dict
use_request_dict = use_request_instance.to_dict()
# create an instance of UseRequest from a dict
use_request_from_dict = UseRequest.from_dict(use_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


