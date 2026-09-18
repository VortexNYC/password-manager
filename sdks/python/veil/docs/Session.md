# Session

Sandbox Use lease metadata. Never the token.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **str** |  | 
**org_id** | **str** |  | 
**agent_id** | **str** |  | 
**expires_at** | **datetime** |  | 
**created_at** | **datetime** |  | 
**revoked_at** | **datetime** |  | [optional] 
**renewed_at** | **datetime** |  | [optional] 
**ttl** | **int** | Initial lease duration in seconds. | 
**max_ttl** | **int** | Maximum cumulative lifetime in seconds. | 
**max_uses** | **int** | Maximum successful Use calls. 0 &#x3D; unlimited. | 
**uses** | **int** | Use calls that passed authorization and reached upstream consumption. | 

## Example

```python
from veil.models.session import Session

# TODO update the JSON string below
json = "{}"
# create an instance of Session from a JSON string
session_instance = Session.from_json(json)
# print the JSON string representation of the object
print(Session.to_json())

# convert the object into a dict
session_dict = session_instance.to_dict()
# create an instance of Session from a dict
session_from_dict = Session.from_dict(session_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


