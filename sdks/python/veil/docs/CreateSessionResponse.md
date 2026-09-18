# CreateSessionResponse

Token is create-only. Never list. Never MCP.

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
**ttl** | **int** |  | 
**max_ttl** | **int** |  | 
**max_uses** | **int** |  | 
**uses** | **int** | Use calls that passed authorization and reached upstream consumption. | 
**token** | **str** |  | 

## Example

```python
from veil.models.create_session_response import CreateSessionResponse

# TODO update the JSON string below
json = "{}"
# create an instance of CreateSessionResponse from a JSON string
create_session_response_instance = CreateSessionResponse.from_json(json)
# print the JSON string representation of the object
print(CreateSessionResponse.to_json())

# convert the object into a dict
create_session_response_dict = create_session_response_instance.to_dict()
# create an instance of CreateSessionResponse from a dict
create_session_response_from_dict = CreateSessionResponse.from_dict(create_session_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


