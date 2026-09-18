# SessionsResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sessions** | [**List[Session]**](Session.md) |  | 

## Example

```python
from veil.models.sessions_response import SessionsResponse

# TODO update the JSON string below
json = "{}"
# create an instance of SessionsResponse from a JSON string
sessions_response_instance = SessionsResponse.from_json(json)
# print the JSON string representation of the object
print(SessionsResponse.to_json())

# convert the object into a dict
sessions_response_dict = sessions_response_instance.to_dict()
# create an instance of SessionsResponse from a dict
sessions_response_from_dict = SessionsResponse.from_dict(sessions_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


