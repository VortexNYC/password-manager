# GrantsResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**grants** | [**List[Grant]**](Grant.md) |  | 

## Example

```python
from veil.models.grants_response import GrantsResponse

# TODO update the JSON string below
json = "{}"
# create an instance of GrantsResponse from a JSON string
grants_response_instance = GrantsResponse.from_json(json)
# print the JSON string representation of the object
print(GrantsResponse.to_json())

# convert the object into a dict
grants_response_dict = grants_response_instance.to_dict()
# create an instance of GrantsResponse from a dict
grants_response_from_dict = GrantsResponse.from_dict(grants_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


