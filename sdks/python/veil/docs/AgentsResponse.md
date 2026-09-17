# AgentsResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**agents** | [**List[Agent]**](Agent.md) |  | 

## Example

```python
from veil.models.agents_response import AgentsResponse

# TODO update the JSON string below
json = "{}"
# create an instance of AgentsResponse from a JSON string
agents_response_instance = AgentsResponse.from_json(json)
# print the JSON string representation of the object
print(AgentsResponse.to_json())

# convert the object into a dict
agents_response_dict = agents_response_instance.to_dict()
# create an instance of AgentsResponse from a dict
agents_response_from_dict = AgentsResponse.from_dict(agents_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


