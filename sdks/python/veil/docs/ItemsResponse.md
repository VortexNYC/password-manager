# ItemsResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**items** | [**List[Item]**](Item.md) |  | 

## Example

```python
from veil.models.items_response import ItemsResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ItemsResponse from a JSON string
items_response_instance = ItemsResponse.from_json(json)
# print the JSON string representation of the object
print(ItemsResponse.to_json())

# convert the object into a dict
items_response_dict = items_response_instance.to_dict()
# create an instance of ItemsResponse from a dict
items_response_from_dict = ItemsResponse.from_dict(items_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


