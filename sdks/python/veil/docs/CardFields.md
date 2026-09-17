# CardFields

Request only. Never returned. Never MCP.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**number** | **str** |  | [optional] 
**exp_month** | **str** |  | [optional] 
**exp_year** | **str** |  | [optional] 
**cvv** | **str** |  | [optional] 
**holder** | **str** |  | [optional] 

## Example

```python
from veil.models.card_fields import CardFields

# TODO update the JSON string below
json = "{}"
# create an instance of CardFields from a JSON string
card_fields_instance = CardFields.from_json(json)
# print the JSON string representation of the object
print(CardFields.to_json())

# convert the object into a dict
card_fields_dict = card_fields_instance.to_dict()
# create an instance of CardFields from a dict
card_fields_from_dict = CardFields.from_dict(card_fields_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


