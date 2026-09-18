# IdentityFields

Request only. Never returned. Never MCP.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**given_name** | **str** |  | [optional] 
**family_name** | **str** |  | [optional] 
**address** | **str** |  | [optional] 
**city** | **str** |  | [optional] 
**region** | **str** |  | [optional] 
**postal** | **str** |  | [optional] 
**country** | **str** |  | [optional] 
**phone** | **str** |  | [optional] 
**email** | **str** |  | [optional] 

## Example

```python
from veil.models.identity_fields import IdentityFields

# TODO update the JSON string below
json = "{}"
# create an instance of IdentityFields from a JSON string
identity_fields_instance = IdentityFields.from_json(json)
# print the JSON string representation of the object
print(IdentityFields.to_json())

# convert the object into a dict
identity_fields_dict = identity_fields_instance.to_dict()
# create an instance of IdentityFields from a dict
identity_fields_from_dict = IdentityFields.from_dict(identity_fields_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


