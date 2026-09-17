# veil.AgentApi

All URIs are relative to *https://veil.nyc*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_health**](AgentApi.md#get_health) | **GET** /health | Liveness. No secrets.
[**get_open_api**](AgentApi.md#get_open_api) | **GET** /openapi.json | This contract.
[**list_events**](AgentApi.md#list_events) | **GET** /v1/events | This agent&#39;s grant events. Decision, item, action. Never secrets. Not MCP.
[**list_items**](AgentApi.md#list_items) | **GET** /v1/items | Items this principal may see. Agent: granted. Human owner: the org. Human member: granted. Names and URIs. Never secrets.
[**use_item**](AgentApi.md#use_item) | **POST** /v1/use | Call a URL as this agent. The broker injects the credential. The vault secret is never in the response.


# **get_health**
> str get_health()

Liveness. No secrets.

### Example


```python
import veil
from veil.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to https://veil.nyc
# See configuration.py for a list of all supported configuration parameters.
configuration = veil.Configuration(
    host = "https://veil.nyc"
)


# Enter a context with an instance of the API client
with veil.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = veil.AgentApi(api_client)

    try:
        # Liveness. No secrets.
        api_response = api_instance.get_health()
        print("The response of AgentApi->get_health:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling AgentApi->get_health: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

**str**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: text/plain

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | ok |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_open_api**
> object get_open_api()

This contract.

### Example


```python
import veil
from veil.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to https://veil.nyc
# See configuration.py for a list of all supported configuration parameters.
configuration = veil.Configuration(
    host = "https://veil.nyc"
)


# Enter a context with an instance of the API client
with veil.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = veil.AgentApi(api_client)

    try:
        # This contract.
        api_response = api_instance.get_open_api()
        print("The response of AgentApi->get_open_api:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling AgentApi->get_open_api: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

**object**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | OpenAPI document |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_events**
> EventsResponse list_events()

This agent's grant events. Decision, item, action. Never secrets. Not MCP.

### Example

* Bearer (JWT) Authentication (bearerAuth):

```python
import veil
from veil.models.events_response import EventsResponse
from veil.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to https://veil.nyc
# See configuration.py for a list of all supported configuration parameters.
configuration = veil.Configuration(
    host = "https://veil.nyc"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

# Configure Bearer authorization (JWT): bearerAuth
configuration = veil.Configuration(
    access_token = os.environ["BEARER_TOKEN"]
)

# Enter a context with an instance of the API client
with veil.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = veil.AgentApi(api_client)

    try:
        # This agent's grant events. Decision, item, action. Never secrets. Not MCP.
        api_response = api_instance.list_events()
        print("The response of AgentApi->list_events:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling AgentApi->list_events: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**EventsResponse**](EventsResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Recent events for the Bearer agent |  -  |
**401** | missing or invalid Bearer |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_items**
> ItemsResponse list_items()

Items this principal may see. Agent: granted. Human owner: the org. Human member: granted. Names and URIs. Never secrets.

### Example

* Bearer (JWT) Authentication (bearerAuth):

```python
import veil
from veil.models.items_response import ItemsResponse
from veil.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to https://veil.nyc
# See configuration.py for a list of all supported configuration parameters.
configuration = veil.Configuration(
    host = "https://veil.nyc"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

# Configure Bearer authorization (JWT): bearerAuth
configuration = veil.Configuration(
    access_token = os.environ["BEARER_TOKEN"]
)

# Enter a context with an instance of the API client
with veil.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = veil.AgentApi(api_client)

    try:
        # Items this principal may see. Agent: granted. Human owner: the org. Human member: granted. Names and URIs. Never secrets.
        api_response = api_instance.list_items()
        print("The response of AgentApi->list_items:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling AgentApi->list_items: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**ItemsResponse**](ItemsResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Items |  -  |
**401** | missing or invalid Bearer |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **use_item**
> UseResponse use_item(use_request)

Call a URL as this agent. The broker injects the credential. The vault secret is never in the response.

### Example

* Bearer (JWT) Authentication (bearerAuth):

```python
import veil
from veil.models.use_request import UseRequest
from veil.models.use_response import UseResponse
from veil.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to https://veil.nyc
# See configuration.py for a list of all supported configuration parameters.
configuration = veil.Configuration(
    host = "https://veil.nyc"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

# Configure Bearer authorization (JWT): bearerAuth
configuration = veil.Configuration(
    access_token = os.environ["BEARER_TOKEN"]
)

# Enter a context with an instance of the API client
with veil.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = veil.AgentApi(api_client)
    use_request = veil.UseRequest() # UseRequest | 

    try:
        # Call a URL as this agent. The broker injects the credential. The vault secret is never in the response.
        api_response = api_instance.use_item(use_request)
        print("The response of AgentApi->use_item:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling AgentApi->use_item: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **use_request** | [**UseRequest**](UseRequest.md)|  | 

### Return type

[**UseResponse**](UseResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Decision plus upstream result, scrubbed |  -  |
**400** | bad request |  -  |
**401** | missing or invalid Bearer |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

