import csv
import os
import datetime
from azure.mgmt.msi import ManagedServiceIdentityClient
import azure.mgmt.resourcegraph as arg
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.core.exceptions import HttpResponseError
import azure.mgmt.devcenter as devcenter
import functools
import re
import json
import requests
import shortuuid
import sys


def _get_mi_associations(credential: DefaultAzureCredential,
                         subscription_id: str,
                         resource_group: str,
                         resource_name: str) -> list | int | list:
    """
    Get the list of resources associated with a managed identity
    :param credential:
    :param subscription_id:
    :param resource_group:
    :param resource_name:
    :return:
    """
    try:
        mi_client = ManagedServiceIdentityClient(credential=credential,
                                                 subscription_id=subscription_id,
                                                 api_version="2021-09-30-preview")
        associated_resources = mi_client.user_assigned_identities.list_associated_resources(
            resource_group_name=resource_group,
            resource_name=resource_name)
        mi_to_resource_associations = {}
        print(f'Checking associations for {resource_name}')
        association_count = 0
        subscription_list = []
        for item in associated_resources:
            mi_to_resource_associations.setdefault(resource_name, [])
            payload = {'id': item.id,
                       'type': item.type,
                       'name': item.name,
                       'subscription_id': item.subscription_id,
                       'resource_group': item.resource_group,
                       'subscription_display_name': item.subscription_display_name}
            mi_to_resource_associations.get(resource_name).append(payload)
            if resource_name in mi_to_resource_associations:
                subscription_list.append(item.subscription_id)
                association_count += 1
                if subscription_id != item.subscription_id:
                    # count += 1
                    pass

        mi_to_resource_associations_list = list(map(list, mi_to_resource_associations.items()))

        return mi_to_resource_associations_list, association_count, subscription_list
    except HttpResponseError as e:
        print(e.message)
        return [], 0, []
    except:
        print(f'Unexpected error: {sys.exc_info()[0]}')
        return [], 0, []


def _enumerate_cosmosdb_role_assignments(cosmosdb_client: CosmosDBManagementClient, resource_group_name: str,
                                         account_name: str, subscription_id: str) -> list:
    """
    Enumerate the Cosmos DB role assignments
    :param cosmosdb_client:
    :param resource_group_name:
    :param account_name:
    :return:
    """
    results = cosmosdb_client.sql_resources.list_sql_role_assignments(resource_group_name=resource_group_name,
                                                                      account_name=account_name)
    cosmos_rbac_role_assignments = []
    for r in results:
        role = r.as_dict()
        role['accountName'] = account_name
        role['subscriptionId'] = subscription_id
        cosmos_rbac_role_assignments.append(role)

    return cosmos_rbac_role_assignments


def get_cosmos_db(credential: DefaultAzureCredential, subscription_id: str) -> str | list | int:
    query = "resources \
            | where type == 'microsoft.documentdb/databaseaccounts' \
            | project name, id, type, tenantId, location, resourceGroup, subscriptionId, properties, identity"
    results = get_resources(credential, query, subscription_id)
    """
    One or multiple scope(s) that the role definition can be assigned at; supported scopes are:
    / (account-level),
    /dbs/<database-name> (database-level),
    /dbs/<database-name>/colls/<container-name> (container-level).
    """

    cosmosdb_client = CosmosDBManagementClient(
        credential=credential,
        subscription_id=subscription_id
    )
    cosmos_rbac_role_assignments = []
    if len(results.data) > 0:
        cosmos_rbac_role_assignments = _enumerate_cosmosdb_role_assignments(cosmosdb_client,
                                                                            results.data[0]['resourceGroup'],
                                                                            results.data[0]['name'],
                                                                            subscription_id)
        return results.data[0]['name'], cosmos_rbac_role_assignments, len(results.data)
    else:
        return None, cosmos_rbac_role_assignments, len(results.data)


def create_path(folder_name: str) -> str:
    path = os.getcwd() + os.sep + "data" + os.sep + folder_name
    # Check whether the specified path exists or not

    if not os.path.exists(path):
        # Create a new directory because it does not exist
        os.makedirs(path)
        print(f"Creating {path} directory")
    else:
        pass
    return path


def get_sql_servers(credential: DefaultAzureCredential, subscription_id: str) -> list | int:
    query = "resources \
    | where type in ('microsoft.sql/servers') \
    | extend properties=parse_json(properties) \
    | extend activeDirectoryAuth=properties['administrators']['azureADOnlyAuthentication'] \
    | extend administratorType=properties['administrators']['administratorType'] \
    | extend objectid=properties['administrators']['sid'] \
    | project subscriptionId, name, type, location, resourceGroup, activeDirectoryAuth, administratorType, objectid"

    results = get_resources(credential, query, subscription_id)

    return results.data, len(results.data)


def get_postgres_flexible_servers(credential: DefaultAzureCredential, subscription_id: str) -> list:
    query = "resources \
    | where type in ('microsoft.dbforpostgresql/flexibleservers') \
    | extend config=parse_json(properties) \
    | extend activeDirectoryAuth=config['authConfig']['activeDirectoryAuth'] \
    | extend passwordAuth=config['authConfig']['passwordAuth'] \
    | project subscriptionId, name, type, location, resourceGroup, activeDirectoryAuth, passwordAuth"

    results = get_resources(credential, query, subscription_id)
    print(f'Total Postgres Flexible Servers: {len(results.data)}')
    return results.data


# of Key Vaults in this sub
def get_all_vaults(credential: DefaultAzureCredential, subscription_id: str) -> list:
    """
    This function will return all of the key vaults in the subscription
    :param credential:
    :param subscription_id:
    :return:
    """
    query = "resources \
    | where type == 'microsoft.keyvault/vaults' \
    | extend d=parse_json(properties) \
    | extend access_policies=d['accessPolicies'] \
    | project subscriptionId, name, id, type, tenantId, location, resourceGroup, access_policies"

    results = get_resources(credential, query, subscription_id)
    print(f'Total Key Vaults: {len(results.data)}')
    return results.data


def get_resources(credential: DefaultAzureCredential, str_query: str, subscription_id: str) -> arg.models.QueryResponse:
    """
    This function will return the results of the query.
    It uses the AzureCLI Credential to authenticate to Azure and query the Azure Resource Graph
    :param subscription_id:
    :param credential:
    :param str_query:
    :return: QueryResponse
    """

    # Create Azure Resource Graph client and set options
    arg_client = arg.ResourceGraphClient(credential)
    arg_query_options = arg.models.QueryRequestOptions(result_format="objectArray")
    # Create query
    arg_query = arg.models.QueryRequest(subscriptions=[subscription_id], query=str_query, options=arg_query_options)
    # Run query
    arg_results = arg_client.resources(arg_query)

    return arg_results


def get_subscription_data(credential: DefaultAzureCredential) -> list | list:
    """
    returns subscription list and subscription raw data. This returns only subscription that a user has access to.
    """
    subs_client = SubscriptionClient(credential)
    # get the list of subscriptions the user has access to
    subs_raw = [s.as_dict() for s in subs_client.subscriptions.list()]
    # get the list of subscription ids as a list
    subs_list = [s.get('subscription_id') for s in subs_raw]
    return subs_list, subs_raw


def generate_auth_credentials(tenant_id: str) -> DefaultAzureCredential:
    """
    This function will generate the credentials for the Azure using the ALI Credential
    :return: ALI Credential
    """
    if str is not None:
        credential = DefaultAzureCredential(interactive_browser_tenant_id=tenant_id)
    else:
        credential = DefaultAzureCredential()  # uses environment variables
    return credential


def enumerate_rbac_roles(credential: DefaultAzureCredential, subscription_id: str, object_id: str) -> list:
    """
    TO DO - get all RBAC assignments for a given object_id
    TO DO - Write all RBACs to a single file - will need to open existing file and append
    TO DO - Filter Mgmt Groups
    :param subscription_id:
    :param credential:
    :param object_id:
    :return:
    """
    # get credential
    authorization_client = AuthorizationManagementClient(credential, subscription_id)

    if object_id is None:
        results = authorization_client.role_assignments.list_for_scope(scope='/subscriptions/' + subscription_id)
    else:
        results = authorization_client.role_assignments.list_for_scope(scope='/subscriptions/' + subscription_id,
                                                                       filter=f"principalId eq '{object_id}'")
    roles = []
    access_token = credential.get_token('https://graph.microsoft.com/.default')
    for item in results:
        try:
            # Identity not found.
            json_text = ""

            if (item.principal_id is None) or (item.principal_id == ''):
                raise ValueError('principalId is None or empty')
            if item.principal_type == 'User':
                json_text = make_get_rest_call(
                    f'https://graph.microsoft.com/beta/users/{item.principal_id}?$select=displayName',
                    access_token)
            elif item.principal_type == 'ServicePrincipal':
                json_text = make_get_rest_call(
                    f'https://graph.microsoft.com/beta/servicePrincipals/{item.principal_id}?$select=displayName',
                    access_token)
            elif item.principal_type == 'Group':
                json_text = make_get_rest_call(
                    f'https://graph.microsoft.com/beta/groups/{item.principal_id}?$select=displayName',
                    access_token)
            json_results = json.loads(json_text)
            obj_display = json_results['displayName']
            # print(obj_display)

            role_def = authorization_client.role_definitions.get_by_id(item.role_definition_id)
            dict_obj = {'subscriptionId': subscription_id, 'name': obj_display, 'assignment_id': item.name,
                        'role_definition_id': item.role_definition_id,
                        'role_name': role_def.role_name,
                        'role_type': role_def.role_type, 'scope': item.scope, 'principal_id': item.principal_id,
                        'principal_type': item.principal_type}
            if item.scope.startswith("/subscriptions"):
                roles.append(dict_obj)
        except HttpResponseError as e:
            print(e)

        except Exception as e:
            print(e)

    return roles


def get_aks_clusters(credential: DefaultAzureCredential, subscription_id: str) -> list | int:
    """
    This function will return all of the AKS clusters in the subscription
    :param credential:
    :param subscription_id:
    :return:
    """
    query = "resources \
    | where type == 'microsoft.containerservice/managedclusters'  \
    | project subscriptionId, name, id, type, tenantId, location, resourceGroup, identity"
    results = get_resources(credential, query, subscription_id)

    return results.data, len(results.data)


def get_all_managed_identities(credential: DefaultAzureCredential, subscription_id: str) -> list | int:
    """
    :return: list of all managed identities
    """
    query = "resources \
    | where type == 'microsoft.managedidentity/userassignedidentities' or \
    identity contains 'SystemAssigned' \
    | extend managedidentity=iff(isnull(identity), properties, identity) \
    | extend identityType=iff(isnull(identity), 'UserAssignedIdentity', 'SystemAssignedIdentity') \
    | extend principalId=parse_json(managedidentity)['principalId'] \
    | project subscriptionId, name, id, type, tenantId, location, resourceGroup, managedidentity, principalId, identityType"

    results = get_resources(credential, query, subscription_id)

    for item in results.data:
        item['group_memberships'] = []
        item['federated_identity_credentials'] = []
        item['associations'] = []
        item['associations_count'] = 0
        item['associations_sub_ids'] = []

        try:
            if (item['principalId'] is None) or (item['principalId'] == ''):
                raise ValueError('principalId is None or empty')

            json_text = make_get_rest_call(
                f'https://graph.microsoft.com/beta/servicePrincipals/{item["principalId"]}/transitiveMemberOf?$select=displayName',
                credential.get_token('https://graph.microsoft.com/.default'))
            json_results = json.loads(json_text)
            json_results_items = json_results['value']
            if len(json_results_items) > 0:
                for json_i in json_results_items:
                    item['group_memberships'].append(json_i['displayName'])

            if item.get('identityType') != 'SystemAssignedIdentity':
                fed_creds, fed_creds_count = get_managed_identity_details(credential,
                                                                          subscription_id,
                                                                          item.get('name'),
                                                                          item.get('resourceGroup'))
                if fed_creds_count > 0:
                    item['federated_identity_credentials'] = fed_creds

                associations, association_count, total_subs = _get_mi_associations(credential,
                                                                                   subscription_id,
                                                                                   item.get('resourceGroup'),
                                                                                   item.get('name'))
                if len(associations) > 0:
                    item['associations'] = associations[0]
                    item['associations_count'] = association_count
                    item['associations_sub_ids'] = total_subs

                print(
                    f'Found {association_count} associations for {item.get("name")} in the following subs: {total_subs}')
        except HttpResponseError as e:
            print(f'Error calling Graph API {e}')
        except Exception as e:
            print(f'Error: {e}')

    return results.data, len(results.data)


def get_managed_identity_details(credential: DefaultAzureCredential, subscription_id: str, resource_name: str,
                                 resource_group: str) -> list | int:
    """
    This function will return the details of a managed identity
    :param resource_group:
    :param resource_name:
    :param credential:
    :param subscription_id:
    :return:
    """
    client = ManagedServiceIdentityClient(credential, subscription_id)
    if hasattr(client, 'federated_identity_credentials'):
        num_fed_creds = 0
        result = client.federated_identity_credentials.list(resource_group, resource_name)
        if result:
            results_dict_list = [item.as_dict() for item in result]
            num_fed_creds = len(results_dict_list)
        print(f'\tFederated Identity Credentials for {resource_name}: {num_fed_creds}')
        return results_dict_list, num_fed_creds
    else:
        return [], 0


def write_to_csv(full_file_name: str, data: list, subscription: str, *args, **kwargs) -> None:
    """
    @param fname: string, name of file to write
    @param data: list of items
    Write data to file
    :param full_file_name:
    :param subscription:
    :param file_name:

    """

    if os.path.isfile(full_file_name):
        with open(full_file_name, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            if not reader.fieldnames:
                # Write header to the file
                with open(full_file_name, 'w', newline='') as csvfile:
                    fieldnames = data[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in data:
                        writer.writerow(row)
            else:
                # Append data to the existing file
                with open(full_file_name, 'a', newline='') as csvfile:
                    fieldnames = reader.fieldnames
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    for row in data:
                        writer.writerow(row)
    else:
        with open(full_file_name, 'w', newline='') as csvfile:
            fieldnames = data[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in data:
                writer.writerow(row)


def get_mi_information_inventory(creds, sub, path):
    sub_rbac_roles = enumerate_rbac_roles(creds, sub, None)
    if sub_rbac_roles is not None and len(sub_rbac_roles) > 0:
        write_to_csv(path + os.sep + "raw-rbac-assignments-export.csv", sub_rbac_roles, sub)
        # write_to_csv("sub-" + sub[-6:] + '-raw-rbac-assignments-export-' + suffix + '.csv', sub_rbac_roles, sub)

    managed_identities, mi_count = get_all_managed_identities(creds, sub)
    print(f'Total Managed Identities: {mi_count}')
    if len(managed_identities) > 0:
        write_to_csv(path + os.sep + "raw-resources-export.csv", managed_identities, sub)
        # write_to_csv('raw-resources-export-' + suffix + '.csv', managed_identities, sub)

    # fn = 'mi-raw-rbac-assignments-export-' + suffix + '.csv'
    fn = 'raw-mi-rbac-assignments-export.csv'
    for mi in managed_identities:
        if not (mi['principalId'] is None or mi['principalId'] == ''):
            rbac_roles = enumerate_rbac_roles(creds, sub, mi['principalId'])
            if rbac_roles is not None and len(rbac_roles) > 0:
                write_to_csv(path + os.sep + "raw-mi-rbac-assignments-export.csv", rbac_roles, sub)


def get_keyvault_information_inventory(creds, sub, path):
    vaults = get_all_vaults(creds, sub)
    if len(vaults) > 0:
        write_to_csv(path + os.sep + 'raw-vaults-export.csv', vaults, sub)


def get_aks_information_inventory(creds, sub, path):
    aks_clusters, num_aks_clusters = get_aks_clusters(creds, sub)
    print(f'Total AKS Clusters: {num_aks_clusters}')
    if len(aks_clusters) > 0:
        write_to_csv(path + os.sep + 'raw-aks-resources-export.csv', aks_clusters, sub)


def get_postgres_information_inventory(creds, sub, path):
    postgres_flex_servers = get_postgres_flexible_servers(creds, sub)
    if len(postgres_flex_servers) > 0:
        write_to_csv(path + os.sep + 'raw-postgres-flexible-servers-export.csv', postgres_flex_servers, sub)


def get_azure_sql_information_inventory(creds, sub, path):
    azure_sql_servers, num_azure_sql_servers = get_sql_servers(creds, sub)
    print(f'Total Azure SQL DB Servers: {num_azure_sql_servers}')
    if len(azure_sql_servers) > 0:
        write_to_csv(path + os.sep + 'raw-sql-servers-export.csv', azure_sql_servers, sub)


def get_cosmosdb_information_inventory(creds, sub, path):
    acct, rbac_roles, num_cosmos_accounts = get_cosmos_db(creds, sub)
    print(f'Total Cosmos DB Accounts: {num_cosmos_accounts}')
    if acct is not None and rbac_roles is not None and len(rbac_roles) > 0:
        write_to_csv(path + os.sep + 'raw-cosmosdb-export.csv', rbac_roles, sub)


# generate the dev centers in a subscription
def get_devcenters(credential: DefaultAzureCredential, subscription_id: str) -> list | int:
    """
    This function will return the number of devboxes in a subscription
    :param credential: DefaultAzureCredential
    :param subscription_id: string
    :return:
    """
    query = "resources \
    | where type == 'microsoft.devcenter/projects' \
    | project name, id, type, tenantId, location, resourceGroup, subscriptionId, properties['devCenterUri']"

    results = get_resources(credential, query, subscription_id)

    return results, len(results.data)


def get_devcenter_devboxes(credential: DefaultAzureCredential, devcenter_uri: str) -> list | int:
    """
    This function will a list devboxes in the specified devcenter
    :param credential: AzureCliCredential
    :param subscription_id: string
    :param location: string
    :param devcenter_name: string
    :return:
    """
    results = []
    endpoint = devcenter_uri

    try:
        # get a token scoped for Dev Center.
        token = credential.get_token('https://devcenter.azure.com')
        if token is None:
            print('Error getting access token')
            return None, 0

        # get the devboxes
        url = f'{endpoint}devboxes?api-version=2023-04-01'
        json_response = make_get_rest_call(url, token)

        # parse the response JSON
        arr = json.loads(json_response)["value"]
        if arr is not None and len(arr) > 0:
            results.extend(arr)

        return results, len(results)
    except Exception as e:
        print(f'Error getting devboxes for {devcenter_uri} - {e}')
        return None, 0


def get_devbox_inventory(creds: DefaultAzureCredential, subscrption_id: str, path: str):
    raw_devboxes = []
    numdevboxes = 0
    devcenters, num_devcenters = get_devcenters(creds, subscrption_id)
    for devcenter in devcenters.data:
        dboxes, count = get_devcenter_devboxes(creds, devcenter['properties_devCenterUri'])
        if dboxes is not None and count > 0:
            for dbox in dboxes:
                dbox['subscriptionId'] = devcenter['subscriptionId']
                dbox['devcenterUri'] = devcenter['properties_devCenterUri']
                raw_devboxes.append(dbox)

            numdevboxes += count

    print(f'Total Devboxes: {numdevboxes}')

    if numdevboxes > 0:
        write_to_csv(path + os.sep + 'raw-devboxes-export.csv', raw_devboxes, subscrption_id)


# use this to make REST API calls. Returns JSON response
def make_get_rest_call(url: str, token: str) -> str:
    """
    This function will make a REST API call to the specified URL. Throws HttpResponseError if
    the response staus code is not 200.
    :param url: string - the URL to call
    :param token: string - access token
    """
    response = requests.get(url, headers={'Authorization': f'Bearer {token.token}'})
    if response.status_code != 200:
        raise HttpResponseError(f'Error on GET call to {url} - {response.status_code} - {response.text}')

    return response.text


def execute_discovery(tenant_id: str, subscription_id: list):
    creds = generate_auth_credentials(tenant_id)  # do this once
    if subscription_id is None or len(subscription_id) == 0:
        sub_list, list_sub_dict = get_subscription_data(creds)
    else:
        sub_list = subscription_id

    suffix = datetime.datetime.now().strftime("%Y%m%d") + '-' + shortuuid.uuid()[:3]

    path = create_path(f'subscriptions_inventory-{suffix}')

    print(path)
    for sub in sub_list:
        if sub != '7dc3c9b5-bb4b-4193-8862-7a02bdf9a001':
            # Print Subscription Header
            print("##################################################")
            print("Subscription: " + sub)
            print("##################################################")

            # Get all RBAC permissions at the subscription level
            get_mi_information_inventory(creds, sub, path)

            # Get all KeyVaults
            get_keyvault_information_inventory(creds, sub, path)

            # Get all AKS Clusters
            get_aks_information_inventory(creds, sub, path)

            # Get all Postgres Flexible Servers
            get_postgres_information_inventory(creds, sub, path)

            # Get all Azure SQL DB Servers
            get_azure_sql_information_inventory(creds, sub, path)

            # Get all Cosmos DB Accounts
            get_cosmosdb_information_inventory(creds, sub, path)

            # Get all Dev Centers/Dev Boxes
            get_devbox_inventory(creds, sub, path)


if __name__ == '__main__':
    # pre_check()

    # takes the tenant ID and a list of subscription IDs
    # if both of empty, it will default to all subscriptions in the tenant in the logged in user's context
    execute_discovery('', [])
