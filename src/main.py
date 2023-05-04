import csv
import os

import azure.mgmt.resourcegraph as arg
from azure.identity import AzureCliCredential
from azure.mgmt.authorization import AuthorizationManagementClient
# Import specific methods and models from other libraries
from azure.mgmt.resource import SubscriptionClient
from azure.cosmos import CosmosClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient

"""

# of Azure RBAC assignments in this sub direct to managed identities (as opposed to via a group)
This would be exported in the “subid-rbac-assignements.csv”
# of managed identities in this sub assigned roles in AAD RBAC (these cannot be transferred)
This would be exported in the “subid-rbac-assignments.csv”
# of managed identities used as Federated Identity Credentials in app registrations in AAD
This would be exported in the “AAD-fic-appreg.csv”

This is already included in the scope of the “resources-export.csv” export
# of Storage accounts with local AAD-based authZ enabled in this sub

This could be a column in the “resources-export.csv” export showing “# of resources with AuthZ enabled”
# of SQL with AAD authN enabled in this sub

This could be a column in the “resources-export.csv” export showing “# of resources with AuthZ enabled”
# of MySQL with AAD authN enabled in this sub
This could be a column in the “resources-export.csv” export showing “# of resources with AuthZ enabled”
# of Cosmos DB with local RBAC enabled in this sub
This could be a column in the “resources-export.csv” export showing “# of resources with Local RBAC enabled”
# of AKS clusters in this sub
This is already included in the scope of the “resources-export.csv” export
# of AAD Domain Services in this sub (this is fatal, we won’t move these ever)
This is already included in the scope of the “resources-export.csv” export
# of Microsoft Dev Box in this sub
This is already included in the scope of the “resources-export.csv” export
# of Azure Deployment Environments in this sub
"""


def _enumerate_cosmosdb_role_assignments(cosmosdb_client: CosmosDBManagementClient, resource_group_name: str,
                                         account_name: str) -> list:
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
        cosmos_rbac_role_assignments.append(role)
        print(r)
    return cosmos_rbac_role_assignments


def get_cosmos_db(credential: AzureCliCredential, subscription_id: str) -> str | list:
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
                                                                            results.data[0]['name'])
        return results.data[0]['name'], cosmos_rbac_role_assignments
    else:
        return None, cosmos_rbac_role_assignments


def create_path(subscription: str) -> str:
    path = os.getcwd() + "/data" + "/" + subscription
    # Check whether the specified path exists or not

    if not os.path.exists(path):
        # Create a new directory because it does not exist
        os.makedirs(path)
        print(f"Creating {path} directory")
    else:
        print(f"Using existing {path} directory")
    return path


def get_sql_servers(credential: AzureCliCredential, subscription_id: str) -> list:
    query = "resources \
    | where type in ('microsoft.sql/servers') \
    | extend properties=parse_json(properties) \
    | extend activeDirectoryAuth=properties['administrators']['azureADOnlyAuthentication'] \
    | extend administratorType=properties['administrators']['administratorType'] \
    | extend objectid=properties['administrators']['sid'] \
    | project name, type, location, resourceGroup, subscriptionId, activeDirectoryAuth, administratorType, objectid"

    results = get_resources(credential, query, subscription_id)
    print(f'Total Azure SQL DB Servers: {len(results.data)}')
    for item in results.data:
        print(item)
    return results.data


def get_postgres_flexible_servers(credential: AzureCliCredential, subscription_id: str) -> list:
    query = "resources \
    | where type in ('microsoft.dbforpostgresql/flexibleservers') \
    | extend config=parse_json(properties) \
    | extend activeDirectoryAuth=config['authConfig']['activeDirectoryAuth'] \
    | extend passwordAuth=config['authConfig']['passwordAuth'] \
    | project name, type, location, resourceGroup, subscriptionId, activeDirectoryAuth, passwordAuth"

    results = get_resources(credential, query, subscription_id)
    print(f'Total Postgres Flexible Servers: {len(results.data)}')
    for item in results.data:
        print(item)
    return results.data


# of Key Vaults in this sub
def get_all_vaults(credential: AzureCliCredential, subscription_id: str) -> list:
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
    | project name, id, type, tenantId, location, resourceGroup, subscriptionId, access_policies"

    results = get_resources(credential, query, subscription_id)
    print(f'Total Key Vaults: {len(results.data)}')
    for item in results.data:
        print(item)
    return results.data


def get_resources(credential: AzureCliCredential, str_query: str, subscription_id: str) -> arg.models.QueryResponse:
    """
    This function will return the results of the query.
    It uses the AzureCLI Credential to authenticate to Azure and query the Azure Resource Graph
    :param subscription_id:
    :param credential:
    :param str_query:
    :return: QueryResponse
    """
    # Get your credentials from Azure CLI (development only!) and get your subscription list

    # TODO
    # 1. Add a check to ensure that the Azure CLI is installed
    # 2. Add a check to ensure that the user has the proper permissions to query the Azure Resource Graph
    # 3. add logic to supply identity and subscription list
    # credential = generate_auth_credentials()

    # Create Azure Resource Graph client and set options
    arg_client = arg.ResourceGraphClient(credential)
    arg_query_options = arg.models.QueryRequestOptions(result_format="objectArray")
    # Create query
    arg_query = arg.models.QueryRequest(subscriptions=[subscription_id], query=str_query, options=arg_query_options)
    # Run query
    arg_results = arg_client.resources(arg_query)

    # Return Python Arg Result Object

    return arg_results


def get_subscription_data(credential) -> list | list:
    """
    returns subscription list and subscription raw data. This returns only subscription that a user has access to.
    """
    subs_client = SubscriptionClient(credential)
    # get the list of subscriptions the user has access to
    subs_raw = [sub.as_dict() for sub in subs_client.subscriptions.list()]
    # get the list of subscription ids as a list
    subs_list = [s.get('subscription_id') for s in subs_raw]
    return subs_list, subs_raw


def generate_rbac_per_sub(credential: AzureCliCredential, subscription_id: str) -> list:
    """
    generate RBAC assignments for each MI per subscription
    :return:
    """
    # get list of subscriptions
    subList, subRaw = get_subscription_data(credential)

    # loop through list of subscriptions
    for sub in subList:
        # get list of managed identities in sub
        # get list of RBAC assignments for each managed identity
        # enumerate_rbac_roles(object_id, sub)
        pass
    # get list of managed identities in sub

    # get list of RBAC assignments for each managed identity

    return []


def generate_auth_credentials():
    """
    This function will generate the credentials for the Azure using the ALI Credential
    :return: ALI Credential
    """
    credential = AzureCliCredential()
    return credential


def enumerate_rbac_roles(credential: AzureCliCredential, subscription_id: str, object_id: str) -> list:
    """
    TO DO - get all RBAC assignments for a given object_id
    :param subscription_id:
    :param credential:
    :param object_id:
    :return:
    """
    # get credential
    authorization_client = AuthorizationManagementClient(credential, subscription_id)
    results = authorization_client.role_assignments.list_for_scope(scope='/subscriptions/' + subscription_id,
                                                                   filter=f"principalId eq '{object_id}'")
    roles = []
    print('*-' * 25)
    # TO DO write output to JSON object
    for item in results:
        dict_obj = {'name': item.name, 'role_definition_id': item.role_definition_id, 'scope': item.scope,
                    'principal_id': item.principal_id, 'principal_type': item.principal_type}
        roles.append(dict_obj)
        print(dict_obj)
        print('*-' * 25)
    return roles


def get_aks_clusters(credential: AzureCliCredential, subscription_id: str) -> list:
    """
    This function will return all of the AKS clusters in the subscription
    :param credential:
    :param subscription_id:
    :return:
    """
    query = "resources \
    | where type == 'microsoft.containerservice/managedclusters'  \
    | project name, id, type, tenantId, location, resourceGroup, subscriptionId, identity"
    results = get_resources(credential, query, subscription_id)
    print(f'Total AKS Clusters: {len(results.data)}')
    for item in results.data:
        print(item)
    # write_to_csv('raw-aks-resources-export.csv', results.data)
    return results.data


def get_all_managed_identities(credential: AzureCliCredential, subscription_id: str) -> list:
    """
    :return: list of all managed identities
    """
    query = "resources \
    | where type == 'microsoft.managedidentity/userassignedidentities' or \
    identity contains 'SystemAssigned' \
    | extend managedidentity=iff(isnull(identity), properties, identity) \
    | extend identityType=iff(isnull(identity), 'UserAssignedIdentity', 'SystemAssignedIdentity') \
    | extend principalId=parse_json(managedidentity)['principalId'] \
    | project name, id, type, tenantId, location, resourceGroup, subscriptionId, managedidentity, principalId, identityType"
    results = get_resources(credential, query, subscription_id)
    print(f'Total Managed Identities: {len(results.data)}')
    for item in results.data:
        print(item)
    return results.data


def pre_check() -> bool:
    """
    TODO
    Check to ensure that the required modules are installed
    Checks whether proper permissions are set
    :return: bool
    """
    return True


# generate a function that writes to a csv file

def write_to_csv(file_name: str, data: list, subscription: str, *args, **kwargs) -> None:
    """
    @param fname: string, name of file to write
    @param data: list of list of items
    Write data to file
    :param subscription:
    :param file_name:

    """
    data_dir = create_path(subscription)
    file_name = subscription[-6:] + "-" + file_name
    full_file_name = data_dir + "/" + file_name
    with open(full_file_name, 'w', newline='\n') as csv_file:
        # csvwriter = csv.writer(csv_file, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        if data is None or len(data) == 0:
            csv_file.write('No Resources Found')
            return
        csvwriter = csv.DictWriter(csv_file, fieldnames=data[0].keys())
        csvwriter.writeheader()
        for row in data:
            csvwriter.writerow(row)


def gather_inventory() -> None:
    # Use a breakpoint in the code line below to debug your script.
    """
    This function will gather the inventory for Azure Managed Identities
    :return:
    """


def execute_discovery() -> None:
    """
    This function will execute the discovery process
    :return:
    """
    # do all of this for a specific subscription id
    write_to_csv('raw-vaults-export.csv', get_all_vaults())
    write_to_csv('raw-resources-export.csv', get_all_managed_identities())
    write_to_csv('raw-aks-resources-export.csv', get_aks_clusters())
    write_to_csv('raw-postgres-flexible-servers-export.csv', get_postgres_flexible_servers())
    # get rbac assignments for a specific managed identity within a subscription id
    enumerate_rbac_roles('0efc4cd0-2507-4a4b-959b-96a110fb8583', '/subscriptions/90376dc6-e4a0-49c3-930d-38ee8e2bafa4')


def execute_report() -> None:
    """
    This function will execute the report generation
    :return:
    """


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # pre_check()
    # gather_inventory()
    # execute_discovery()
    # execute_report()
    creds = generate_auth_credentials()  # do this once
    sub_list, list_sub_dict = get_subscription_data(creds)
    # print(sub_list)
    # print(list_sub_dict)
    for sub in sub_list:
        if sub != '7dc3c9b5-bb4b-4193-8862-7a02bdf9a001':
            # managed_identities = get_all_managed_identities(creds, sub)
            write_to_csv('raw-resources-export.csv', get_all_managed_identities(creds, sub), sub)
            # for mi in managed_identities:
            #     write_to_csv("mi-" + mi['principalId'][-6:] + '-raw-rbac-assignments-export.csv',
            #                  enumerate_rbac_roles(creds, sub, mi['principalId']), sub)
            #     # enumerate_rbac_roles(creds, sub, mi['principalId'])
            # # print(mi['principalId'])
            #
            # write_to_csv('raw-vaults-export.csv', get_all_vaults(creds, sub), sub)
            # get_aks_clusters(creds, sub)
            # get_postgres_flexible_servers(creds, sub)
            # get_sql_servers(creds, sub)
            # get_sql_managed_instances(creds, sub)
            acct, rbac_roles = get_cosmos_db(creds, sub)
            if acct is not None:
                write_to_csv(acct + '-raw-cosmosdb-export.csv', rbac_roles, sub)

            # print(test)
