import csv
import os
import datetime
from azure.mgmt.msi import ManagedServiceIdentityClient  # async libary
from azure.cli.core import get_default_cli
import azure.mgmt.resourcegraph as arg
from azure.identity import AzureCliCredential
from azure.mgmt.authorization import AuthorizationManagementClient
# Import specific methods and models from other libraries
from azure.mgmt.resource import SubscriptionClient
from azure.cosmos import CosmosClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.graphrbac import GraphRbacManagementClient
from azure.core.exceptions import HttpResponseError
import azure
import shortuuid


"""

# of Azure RBAC assignments in this sub direct to managed identities (as opposed to via a group)
This would be exported in the “subid-rbac-assignements.csv” DONE

# of managed identities in this sub assigned roles in AAD RBAC (these cannot be transferred)
This would be exported in the “subid-rbac-assignments.csv” DONE

# of managed identities used as Federated Identity Credentials in app registrations in AAD
This would be exported in the “AAD-fic-appreg.csv” DONE

This is already included in the scope of the “resources-export.csv” export
# of Storage accounts with local AAD-based authZ enabled in this sub - WIP

This could be a column in the “resources-export.csv” export showing “# of resources with AuthZ enabled”
# of SQL with AAD authN enabled in this sub - DONE

This could be a column in the “resources-export.csv” export showing “# of resources with AuthZ enabled”
# of MySQL with AAD authN enabled in this sub - WIP

This could be a column in the “resources-export.csv” export showing “# of resources with AuthZ enabled”
# of Cosmos DB with local RBAC enabled in this sub -- DONE

This could be a column in the “resources-export.csv” export showing “# of resources with Local RBAC enabled”
# of AKS clusters in this sub -- DONE
This is already included in the scope of the “resources-export.csv” export
# of AAD Domain Services in this sub (this is fatal, we won’t move these ever) - TO DO
This is already included in the scope of the “resources-export.csv” export
# of Microsoft Dev Box in this sub - TO DO
This is already included in the scope of the “resources-export.csv” export
# of Azure Deployment Environments in this sub
"""


def _get_mi_associations(credential: AzureCliCredential,
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
        print (e.message)
        return [], 0, []
    except:
        print(f'Unexpected error: {sys.exc_info()[0]}')
        return [], 0, []

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

    return cosmos_rbac_role_assignments


def get_cosmos_db(credential: AzureCliCredential, subscription_id: str) -> str | list | int:
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
        return results.data[0]['name'], cosmos_rbac_role_assignments, len(results.data)
    else:
        return None, cosmos_rbac_role_assignments, len(results.data)


def create_path(subscription: str) -> str:
    path = os.getcwd() + os.sep + "data" + os.sep + subscription
    # Check whether the specified path exists or not

    if not os.path.exists(path):
        # Create a new directory because it does not exist
        os.makedirs(path)
        print(f"Creating {path} directory")
    else:
        # print(f"Using existing {path} directory")
        pass
    return path


def get_sql_servers(credential: AzureCliCredential, subscription_id: str) -> list | int:
    query = "resources \
    | where type in ('microsoft.sql/servers') \
    | extend properties=parse_json(properties) \
    | extend activeDirectoryAuth=properties['administrators']['azureADOnlyAuthentication'] \
    | extend administratorType=properties['administrators']['administratorType'] \
    | extend objectid=properties['administrators']['sid'] \
    | project name, type, location, resourceGroup, subscriptionId, activeDirectoryAuth, administratorType, objectid"

    results = get_resources(credential, query, subscription_id)

    return results.data, len(results.data)


def get_postgres_flexible_servers(credential: AzureCliCredential, subscription_id: str) -> list:
    query = "resources \
    | where type in ('microsoft.dbforpostgresql/flexibleservers') \
    | extend config=parse_json(properties) \
    | extend activeDirectoryAuth=config['authConfig']['activeDirectoryAuth'] \
    | extend passwordAuth=config['authConfig']['passwordAuth'] \
    | project name, type, location, resourceGroup, subscriptionId, activeDirectoryAuth, passwordAuth"

    results = get_resources(credential, query, subscription_id)
    print(f'Total Postgres Flexible Servers: {len(results.data)}')
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

    return arg_results


def get_subscription_data(credential) -> list | list:
    """
    returns subscription list and subscription raw data. This returns only subscription that a user has access to.
    """
    subs_client = SubscriptionClient(credential)
    # get the list of subscriptions the user has access to
    subs_raw = [s.as_dict() for s in subs_client.subscriptions.list()]
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

    # '/subscriptions/021e08c7-8839-4dc6-940d-f4219dc5dcb1/providers/Microsoft.Authorization/roleDefinitions/b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
    # TO DO write output to JSON object

    for item in results:
        role_def = authorization_client.role_definitions.get_by_id(item.role_definition_id)
        dict_obj = {'name': item.name, 'role_definition_id': item.role_definition_id, 'role_name': role_def.role_name,
                    'role_type': role_def.role_type, 'scope': item.scope, 'principal_id': item.principal_id,
                    'principal_type': item.principal_type}
        if item.scope.startswith("/subscriptions"):
            roles.append(dict_obj)

    return roles


def get_aks_clusters(credential: AzureCliCredential, subscription_id: str) -> list | int:
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

    return results.data, len(results.data)


def get_all_managed_identities(credential: AzureCliCredential, subscription_id: str) -> list | int:
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

    for item in results.data:

        item['federated_identity_credentials'] = []
        item['associations'] = []
        item['associations_count'] = 0
        item['associations_sub_ids'] = []
        if item.get('identityType') != 'SystemAssignedIdentity':
            fed_creds, fed_creds_count = get_managed_identity_details(credential,
                                                                      subscription_id,
                                                                      item.get('name'),
                                                                      item.get('resourceGroup'))
            if fed_creds_count > 0:
                # print(f'Federated Identity Credentials: {fed_creds_count}')
                item['federated_identity_credentials'] = fed_creds

            associations, association_count, total_subs = _get_mi_associations(credential,
                                                                               subscription_id,
                                                                               item.get('resourceGroup'),
                                                                               item.get('name'))
            if len(associations) > 0:
                item['associations'] = associations[0]
                item['associations_count'] = association_count
                item['associations_sub_ids'] = total_subs

            print(f'Found {association_count} associations for {item.get("name")} in the follwoing subs: {total_subs}')
    return results.data, len(results.data)



def get_managed_identity_details(credential: AzureCliCredential, subscription_id: str, resource_name: str,
                                 resource_group: str) -> list | int:
    """
    This function will return the details of a managed identity
    :param credential:
    :param subscription_id:
    :param object_id:
    :return:
    """
    client = ManagedServiceIdentityClient(credential, subscription_id)
    if (hasattr(client, 'federated_identity_credentials')):
        num_fed_creds = 0
        result = client.federated_identity_credentials.list(resource_group, resource_name)
        if result:
            results_dict_list = [item.as_dict() for item in result]
            num_fed_creds = len(results_dict_list)
        print(f'\tFederated Identity Credentials for {resource_name}: {num_fed_creds}')
        return results_dict_list, num_fed_creds
    else:
        return [], 0


# generate a function that writes to a csv file

def write_to_csv(file_name: str, data: list, subscription: str, *args, **kwargs) -> None:
    """
    @param fname: string, name of file to write
    @param data: list of list of items
    Write data to file
    :param subscription:
    :param file_name:

    """

    # TODO - move filename stuff outside of the function. This should just write out data
    data_dir = create_path(subscription)
    file_name = subscription[-6:] + "-" + file_name
    full_file_name = data_dir + os.sep + file_name

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
    write_to_csv('raw-vaults-export-' + suffix + '.csv', get_all_vaults())
    write_to_csv('raw-resources-export-' + suffix + '.csv', get_all_managed_identities())
    write_to_csv('raw-aks-resources-export-' + suffix + '.csv', get_aks_clusters())
    write_to_csv('raw-postgres-flexible-servers-export-' + suffix + '.csv', get_postgres_flexible_servers())
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
    suffix = datetime.datetime.now().strftime("%Y%m%d") + '-' + shortuuid.uuid()[:8]

    for sub in sub_list:
        if sub != '7dc3c9b5-bb4b-4193-8862-7a02bdf9a001':

            # Print Subscription Header
            print("##################################################")
            print("Subscription: " + sub)
            print("##################################################")

            ### Get all RBAC permissions at the subscription level

            sub_rbac_roles = enumerate_rbac_roles(creds, sub, None)
            if sub_rbac_roles is not None and len(sub_rbac_roles) > 0:
                write_to_csv("sub-" + sub[-6:] + '-raw-rbac-assignments-export-' + suffix + '.csv', sub_rbac_roles, sub)

            ### Get all managed identities and write to csv
            # print(f'Found {association_count} associations for {item.get("name")} in the follwoing subs: {total_subs}')
            # results.data, len(results.data), associations, association_count, total_subs
            managed_identities, mi_count = get_all_managed_identities(creds, sub)
            print(f'Total Managed Identities: {mi_count}')
            if len(managed_identities) > 0:
                write_to_csv('raw-resources-export-' + suffix + '.csv', managed_identities, sub)

            fn = 'mi-raw-rbac-assignments-export-' + suffix + '.csv'
            for mi in managed_identities:
                if not (mi['principalId'] is None or mi['principalId'] == ''):
                    rbac_roles = enumerate_rbac_roles(creds, sub, mi['principalId'])
                    if rbac_roles is not None and len(rbac_roles) > 0:
                        write_to_csv(fn, rbac_roles, sub)

            ### Get all key vaults and write to csv
            #
            vaults = get_all_vaults(creds, sub)

            if len(vaults) > 0:
                write_to_csv('raw-vaults-export-' + suffix + '.csv', vaults, sub)

            aks_clusters, num_aks_clusters = get_aks_clusters(creds, sub)
            print(f'Total AKS Clusters: {num_aks_clusters}')
            if len(aks_clusters) > 0:
                write_to_csv('raw-aks-resources-export-' + suffix + '.csv', aks_clusters, sub)

            postgres_flex_servers = get_postgres_flexible_servers(creds, sub)
            if len(postgres_flex_servers) > 0:
                write_to_csv('raw-postgres-flexible-servers-export-' + suffix + '.csv', postgres_flex_servers, sub)

            azure_sql_servers, num_azure_sql_servers = get_sql_servers(creds, sub)
            print(f'Total Azure SQL DB Servers: {num_azure_sql_servers}')
            if len(azure_sql_servers) > 0:
                write_to_csv('raw-sql-servers-export-' + suffix + '.csv', azure_sql_servers, sub)

            # get_sql_managed_instances(creds, sub)

            acct, rbac_roles, num_cosmos_accounts = get_cosmos_db(creds, sub)
            print(f'Total Cosmos DB Accounts: {num_cosmos_accounts}')
            if acct is not None and rbac_roles is not None and len(rbac_roles) > 0:
                write_to_csv(acct + '-raw-cosmosdb-export-' + suffix + '.csv', rbac_roles, sub)
