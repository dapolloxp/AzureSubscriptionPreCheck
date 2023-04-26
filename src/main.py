import azure.mgmt.resourcegraph as arg
import csv
# Import specific methods and models from other libraries
from azure.mgmt.resource import SubscriptionClient
from azure.identity import AzureCliCredential
import os

"""
# of managed identities in this sub
UAMI - UserAssigned (microsoft.managedidentity/userassignedidentities) is already included in the scope of the “resources-export.csv” export
SAMI - SystemAssigned needs to be captured. This can be the # of resources of a given type with SAMI, a column for the ResourceType in the “resources-export.csv” export
# of Azure RBAC assignments in this sub direct to managed identities (as opposed to via a group)
This would be exported in the “subid-rbac-assignements.csv”
# of managed identities in this sub assigned roles in AAD RBAC (these cannot be transferred)
This would be exported in the “subid-rbac-assignments.csv”
# of managed identities used as Federated Identity Credentials in app registrations in AAD
This would be exported in the “AAD-fic-appreg.csv”
# of Key Vaults in this sub
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

def createPath():
    path = os.getcwd() + "/data"
    # Check whether the specified path exists or not

    if not os.path.exists(path):
        # Create a new directory because it does not exist
        os.makedirs(path)
        print(f"Creating {path} directory")
    else:
        print(f"Using existing {path} directory")
    return path
def get_resources(strQuery):
    """
    This function will return the results of the query.
    It uses the AzureCLI Credential to authenticate to Azure and query the Azure Resource Graph
    :param strQuery:
    :return: QueryResponse
    """
    # Get your credentials from Azure CLI (development only!) and get your subscription list

    # TODO
    # 1. Add a check to ensure that the Azure CLI is installed
    # 2. Add a check to ensure that the user has the proper permissions to query the Azure Resource Graph
    # 3. add logic to supply identity and subscription list
    credential = AzureCliCredential()
    subsClient = SubscriptionClient(credential)
    subsRaw = []
    for sub in subsClient.subscriptions.list():
        subsRaw.append(sub.as_dict())
    subsList = []
    for sub in subsRaw:
        subsList.append(sub.get('subscription_id'))

    # Create Azure Resource Graph client and set options
    argClient = arg.ResourceGraphClient(credential)
    argQueryOptions = arg.models.QueryRequestOptions(result_format="objectArray")

    # Create query
    argQuery = arg.models.QueryRequest(subscriptions=subsList, query=strQuery, options=argQueryOptions)

    # Run query
    argResults = argClient.resources(argQuery)

    # Return Python Arg Result Object

    return argResults


def get_aks_clusters():

    query = "resources | where type == 'microsoft.containerservice/managedclusters' | project name, id, type, tenantId, location, resourceGroup, subscriptionId, identity"
    results = get_resources(query)
    print(f'Total AKS Clusters: {len(results.data)}')
    for item in results.data:
        print(item)
    write_to_csv('raw-aks-resources-export.csv', results.data)
def get_all_managed_identities():
    """

    :return: list of all managed identities
    """
    query = "resources | where type == 'microsoft.managedidentity/userassignedidentities' or \
    identity contains 'SystemAssigned'| extend managedidentity=iff(isnull(identity), properties, identity) \
    | extend identityType=iff(isnull(identity), 'UserAssignedIdentity', 'SystemAssignedIdentity') \
    | project name, id, type, tenantId, location, resourceGroup, subscriptionId, managedidentity, identityType"
    results = get_resources(query)
    print(f'Total Managed Identities: {len(results.data)}')
    for item in results.data:
        print(item)
    write_to_csv('resources-export.csv', results.data)

def pre_check():
    """
    TODO
    Check to ensure that the required modules are installed
    Checks whether proper permissions are set
    :return: bool
    """
    return True
# generate a function that writes to a csv file

def write_to_csv(file_name, data, *args, **kwargs):
    """
    @param fname: string, name of file to write
    @param data: list of list of items

    Write data to file
    """
    dataDir = createPath()
    full_file_name = dataDir + "/" + file_name
    with open(full_file_name, 'w', newline='\n') as csv_file:
        #csvwriter = csv.writer(csv_file, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        csvwriter = csv.DictWriter(csv_file, fieldnames=data[0].keys())
        csvwriter.writeheader()
        for row in data:
            csvwriter.writerow(row)

def gather_inventory():
    # Use a breakpoint in the code line below to debug your script.
    """
    This function will gather the inventory for Azure Managed Identities
    :return:
    """
def execute_discovery():
    """
    This function will execute the discovery process
    :return:
    """
def execute_report():
    """
    This function will execute the report generation
    :return:
    """

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    pre_check()
    gather_inventory()
    execute_discovery()
    execute_report()
    get_all_managed_identities()
    get_aks_clusters()


