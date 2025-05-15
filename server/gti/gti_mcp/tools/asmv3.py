import typing
import urllib.parse  # For URL encoding the search string
import logging
import asyncio

from mcp.server.fastmcp import Context

# Assuming these imports exist based on your example
from .. import utils  # Or adjust path as needed
from ..server import server, vt_client

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


async def fetch_with_retries(client_call, max_retries: int = 3, retry_delay: float = 2.0):
    """
    A helper function that retries an asynchronous HTTP call if the response is not 200.
    
    Args:
        client_call: The asynchronous function to call (e.g., vt_client.get_async()).
        max_retries: Maximum number of retries for the request.
        retry_delay: Delay in seconds between retries.
    
    Returns:
        The data from the successful response.
    
    Raises:
        Exception: If all retries fail.
    """
    for attempt in range(max_retries):
        try:
            response = await client_call()
            if response.status == 200:
                # Parse JSON only if the response is successful
                return await response.json_async()
            else:
                logger.warning(
                    f"Attempt {attempt + 1}/{max_retries}: Received non-200 status code {response.status}"
                )
        except Exception as e:
            logger.error(f"Attempt {attempt + 1}/{max_retries}: Error during request - {e}")
        
        # Wait before retrying
        if attempt < max_retries - 1:
            await asyncio.sleep(retry_delay)
    
    # If all retries fail, raise an exception
    raise Exception(f"Request failed after {max_retries} attempts.")


@server.tool()
async def get_asm_issue_details(id: str, ctx: Context) -> typing.Dict[str, typing.Any]:
    """
    Retrieves the detailed information for a specific Attack Surface Management (ASM) issue
    identified by its unique ID from Google Threat Intelligence (VirusTotal).
    
    Args:
        id (required): The unique identifier of the ASM issue.
    
    Returns:
        A dictionary containing the detailed attributes and data for the requested ASM issue.
    """
    api_path = f"/asm/issues/{id}"
    try:
        data = await fetch_with_retries(
            lambda: vt_client(ctx).get_async(api_path)
        )
        return data
    except Exception as e:
        logger.error(f"Error fetching ASM issue details for ID {id}: {e}")
        return {"error": f"Failed to fetch ASM issue details for ID {id}. Reason: {str(e)}"}


@server.tool()
async def search_asm_issues(
    query: str, ctx: Context, limit: int = 100, cursor: typing.Optional[str] = None
) -> typing.Dict[str, typing.Any]:
    """
    Searches for Attack Surface Management (ASM) issues in Google Threat Intelligence
    (VirusTotal) based on a provided search query string.

    Args:
        query (required): The search string used to find ASM issues.
                          Construct this string using keyword:value pairs.
                          Combine multiple pairs with spaces (implies AND).
                          Example: 'status_new:open severity_gte:3 entity_type:Domain'
        limit (optional): The maximum number of issues to return. Defaults to 100. Max is 1000.
        cursor (optional): Pagination cursor from a previous result's 'meta.next_page_token'.

    Returns:
        A dictionary representing the API's JSON response.

    ------------------------------------------------------------------------------------
    How to construct the 'query' parameter:
    ------------------------------------------------------------------------------------

    Valid Search Keywords ('query' parameter):
        collection:name_123k221
        name:string
        uid:12345
        tag:tag_name
        last_seen_after:YYYY-MM-DD
        last_seen_before:YYYY-MM-DD
        first_seen_after:YYYY-MM-DD
        entity_uid:12345
        entity_type:string (e.g., ApiEndpoint, AppEndpoint, AutonomousSystem, AwsEC2Instance,
                           AwsRdsDbInstance, AwsS3Bucket, AzureStorageAccount, AzureVirtualMachine,
                           DnsRecord, Domain, EmailAddress, GcpApiGateway, GcpAppEngineApplication,
                           GcpCloudFunction, GcpCloudSQLInstance, GcpComputeEngineInstance,
                           GcpStorageBucket, GithubAccount, GithubRepository, IpAddress,
                           Nameserver, NetBlock, NetworkService, SslCertificate, UniqueKeyword,
                           UniqueToken, Uri)
        entity_name:string
        scoped:true | false
        severity:integer (1-5)
        severity_lte:integer (1-5) (less than or equal to)
        severity_gte:integer (1-5) (greater than or equal to)
        status_new:open | closed
        status_detailed:string (e.g., open_triaged, open_in_progress, closed_mitigated,
                               closed_resolved, closed_duplicate, closed_out_of_scope,
                               closed_benign, closed_risk_accepted, closed_false_positive,
                               closed_no_reproduce, closed_tracked_externally)

    Example Query:
        'status_new:open entity_type:Domain entity_name:example.com severity_gte:3 last_seen_after:2024-01-15'
    ------------------------------------------------------------------------------------
    """
    # URL-encode the query string part that goes into the path
    encoded_query_path_segment = urllib.parse.quote_plus(query)
    api_path = f"/asm/search/issues/{encoded_query_path_segment}"

    params = {"page_size": limit}
    if cursor:
        params["page_token"] = cursor

    try:
        data = await fetch_with_retries(
            lambda: vt_client(ctx).get_async(api_path, params=params)
        )
        return data
    except Exception as e:
        logger.error(f"Error searching ASM issues with query '{query}': {e}")
        return {"error": f"Failed to search ASM issues with query '{query}'. Reason: {str(e)}"}
