import typing
import urllib.parse # For URL encoding if needed, though not for query params here
import logging
import asyncio

from mcp.server.fastmcp import Context

# Assuming these imports exist based on your example structure
# If this file is, for example, server/gti/gti_mcp/tools/dtm_tools.py
from .. import utils # Or adjust path as needed if fetch_with_retries is there
from ..server import server, vt_client # Assuming vt_client is the API client

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# Re-defining fetch_with_retries here for completeness, 
# but ideally it would be in a shared utils module.
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
    last_exception = None
    for attempt in range(max_retries):
        try:
            response = await client_call()
            if response.status == 200:
                # Parse JSON only if the response is successful
                return await response.json_async()
            else:
                logger.warning(
                    f"Attempt {attempt + 1}/{max_retries}: Received non-200 status code {response.status}. Response: {await response.text()}"
                )
                last_exception = Exception(f"Received non-200 status code {response.status}")
        except Exception as e:
            logger.error(f"Attempt {attempt + 1}/{max_retries}: Error during request - {str(e)}")
            last_exception = e
        
        # Wait before retrying
        if attempt < max_retries - 1:
            await asyncio.sleep(retry_delay)
    
    # If all retries fail, raise the last known exception
    raise Exception(f"Request failed after {max_retries} attempts. Last error: {str(last_exception)}")


@server.tool()
async def list_dtm_alerts(
    ctx: Context,
    sort_by: typing.Optional[str] = "created_at",
    sort_order: typing.Optional[str] = "desc",
    limit: typing.Optional[int] = 10, # API param is 'size'
    monitor_ids: typing.Optional[typing.List[str]] = None, # API param 'monitor_id', repeatable
    include_refs: typing.Optional[bool] = True, # API param 'refs'
    replace_links: typing.Optional[bool] = False,
    include_monitor_name: typing.Optional[bool] = False, # API param 'monitor_name'
    has_analysis: typing.Optional[bool] = None,
    include_buckets: typing.Optional[bool] = False, # API param 'buckets'
    since_date: typing.Optional[str] = None, # API param 'since', RFC3339 date-time string
    until_date: typing.Optional[str] = None, # API param 'until', RFC3339 date-time string
    cursor: typing.Optional[str] = None, # API param 'page'
    truncate_length: typing.Optional[int] = None, # API param 'truncate'
    statuses: typing.Optional[typing.List[str]] = None, # API param 'status', repeatable
    alert_types: typing.Optional[typing.List[str]] = None, # API param 'alert_type', repeatable
    search_query: typing.Optional[str] = None, # API param 'search'
    match_values: typing.Optional[typing.List[str]] = None, # API param 'match_value', repeatable
    tags: typing.Optional[typing.List[str]] = None, # repeatable
    search_encoding: typing.Optional[str] = None, # e.g., 'base64'
    severities: typing.Optional[typing.List[str]] = None, # API param 'severity', repeatable
    sanitize: typing.Optional[typing.Union[bool, str, typing.List[str]]] = None, # API param can be "true" or JSON path(s)
    mscore_gte: typing.Optional[int] = None
) -> typing.Dict[str, typing.Any]:
    """
    Retrieves a list of DTM (Detection & Threat Monitoring) alerts from VirusTotal 
    for the current organization, with extensive filtering and sorting capabilities.

    Args:
        ctx: The MCP context.
        sort_by (optional): Alert field to sort by. Defaults to 'created_at'.
                          Valid values: 'updated_atid', 'created_at', 'updated_at', 'monitor_id'.
        sort_order (optional): Order for sorting. Defaults to 'desc'.
                             Valid values: 'asc', 'desc'.
        limit (optional): Number of alerts per page. Defaults to 10. Max 100. (API param 'size')
        monitor_ids (optional): List of monitor IDs to filter alerts. (API param 'monitor_id')
        include_refs (optional): If False, 'doc', 'labels', 'topics' are excluded. Defaults to True. (API param 'refs')
        replace_links (optional): If True, links in alert doc are sanitized. Defaults to False.
        include_monitor_name (optional): If True, monitor name is returned. Defaults to False. (API param 'monitor_name')
        has_analysis (optional): If True, only alerts with analysis are returned.
        include_buckets (optional): If True, alert buckets for aggregated alerts are returned. Defaults to False. (API param 'buckets')
        since_date (optional): Start date for alerts (RFC3339 format, e.g., '2023-01-01T00:00:00Z'). (API param 'since')
        until_date (optional): End date for alerts (RFC3339 format, e.g., '2023-01-15T23:59:59Z'). (API param 'until')
        cursor (optional): Pagination cursor (page ID from previous response). (API param 'page')
        truncate_length (optional): Length to truncate document fields. (API param 'truncate')
        statuses (optional): List of alert statuses to filter by. (API param 'status')
                          Valid values: 'new', 'read', 'escalated', 'in_progress', 'closed', 
                                        'no_action_required', 'duplicate', 'not_relevant', 'tracked_external'.
        alert_types (optional): List of alert types to filter by. (API param 'alert_type')
                             Valid values: 'Compromised Credentials', 'Domain Discovery', 'Forum Post', 
                                           'Message', 'Paste', 'Shop Listing', 'Tweet', 'Web Content'.
        search_query (optional): Lucene query string for alert/doc contents. (API param 'search')
        match_values (optional): List of specific match values to filter alerts. (API param 'match_value')
        tags (optional): List of tags to filter alerts by.
        search_encoding (optional): Encoding of 'search_query' if not plain text (e.g., 'base64').
        severities (optional): List of severities to filter by. (API param 'severity')
                            Valid values: 'high', 'medium', 'low'.
        sanitize (optional): If 'true' (str) or True (bool), HTML content is sanitized. 
                           Can also be a JSON path string or list of JSON path strings to sanitize.
        mscore_gte (optional): Filter alerts with mscores >= this value (0-100).

    Returns:
        A dictionary containing the list of DTM alerts and pagination metadata.
    """
    api_path = "/dtm/alerts"
    params: typing.Dict[str, typing.Any] = {}

    if sort_by is not None:
        params["sort"] = sort_by
    if sort_order is not None:
        params["order"] = sort_order
    if limit is not None:
        params["size"] = min(limit, 100) # Enforce API max
    if monitor_ids:
        params["monitor_id"] = monitor_ids
    if include_refs is not None:
        params["refs"] = str(include_refs).lower() # API expects "true" or "false" strings
    if replace_links is not None:
        params["replace_links"] = str(replace_links).lower()
    if include_monitor_name is not None:
        params["monitor_name"] = str(include_monitor_name).lower()
    if has_analysis is not None:
        params["has_analysis"] = str(has_analysis).lower()
    if include_buckets is not None:
        params["buckets"] = str(include_buckets).lower()
    if since_date:
        params["since"] = since_date
    if until_date:
        params["until"] = until_date
    if cursor: # This API uses 'page' for cursor/pagination token
        params["page"] = cursor
    if truncate_length is not None:
        params["truncate"] = truncate_length
    if statuses:
        params["status"] = statuses
    if alert_types:
        params["alert_type"] = alert_types
    if search_query:
        params["search"] = search_query
    if match_values:
        params["match_value"] = match_values
    if tags:
        params["tags"] = tags
    if search_encoding:
        params["search_encoding"] = search_encoding
    if severities:
        params["severity"] = severities
    if sanitize is not None:
        if isinstance(sanitize, bool):
            params["sanitize"] = str(sanitize).lower()
        else: # str or List[str]
            params["sanitize"] = sanitize
    if mscore_gte is not None:
        params["mscore_gte"] = mscore_gte
    
    # Remove params with None values if any were missed (though explicit checks above are better)
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Requesting DTM alerts with params: {params}")
        data = await fetch_with_retries(
            lambda: vt_client(ctx).get_async(api_path, params=params)
        )
        return data
    except Exception as e:
        logger.error(f"Error listing DTM alerts: {str(e)}")
        # Mask sensitive parts of params if necessary, though here it's mostly filters
        return {"error": f"Failed to list DTM alerts. Reason: {str(e)}"}

