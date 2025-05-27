import typing
import urllib.parse
import logging
import asyncio
import re
import json # Added for potential JSON operations if needed by helpers
# import os # os was used for VT_APIKEY, now vt_client handles it
# from getpass import getpass # Removed, not for server tools
# from pathlib import Path # Removed, for local creds file
# from datetime import timedelta # Re-added for malware helper
# from tabulate import tabulate # Removed, tools should return data
# from textwrap import wrap # Removed, for CLI display

from mcp.server.fastmcp import Context

# Assuming these imports exist based on your example structure
from .. import utils # This might not be used if helpers are in this file.
                     # If your CLI's utils.py had other relevant things, they'd need to be here.
from ..server import server, vt_client

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Set to logging.DEBUG for verbose output during testing

# --- START: Helper Functions (Kept in this file for now) ---

LINK_HEADER_NEXT_REGEX = re.compile(r'<([^>]+)>;\s*rel="next"')

def _helper_parse_link_header_for_next_url(headers: typing.Mapping[str, str]) -> typing.Optional[str]:
    """
    Parses the Link HTTP header and returns the FULL URL for rel="next".
    (Internal helper, prefixed with underscore)
    """
    link_header_val = headers.get('Link')
    if not link_header_val:
        link_header_val = headers.get('link')

    if link_header_val:
        logger.debug(f"DEBUG (_helper_parse_link_header_for_next_url): Raw Link header: {link_header_val}")
        links = link_header_val.split(',')
        for link_entry in links:
            parts = link_entry.split(';')
            if len(parts) < 2:
                continue
            url_part = parts[0].strip()
            is_next_link = any(re.match(r'rel\s*=\s*"?next"?', param.strip(), re.IGNORECASE) for param in parts[1:])
            if is_next_link:
                if url_part.startswith('<') and url_part.endswith('>'):
                    next_url = url_part[1:-1]
                    logger.info(f"DEBUG (_helper_parse_link_header_for_next_url): Found next page FULL URL: {next_url}")
                    return next_url
        logger.debug(f"DEBUG (_helper_parse_link_header_for_next_url): No 'rel=\"next\"' found in Link header.")
    else:
        logger.debug(f"DEBUG (_helper_parse_link_header_for_next_url): No 'Link' header found.")
    return None

# This is the _parse_next_link_header from your original DTM tools, renamed for clarity
def _helper_parse_page_cursor_from_link_header(headers: typing.Mapping[str, str]) -> typing.Optional[str]:
    """
    Parses the Link HTTP header for rel="next" and extracts the 'page' query parameter value.
    This was used by your original DTM tools.
    """
    link_header = headers.get("link") # Your original used lowercase "link"
    if not link_header:
        link_header = headers.get("Link") # Try capitalized as well
    if not link_header:
        logger.debug("DEBUG (_helper_parse_page_cursor_from_link_header): No 'Link' header found.")
        return None

    logger.debug(f"DEBUG (_helper_parse_page_cursor_from_link_header): Raw Link header: {link_header}")
    links = link_header.split(',')
    for link_entry in links:
        parts = link_entry.split(';')
        if len(parts) < 2:
            continue
        url_part = parts[0].strip()
        is_next_link = any(re.match(r'rel\s*=\s*"?next"?', param.strip(), re.IGNORECASE) for param in parts[1:])
        
        if is_next_link:
            if url_part.startswith('<') and url_part.endswith('>'):
                next_url_str = url_part[1:-1]
                try:
                    parsed_url = urllib.parse.urlparse(next_url_str)
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    page_cursor = query_params.get('page', [None])[0] # Get first 'page' param
                    if page_cursor:
                        logger.info(f"DEBUG (_helper_parse_page_cursor_from_link_header): Extracted 'page' cursor: {page_cursor}")
                        return page_cursor
                    else:
                        logger.debug(f"DEBUG (_helper_parse_page_cursor_from_link_header): 'page' param not found in next URL query: {parsed_url.query}")
                except Exception as e:
                    logger.error(f"DEBUG (_helper_parse_page_cursor_from_link_header): Error parsing next URL '{next_url_str}': {e}")
            return None # Found rel=next but couldn't parse URL or page param
    logger.debug(f"DEBUG (_helper_parse_page_cursor_from_link_header): No 'rel=\"next\"' link found or no 'page' cursor in it.")
    return None


async def _helper_download_pdf_content_from_url(api_client_for_auth_headers_only, pdf_url: str) -> typing.Optional[bytes]:
    logger.warning("DEBUG (_helper_download_pdf_content_from_url): PDF download functionality is a placeholder and not fully implemented with vt_client for raw downloads.")
    return None


# Re-importing timedelta for _helper_format_malware_data
from datetime import datetime, timedelta, timezone

def _helper_format_malware_data(malware_list_from_api: list, days_filter: typing.Optional[int]) -> dict:
    logger.debug(f"DEBUG (_helper_format_malware_data): Processing {len(malware_list_from_api)} malware items. Days filter: {days_filter}")
    processed_malware_list = []
    threshold_date = None
    if days_filter is not None:
        try:
            threshold_date = datetime.now(timezone.utc) - timedelta(days=days_filter)
        except TypeError:
            logger.warning(f"DEBUG (_helper_format_malware_data): Invalid 'days_filter' value: {days_filter}. Disabling date filtering.")
            threshold_date = None

    for malware_item in malware_list_from_api:
        if not isinstance(malware_item, dict):
            logger.warning(f"DEBUG (_helper_format_malware_data): Skipping non-dict malware item: {type(malware_item)}")
            continue
        if threshold_date:
            last_updated_str = malware_item.get('last_updated')
            if isinstance(last_updated_str, str):
                try:
                    if last_updated_str.endswith('Z'):
                        last_updated_str = last_updated_str[:-1] + '+00:00'
                    last_updated_datetime = datetime.fromisoformat(last_updated_str).astimezone(timezone.utc)
                    if last_updated_datetime < threshold_date:
                        logger.debug(f"DEBUG (_helper_format_malware_data): Skipping malware '{malware_item.get('name', malware_item.get('id'))}' due to old last_updated: {last_updated_str}")
                        continue 
                except ValueError as e:
                    logger.warning(f"DEBUG (_helper_format_malware_data): Error parsing date '{last_updated_str}' for malware '{malware_item.get('name', 'N/A')}': {e}")
                except Exception as e_gen:
                    logger.warning(f"DEBUG (_helper_format_malware_data): Generic error parsing date '{last_updated_str}' for malware '{malware_item.get('name', 'N/A')}': {e_gen}")
        processed_item = {
            "id": malware_item.get("id"), "name": malware_item.get("name"),
            "description": malware_item.get("description"), "last_updated": malware_item.get("last_updated"),
            "has_yara": malware_item.get("has_yara"),
            "aliases": [alias.get("name") for alias in malware_item.get("aliases", []) if isinstance(alias, dict) and "name" in alias]
        }
        processed_malware_list.append(processed_item)
    try:
        processed_malware_list.sort(
            key=lambda x: datetime.fromisoformat(x['last_updated'].replace('Z', '+00:00')).astimezone(timezone.utc) if x.get('last_updated') else datetime.min.replace(tzinfo=timezone.utc),
            reverse=True
        )
    except Exception as e:
        logger.warning(f"DEBUG (_helper_format_malware_data): Could not sort malware list by date: {e}")
    return {"malware_reports": processed_malware_list, "count": len(processed_malware_list)}

# --- END: Helper Functions ---


# --- START: Your ORIGINAL DTM Tools (renamed for clarity) ---
# This is your original _parse_next_link_header, now correctly named _helper_parse_page_cursor_from_link_header
# and placed in the helper section above.

@server.tool()
async def list_dtm_alerts_original_single_page( # Renamed from list_dtm_alerts
    ctx: Context,
    sort_by: typing.Optional[str] = "created_at",
    sort_order: typing.Optional[str] = "desc",
    limit: typing.Optional[int] = 10,
    monitor_ids: typing.Optional[typing.List[str]] = None,
    include_refs: typing.Optional[bool] = True,
    replace_links: typing.Optional[bool] = False,
    include_monitor_name: typing.Optional[bool] = False,
    has_analysis: typing.Optional[bool] = None,
    include_buckets: typing.Optional[bool] = False,
    since_date: typing.Optional[str] = None,
    until_date: typing.Optional[str] = None,
    cursor: typing.Optional[str] = None,
    truncate_length: typing.Optional[int] = None,
    statuses: typing.Optional[typing.List[str]] = None,
    alert_types: typing.Optional[typing.List[str]] = None,
    search_query: typing.Optional[str] = None,
    match_values: typing.Optional[typing.List[str]] = None,
    tags: typing.Optional[typing.List[str]] = None,
    search_encoding: typing.Optional[str] = None,
    severities: typing.Optional[typing.List[str]] = None,
    sanitize: typing.Optional[typing.Union[bool, str, typing.List[str]]] = None,
    mscore_gte: typing.Optional[int] = None
) -> typing.Dict[str, typing.Any]:
    """
    ORIGINAL: Retrieves DTM alerts for the current organization. Fetches ONE page.
    (Docstring from your provided code)
    """
    api_path = "/dtm/alerts"
    params: typing.Dict[str, typing.Any] = {}

    if cursor:
        params["page"] = cursor
        logger.info(f"DEBUG (list_dtm_alerts_original_single_page): Using provided cursor for 'page': {cursor}")
    else:
        # Parameter filling logic for initial request
        if sort_by is not None: params["sort"] = sort_by
        if sort_order is not None: params["order"] = sort_order
        if limit is not None:
            # Your original logic for max size based on include_refs
            effective_include_refs = include_refs if include_refs is not None else True
            # Max size is 25 if refs=true, 100 if refs=false for alerts
            # This logic was observed in VT Enterprise documentation for some DTM endpoints
            current_max_size = 25 if effective_include_refs else 100
            params["size"] = min(limit, current_max_size)
            logger.info(f"DEBUG (list_dtm_alerts_original_single_page): Calculated size: {params['size']} (limit: {limit}, max_for_refs={effective_include_refs}: {current_max_size})")
        if monitor_ids: params["monitor_id"] = monitor_ids
        if include_refs is not None: params["refs"] = str(include_refs).lower()
        if replace_links is not None: params["replace_links"] = str(replace_links).lower()
        if include_monitor_name is not None: params["monitor_name"] = str(include_monitor_name).lower()
        if has_analysis is not None: params["has_analysis"] = str(has_analysis).lower()
        if include_buckets is not None: params["buckets"] = str(include_buckets).lower()
        if since_date: params["since"] = since_date
        if until_date: params["until"] = until_date
        if truncate_length is not None: params["truncate"] = truncate_length
        if statuses: params["status"] = statuses
        if alert_types: params["alert_type"] = alert_types
        if search_query: params["search"] = search_query
        if match_values: params["match_value"] = match_values
        if tags: params["tags"] = tags
        if search_encoding: params["search_encoding"] = search_encoding
        if severities: params["severity"] = severities
        if sanitize is not None:
            params["sanitize"] = str(sanitize).lower() if isinstance(sanitize, bool) else sanitize
        if mscore_gte is not None: params["mscore_gte"] = mscore_gte
    
    params = {k:v for k,v in params.items() if v is not None} # Clean None values

    try:
        logger.info(f"DEBUG (list_dtm_alerts_original_single_page): Requesting. Path: {api_path}, Params: {params}")
        api_client = vt_client(ctx)
        response = await api_client.get_async(api_path, params=params)

        api_response_data = None
        headers = response.headers # Get headers for Link parsing

        if response.status == 200:
            api_response_data = await response.json_async()
        else:
            error_text = await response.text_async() # Important: use _async
            logger.error(f"DEBUG (list_dtm_alerts_original_single_page): API call to {api_path} failed with status {response.status}: {error_text[:300]}")
            # Original code raised Exception here, let's return an error dict to be consistent with MCP tool patterns
            return {"error": f"API Error {response.status}: {error_text[:200]}", "data": [], "meta": {"next_cursor": None}}


        # Use the helper that extracts the 'page' cursor from Link header
        next_page_cursor = _helper_parse_page_cursor_from_link_header(headers)
        logger.info(f"DEBUG (list_dtm_alerts_original_single_page): Next page cursor from Link header: {next_page_cursor}")


        data_content = []
        meta_content_from_api = {} # For any 'meta' block the API might return in its body

        if isinstance(api_response_data, dict):
            # MODIFICATION: Your original code used "alerts" based on an example.
            # Standard VT API often uses "data". We should check which is correct for DTM alerts.
            # If the DTM API response for /alerts has {"data": [...], "meta": {...}} this is correct.
            # If it has {"alerts": [...], "meta_for_alerts": {...}} this should be "alerts".
            # Let's assume standard "data" and "meta" for now, but this is a key verification point.
            data_content = api_response_data.get("data", []) # Assuming "data" is the key for alert items
            logger.info(f"DEBUG (list_dtm_alerts_original_single_page): Extracted {len(data_content)} items from 'data' key.")
            
            potential_meta = api_response_data.get("meta") # Check if VT API *also* has a meta block
            if isinstance(potential_meta, dict):
                meta_content_from_api = potential_meta
                logger.info(f"DEBUG (list_dtm_alerts_original_single_page): Found 'meta' block in response body: {meta_content_from_api}")
                # If body meta has a cursor, prefer Link header, but good to know if it's there
                if "cursor" in meta_content_from_api and not next_page_cursor:
                    logger.info(f"DEBUG (list_dtm_alerts_original_single_page): Using cursor from response body meta: {meta_content_from_api['cursor']}")
                    # This tool's contract is to return Link header cursor, but good to be aware
                    # next_page_cursor = meta_content_from_api['cursor'] # Potentially override if Link header missing
        elif api_response_data is not None: # Response was 200 but not a dict
            logger.warning(
                f"DEBUG (list_dtm_alerts_original_single_page): API response data for {api_path} was not a dictionary as expected: {type(api_response_data)}. Data: {str(api_response_data)[:300]}"
            )

        # The tool's response structure (wrapping with "data" and "meta") is defined here by your original tool:
        return {
            "data": data_content, # This is your tool's output key for the list of alerts
            "meta": {
                "next_cursor": next_page_cursor, # This is from Link header
                **meta_content_from_api # Merge any meta from API body
            }
        }
    except Exception as e:
        logger.error(f"DEBUG (list_dtm_alerts_original_single_page): Error processing DTM alerts response: {str(e)}", exc_info=True)
        return {"error": f"Failed to list DTM alerts. Reason: {str(e)}", "data": [], "meta": {"next_cursor": None}}


@server.tool()
async def list_child_alerts_for_aggregate_bucket_original_single_page( # Renamed
    ctx: Context,
    aggregate_id: str, # Changed from alert_bucket_id to match your original code's param name
    sort_by: typing.Optional[str] = "created_at",
    sort_order: typing.Optional[str] = "desc",
    limit: typing.Optional[int] = 10,
    # ... (all other parameters from your original child alerts tool)
    monitor_ids: typing.Optional[typing.List[str]] = None,
    include_refs: typing.Optional[bool] = True,
    replace_links: typing.Optional[bool] = False,
    include_monitor_name: typing.Optional[bool] = False,
    has_analysis: typing.Optional[bool] = None,
    since_date: typing.Optional[str] = None,
    until_date: typing.Optional[str] = None,
    cursor: typing.Optional[str] = None,
    truncate_length: typing.Optional[int] = None,
    statuses: typing.Optional[typing.List[str]] = None,
    alert_types: typing.Optional[typing.List[str]] = None,
    search_query: typing.Optional[str] = None,
    match_values: typing.Optional[typing.List[str]] = None,
    tags: typing.Optional[typing.List[str]] = None,
    search_encoding: typing.Optional[str] = None,
    severities: typing.Optional[typing.List[str]] = None,
    sanitize: typing.Optional[typing.Union[bool, str, typing.List[str]]] = None,
    mscore_gte: typing.Optional[int] = None
) -> typing.Dict[str, typing.Any]:
    """
    ORIGINAL: Get child alerts for a given DTM aggregated alert bucket ID. Fetches ONE page.
    (Docstring from your provided code)
    """
    if not aggregate_id: # From your original logic
        logger.error("DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): aggregate_id is required.")
        return {"error": "aggregate_id is required."}

    api_path = f"/dtm/alerts/{aggregate_id}/aggregates"
    params: typing.Dict[str, typing.Any] = {}

    if cursor:
        params["page"] = cursor
        logger.info(f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): Using provided cursor for 'page': {cursor}")
    else:
        # Parameter filling logic for initial request (copied from your original)
        if sort_by is not None: params["sort"] = sort_by
        if sort_order is not None: params["order"] = sort_order
        if limit is not None:
            effective_include_refs = include_refs if include_refs is not None else True
            current_max_size = 25 if effective_include_refs else 100 # Max size for child alerts? Assume same as parent for now
            params["size"] = min(limit, current_max_size)
            logger.info(f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): Calculated size: {params['size']}")
        if monitor_ids: params["monitor_id"] = monitor_ids
        if include_refs is not None: params["refs"] = str(include_refs).lower()
        if replace_links is not None: params["replace_links"] = str(replace_links).lower()
        if include_monitor_name is not None: params["monitor_name"] = str(include_monitor_name).lower()
        if has_analysis is not None: params["has_analysis"] = str(has_analysis).lower()
        params["buckets"] = "false" # Crucial: ensures child alerts are returned
        if since_date: params["since"] = since_date
        if until_date: params["until"] = until_date
        if truncate_length is not None: params["truncate"] = truncate_length
        if statuses: params["status"] = statuses
        if alert_types: params["alert_type"] = alert_types
        if search_query: params["search"] = search_query
        if match_values: params["match_value"] = match_values
        if tags: params["tags"] = tags
        if search_encoding: params["search_encoding"] = search_encoding
        if severities: params["severity"] = severities
        if sanitize is not None:
            params["sanitize"] = str(sanitize).lower() if isinstance(sanitize, bool) else sanitize
        if mscore_gte is not None: params["mscore_gte"] = mscore_gte

    params = {k:v for k,v in params.items() if v is not None}

    try:
        logger.info(f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): Requesting child DTM alerts for bucket {aggregate_id}. Path: {api_path}, Params: {params}")
        api_client = vt_client(ctx)
        response = await api_client.get_async(api_path, params=params)

        api_response_data = None
        headers = response.headers

        if response.status == 200:
            api_response_data = await response.json_async()
        else:
            error_text = await response.text_async() # Important: use _async
            logger.error(f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): API call to {api_path} failed, status {response.status}: {error_text[:300]}")
            return {"error": f"API Error {response.status}: {error_text[:200]}", "data": [], "meta": {"next_cursor": None}}

        next_page_cursor = _helper_parse_page_cursor_from_link_header(headers)
        logger.info(f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): Next page cursor from Link header: {next_page_cursor}")

        data_content = []
        meta_content_from_api = {}

        # How are child alerts structured? The DTM API sometimes returns a direct list for sub-resources.
        # Or it could be {"data": [...]} or {"alerts": [...]}. This needs verification.
        # Your original code assumed "alerts" - api_response_data.get("alerts", [])
        # If the /aggregates endpoint returns a direct list:
        if isinstance(api_response_data, list):
            data_content = api_response_data
            logger.info(f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): Response is a direct list of {len(data_content)} items.")
        elif isinstance(api_response_data, dict):
            # Check for "data" key first (common in VT for lists)
            if "data" in api_response_data and isinstance(api_response_data["data"], list):
                data_content = api_response_data["data"]
                logger.info(f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): Extracted {len(data_content)} items from 'data' key.")
            # Then check for "alerts" key (as per your original code for this tool)
            elif "alerts" in api_response_data and isinstance(api_response_data["alerts"], list):
                data_content = api_response_data["alerts"]
                logger.info(f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): Extracted {len(data_content)} items from 'alerts' key.")
            else:
                logger.warning(f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): Response dict did not contain 'data' or 'alerts' as a list. Keys: {list(api_response_data.keys())}")

            potential_meta = api_response_data.get("meta")
            if isinstance(potential_meta, dict):
                meta_content_from_api = potential_meta
                logger.info(f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): Found 'meta' block in response body: {meta_content_from_api}")
        elif api_response_data is not None:
            logger.warning(
                f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): API response data for {api_path} was not a list or dictionary as expected: {type(api_response_data)}. Data: {str(api_response_data)[:300]}"
            )

        return {
            "data": data_content,
            "meta": {
                "next_cursor": next_page_cursor,
                **meta_content_from_api
            }
        }
    except Exception as e:
        logger.error(f"DEBUG (list_child_alerts_for_aggregate_bucket_original_single_page): Error processing child DTM alerts for bucket {aggregate_id}: {str(e)}", exc_info=True)
        return {"error": f"Failed to list child DTM alerts for bucket {aggregate_id}. Reason: {str(e)}", "data": [], "meta": {"next_cursor": None}}

# --- END: Your ORIGINAL DTM Tools ---


# --- START: New Generic API Fetch Tool (as defined before) ---
@server.tool()
async def fetch_virustotal_api_generic(
    ctx: Context,
    api_path: str,
    params: typing.Optional[typing.Dict[str, typing.Any]] = None,
    paginate_fully: bool = False,
    max_pages_fetch: typing.Optional[int] = None,
    data_key: str = "data" 
) -> typing.Dict[str, typing.Any]:
    """
    Fetches data from a specified VirusTotal API v3 path with optional parameters and pagination.
    (Full docstring as previously provided)
    """
    if not api_path.startswith("/"):
        logger.error(f"DEBUG (fetch_virustotal_api_generic): api_path must start with '/', got: {api_path}")
        return {"error": "api_path must start with '/'", "data": [], "meta": {"next_cursor": None}}
    
    logger.info(f"DEBUG (fetch_virustotal_api_generic): Invoked. Path: '{api_path}', Params: {params}, PaginateFully: {paginate_fully}, MaxPages: {max_pages_fetch}, DataKey: '{data_key}'")

    api_client = vt_client(ctx)
    current_params_for_first_call = params.copy() if params else {} 
    
    all_items_aggregated: typing.List[dict] = []
    page_count = 0
    next_page_full_url: typing.Optional[str] = None
    last_api_meta_block: typing.Optional[dict] = None 

    current_request_path_for_client = api_path 

    while True:
        page_count += 1
        if paginate_fully and max_pages_fetch is not None and page_count > max_pages_fetch:
            logger.info(f"DEBUG (fetch_virustotal_api_generic): Reached max_pages_fetch limit of {max_pages_fetch}. Stopping.")
            break

        response_obj = None
        current_call_params = None 

        try:
            if next_page_full_url: 
                logger.info(f"DEBUG (fetch_virustotal_api_generic): Page {page_count}: Requesting from next_page_url: {next_page_full_url}")
                if hasattr(api_client, 'get_url'): 
                    response_obj = await api_client.get_url(next_page_full_url) 
                else: 
                    logger.warning("DEBUG (fetch_virustotal_api_generic): vt_client has no 'get_url'. Parsing URL for get_async.")
                    parsed_next_url = urllib.parse.urlparse(next_page_full_url)
                    current_request_path_for_client = parsed_next_url.path
                    current_call_params = dict(urllib.parse.parse_qs(parsed_next_url.query)) 
                    current_call_params = {k: v[0] if len(v)==1 else v for k,v in current_call_params.items()}
                    response_obj = await api_client.get_async(current_request_path_for_client, params=current_call_params)
            else: 
                current_call_params = current_params_for_first_call
                logger.info(f"DEBUG (fetch_virustotal_api_generic): Page {page_count} (Initial): Path '{current_request_path_for_client}', Params: {current_call_params}")
                response_obj = await api_client.get_async(current_request_path_for_client, params=current_call_params)

            logger.info(f"DEBUG (fetch_virustotal_api_generic): Page {page_count}: Response status: {response_obj.status}")

            if response_obj.status == 200:
                api_response_data = await response_obj.json_async()
                items_on_page = []
                if isinstance(api_response_data, dict):
                    if "meta" in api_response_data and isinstance(api_response_data["meta"], dict):
                        last_api_meta_block = api_response_data["meta"]
                    if data_key and data_key in api_response_data:
                        fetched_items = api_response_data.get(data_key)
                        if isinstance(fetched_items, list): items_on_page = fetched_items
                        else: logger.warning(f"DEBUG (fetch_virustotal_api_generic): '{data_key}' not a list. Type: {type(fetched_items)}")
                    elif not data_key: logger.warning(f"DEBUG (fetch_virustotal_api_generic): data_key empty, response a dict.")
                elif isinstance(api_response_data, list) and not data_key : 
                    items_on_page = api_response_data
                    last_api_meta_block = {} 
                else: logger.warning(f"DEBUG (fetch_virustotal_api_generic): API response not dict/list or '{data_key}' not found/applicable. Type: {type(api_response_data)}. Data: {str(api_response_data)[:300]}")

                logger.info(f"DEBUG (fetch_virustotal_api_generic): Page {page_count}: Fetched {len(items_on_page)} items using data_key '{data_key}'.")
                all_items_aggregated.extend(items_on_page)

                if not paginate_fully: 
                    next_page_cursor_from_link = _helper_parse_page_cursor_from_link_header(response_obj.headers)
                    cursor_from_body_meta = None
                    if last_api_meta_block and "cursor" in last_api_meta_block: 
                        cursor_from_body_meta = last_api_meta_block["cursor"]
                    final_next_cursor = next_page_cursor_from_link or cursor_from_body_meta
                    return {
                        data_key if data_key else "data": all_items_aggregated, 
                        "meta": {"next_cursor": final_next_cursor, **(last_api_meta_block if last_api_meta_block else {})}
                    }
                next_page_full_url = _helper_parse_link_header_for_next_url(response_obj.headers)
                if not next_page_full_url:
                    logger.info(f"DEBUG (fetch_virustotal_api_generic): Page {page_count}: No more pages (no 'next' link from Link header).")
                    break
            else: 
                error_text = await response_obj.text_async()
                api_target = api_path if not next_page_full_url else next_page_full_url
                logger.error(f"DEBUG (fetch_virustotal_api_generic): Page {page_count}: API Error: Status {response_obj.status} for {api_target}. Response: {error_text[:500]}...")
                current_data_key = "all_data" if paginate_fully else (data_key if data_key else "data")
                return {"error": f"API call to '{api_target}' failed. Status: {response_obj.status}, Body: {error_text[:200]}...", current_data_key: all_items_aggregated, "meta": {"next_cursor": None, **(last_api_meta_block if last_api_meta_block else {})}}
        except Exception as e:
            api_target = api_path if not next_page_full_url else next_page_full_url
            logger.error(f"DEBUG (fetch_virustotal_api_generic): Page {page_count}: Exception for '{api_target}': {type(e).__name__} - {str(e)}", exc_info=True)
            current_data_key = "all_data" if paginate_fully else (data_key if data_key else "data")
            return {"error": f"Exception during API call for '{api_target}': {str(e)}", current_data_key: all_items_aggregated, "meta": {"next_cursor": None, **(last_api_meta_block if last_api_meta_block else {})}}

    if paginate_fully:
        return {"all_data": all_items_aggregated, "meta_summary": {"total_items_retrieved": len(all_items_aggregated), "pages_fetched": page_count, "pagination_complete": not bool(next_page_full_url)}}
    else: 
        logger.info(f"DEBUG (fetch_virustotal_api_generic): Single page fetched, no further pagination by this tool.")
        return {data_key if data_key else "data": all_items_aggregated, "meta": {"next_cursor": None, **(last_api_meta_block if last_api_meta_block else {})}}
# --- END: New Generic API Fetch Tool ---


# --- START: New DTM Tools using the Generic Fetcher (as defined before) ---
@server.tool()
async def list_dtm_alerts_paginated(
    ctx: Context,
    sort_by: typing.Optional[str] = "created_at",
    sort_order: typing.Optional[str] = "desc",
    limit_per_page: typing.Optional[int] = 100,
    monitor_ids: typing.Optional[typing.List[str]] = None,
    include_refs: typing.Optional[bool] = True,
    replace_links: typing.Optional[bool] = False,
    include_monitor_name: typing.Optional[bool] = False,
    has_analysis: typing.Optional[bool] = None,
    include_buckets: typing.Optional[bool] = False,
    since_date: typing.Optional[str] = None,
    until_date: typing.Optional[str] = None,
    cursor_for_first_page: typing.Optional[str] = None,
    truncate_length: typing.Optional[int] = None,
    statuses: typing.Optional[typing.List[str]] = None,
    alert_types: typing.Optional[typing.List[str]] = None,
    search_query: typing.Optional[str] = None,
    match_values: typing.Optional[typing.List[str]] = None,
    tags: typing.Optional[typing.List[str]] = None,
    search_encoding: typing.Optional[str] = None,
    severities: typing.Optional[typing.List[str]] = None,
    sanitize: typing.Optional[typing.Union[bool, str, typing.List[str]]] = None,
    mscore_gte: typing.Optional[int] = None,
    fetch_all_pages: bool = True,
    max_total_pages: typing.Optional[int] = None
) -> typing.Dict[str, typing.Any]:
    """
    Retrieves DTM alerts. If fetch_all_pages is True (default), attempts to get all pages.
    Args docstring as per your `list_dtm_alerts_original_single_page`
    """
    api_path = "/dtm/alerts"
    params: typing.Dict[str, typing.Any] = {}
    if cursor_for_first_page: params["page"] = cursor_for_first_page
    if sort_by is not None: params["sort"] = sort_by
    if sort_order is not None: params["order"] = sort_order
    if limit_per_page is not None: params["size"] = min(limit_per_page, 100) # VT typical max page size
    if monitor_ids: params["monitor_id"] = monitor_ids
    if include_refs is not None: params["refs"] = str(include_refs).lower()
    if replace_links is not None: params["replace_links"] = str(replace_links).lower()
    if include_monitor_name is not None: params["monitor_name"] = str(include_monitor_name).lower()
    if has_analysis is not None: params["has_analysis"] = str(has_analysis).lower()
    if include_buckets is not None: params["buckets"] = str(include_buckets).lower()
    if since_date: params["since"] = since_date
    if until_date: params["until"] = until_date
    if truncate_length is not None: params["truncate"] = truncate_length
    if statuses: params["status"] = statuses
    if alert_types: params["alert_type"] = alert_types
    if search_query: params["search"] = search_query
    if match_values: params["match_value"] = match_values
    if tags: params["tags"] = tags
    if search_encoding: params["search_encoding"] = search_encoding
    if severities: params["severity"] = severities
    if sanitize is not None: params["sanitize"] = str(sanitize).lower() if isinstance(sanitize, bool) else sanitize
    if mscore_gte is not None: params["mscore_gte"] = mscore_gte
    params = {k:v for k,v in params.items() if v is not None}

    result = await fetch_virustotal_api_generic(
        ctx=ctx, api_path=api_path, params=params,
        paginate_fully=fetch_all_pages, max_pages_fetch=max_total_pages,
        data_key="data" # DTM /alerts uses "data" for the list and "meta.cursor" for next page (if not Link header)
    )
    return result


@server.tool()
async def list_child_alerts_for_aggregate_bucket_paginated(
    ctx: Context,
    aggregate_id: str,
    sort_by: typing.Optional[str] = "created_at",
    sort_order: typing.Optional[str] = "desc",
    limit_per_page: typing.Optional[int] = 100,
    monitor_ids: typing.Optional[typing.List[str]] = None,
    include_refs: typing.Optional[bool] = True,
    replace_links: typing.Optional[bool] = False,
    include_monitor_name: typing.Optional[bool] = False,
    has_analysis: typing.Optional[bool] = None,
    since_date: typing.Optional[str] = None,
    until_date: typing.Optional[str] = None,
    cursor_for_first_page: typing.Optional[str] = None,
    truncate_length: typing.Optional[int] = None,
    statuses: typing.Optional[typing.List[str]] = None,
    alert_types: typing.Optional[typing.List[str]] = None,
    search_query: typing.Optional[str] = None,
    match_values: typing.Optional[typing.List[str]] = None,
    tags: typing.Optional[typing.List[str]] = None,
    search_encoding: typing.Optional[str] = None,
    severities: typing.Optional[typing.List[str]] = None,
    sanitize: typing.Optional[typing.Union[bool, str, typing.List[str]]] = None,
    mscore_gte: typing.Optional[int] = None,
    fetch_all_pages: bool = True,
    max_total_pages: typing.Optional[int] = None
) -> typing.Dict[str, typing.Any]:
    """
    Get child alerts for a DTM aggregate. If fetch_all_pages is True (default), gets all pages.
    Args docstring as per your `list_child_alerts_for_aggregate_bucket_original_single_page`
    """
    if not aggregate_id: return {"error": "aggregate_id is required."}
    api_path = f"/dtm/alerts/{aggregate_id}/aggregates"
    params: typing.Dict[str, typing.Any] = {}
    if cursor_for_first_page: params["page"] = cursor_for_first_page
    if sort_by is not None: params["sort"] = sort_by
    if sort_order is not None: params["order"] = sort_order
    if limit_per_page is not None: params["size"] = min(limit_per_page, 100)
    params["buckets"] = "false" 
    if monitor_ids: params["monitor_id"] = monitor_ids
    if include_refs is not None: params["refs"] = str(include_refs).lower()
    if replace_links is not None: params["replace_links"] = str(replace_links).lower()
    if include_monitor_name is not None: params["monitor_name"] = str(include_monitor_name).lower()
    if has_analysis is not None: params["has_analysis"] = str(has_analysis).lower()
    if since_date: params["since"] = since_date
    if until_date: params["until"] = until_date
    if truncate_length is not None: params["truncate"] = truncate_length
    if statuses: params["status"] = statuses
    if alert_types: params["alert_type"] = alert_types
    if search_query: params["search"] = search_query
    if match_values: params["match_value"] = match_values
    if tags: params["tags"] = tags
    if search_encoding: params["search_encoding"] = search_encoding
    if severities: params["severity"] = severities
    if sanitize is not None: params["sanitize"] = str(sanitize).lower() if isinstance(sanitize, bool) else sanitize
    if mscore_gte is not None: params["mscore_gte"] = mscore_gte
    params = {k:v for k,v in params.items() if v is not None}

    # For /aggregates, verify the data_key. If it's a direct list, use data_key="".
    result = await fetch_virustotal_api_generic(
        ctx=ctx, api_path=api_path, params=params,
        paginate_fully=fetch_all_pages, max_pages_fetch=max_total_pages,
        data_key="data" # VERIFY THIS for /aggregates.
    )
    return result
# --- END: New DTM Tools ---


# --- START: New Conceptual Tools based on your CLI (as defined before) ---
@server.tool()
async def get_vt_intelligence_report_pdf_url(
    ctx: Context,
    report_api_path: str 
) -> typing.Dict[str, typing.Any]:
    """
    Fetches the download URL for a VirusTotal Intelligence PDF report.
    (Full docstring as previously provided)
    """
    if not report_api_path.startswith("/"): return {"error": "report_api_path must start with '/'."}
    logger.info(f"DEBUG (get_vt_intelligence_report_pdf_url): Fetching PDF URL from {report_api_path}")
    api_client = vt_client(ctx)
    try:
        response_obj = await api_client.get_async(report_api_path)
        if response_obj.status == 200:
            json_data = await response_obj.json_async()
            if isinstance(json_data, dict) and "data" in json_data and isinstance(json_data["data"], str):
                pdf_url = json_data["data"]
                logger.info(f"DEBUG (get_vt_intelligence_report_pdf_url): Found PDF URL: {pdf_url}")
                return {"pdf_download_url": pdf_url, "status": "success"}
            else:
                logger.warning(f"DEBUG (get_vt_intelligence_report_pdf_url): Could not extract PDF URL from API response. Data: {str(json_data)[:500]}")
                return {"error": "Could not extract PDF download URL from API response.", "response_preview": str(json_data)[:200]}
        else:
            error_text = await response_obj.text_async()
            logger.error(f"DEBUG (get_vt_intelligence_report_pdf_url): API error status {response_obj.status} from {report_api_path}: {error_text[:300]}")
            return {"error": f"API error getting PDF URL: Status {response_obj.status}", "details": error_text[:200]}
    except Exception as e:
        logger.error(f"DEBUG (get_vt_intelligence_report_pdf_url): Exception: {type(e).__name__} - {str(e)}", exc_info=True)
        return {"error": str(e) }


@server.tool()
async def get_vt_mati_malware_reports_processed(
    ctx: Context,
    days_filter: typing.Optional[int] = 7,
    fetch_all_pages: bool = True, 
    max_total_pages: typing.Optional[int] = None,
    # --- ADDED parameters for the MATI malware endpoint based on your CLI logic ---
    # The CLI script didn't show specific filter params for /mati/malware direct call other than pagination.
    # If the actual /intelligence/malware or similar endpoint supports filters, add them here.
    # For example:
    # query_filter: typing.Optional[str] = None, 
    # relationships: typing.Optional[str] = None,
    limit_per_page: typing.Optional[int] = 100 # Default page size for underlying fetcher
) -> typing.Dict[str, typing.Any]:
    """
    Fetches VirusTotal MATI-like malware reports and processes them.
    (Full docstring as previously provided)
    """
    # VERIFY THE CORRECT VT v3 PATH for malware intelligence reports.
    # /intelligence/malware is a common one. Your CLI used /mati/malware, which might be different.
    api_path = "/intelligence/malware" 
    # VERIFY THE DATA KEY. If MATI response was `{"malware": [...]}` use "malware".
    # If it's standard VT `{"data": [...]}` use "data".
    data_key_for_malware = "data" 
    logger.info(f"DEBUG (get_vt_mati_malware_reports_processed): Fetching malware. Days filter: {days_filter}")

    initial_params = {"limit": limit_per_page} # Common param for list endpoints
    # if query_filter: initial_params["filter"] = query_filter # Example if API supports it
    # if relationships: initial_params["relationships"] = relationships # Example

    raw_response_data = await fetch_virustotal_api_generic(
        ctx,
        api_path=api_path,
        params=initial_params,
        paginate_fully=fetch_all_pages,
        max_pages_fetch=max_total_pages,
        data_key=data_key_for_malware
    )
    if "error" in raw_response_data: return raw_response_data
    malware_list_from_api = raw_response_data.get("all_data" if fetch_all_pages else data_key_for_malware, [])
    if not malware_list_from_api:
        logger.info("DEBUG (get_vt_mati_malware_reports_processed): No malware data from API.")
        return {"malware_reports": [], "count": 0, "message": "No malware data returned."}
    processed_result = _helper_format_malware_data(malware_list_from_api, days_filter)
    if fetch_all_pages and "meta_summary" in raw_response_data: processed_result["meta_summary"] = raw_response_data["meta_summary"]
    elif not fetch_all_pages and "meta" in raw_response_data: processed_result["meta"] = raw_response_data["meta"]
    return processed_result
# --- END: New Conceptual Tools ---
