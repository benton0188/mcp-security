import typing
import urllib.parse
import logging
import asyncio
import re

from mcp.server.fastmcp import Context
from ..server import server, vt_client

logger = logging.getLogger(__name__)

def _parse_next_link_header(headers: typing.Mapping[str, str]) -> typing.Optional[str]:
    # ... (no change to this function)
    link_header = headers.get("link")
    if not link_header:
        return None
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
                parsed_url = urllib.parse.urlparse(next_url_str)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                page_cursor = query_params.get('page', [None])[0]
                if page_cursor:
                    return page_cursor
    return None


@server.tool()
async def list_dtm_alerts(
    # ... (parameters and their docstrings remain the same as the last full version) ...
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
    Retrieves DTM alerts for the current organization with extensive filtering and pagination.
    (Full docstring as per previous correct version)
    """
    api_path = "/dtm/alerts"
    params: typing.Dict[str, typing.Any] = {}

    if cursor:
        params["page"] = cursor
    else:
        # ... (parameter filling logic for initial request remains the same) ...
        if sort_by is not None: params["sort"] = sort_by
        if sort_order is not None: params["order"] = sort_order
        if limit is not None:
            effective_include_refs = include_refs if include_refs is not None else True
            current_max_size = 25 if effective_include_refs else 100
            params["size"] = min(limit, current_max_size)
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

    try:
        logger.info(f"Requesting DTM alerts. Path: {api_path}, Params: {params}")
        api_client = vt_client(ctx)
        response = await api_client.get_async(api_path, params=params)

        api_response_data = None
        headers = response.headers

        if response.status == 200:
            api_response_data = await response.json_async()
        else:
            error_text = await response.text_async()
            logger.error(f"API call to {api_path} failed with status {response.status}: {error_text}")
            raise Exception(f"API Error {response.status}: {error_text}")

        next_page_cursor = _parse_next_link_header(headers)

        data_content = []
        meta_content_from_api = {} # For any 'meta' block the  API might return in its body

        if isinstance(api_response_data, dict):
            # --- MODIFICATION: Use "alerts" key from API response ---
            data_content = api_response_data.get("alerts", []) # Changed "data" to "alerts"
            # --- END MODIFICATION ---
            potential_meta = api_response_data.get("meta") # Check if VT API *also* has a meta block
            if isinstance(potential_meta, dict):
                meta_content_from_api = potential_meta
        elif api_response_data is not None:
            logger.warning(
                f"API response data for {api_path} was not a dictionary as expected: {type(api_response_data)}"
            )

        # The tool's response structure (wrapping with "data" and "meta") is defined here:
        return {
            "data": data_content, # This is your tool's output key for the list of alerts
            "meta": {
                "next_cursor": next_page_cursor,
                **meta_content_from_api # Merge any meta from API body
            }
        }
    except Exception as e:
        logger.error(f"Error processing DTM alerts response: {str(e)}", exc_info=True)
        return {"error": f"Failed to list DTM alerts. Reason: {str(e)}", "data": [], "meta": {"next_cursor": None}}


@server.tool()
async def list_child_alerts_for_aggregate_bucket(
    # ... (parameters and their docstrings remain the same) ...
    ctx: Context,
    aggregate_id: str,
    sort_by: typing.Optional[str] = "created_at",
    sort_order: typing.Optional[str] = "desc",
    limit: typing.Optional[int] = 10,
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
    Get child alerts for a given DTM aggregated alert bucket ID.
    (Full docstring as per previous correct version)
    """
    api_path = f"/dtm/alerts/{aggregate_id}/aggregates"
    params: typing.Dict[str, typing.Any] = {}

    if cursor:
        params["page"] = cursor
    else:
        # ... (parameter filling logic for initial request remains the same) ...
        if sort_by is not None: params["sort"] = sort_by
        if sort_order is not None: params["order"] = sort_order
        if limit is not None:
            effective_include_refs = include_refs if include_refs is not None else True
            current_max_size = 25 if effective_include_refs else 100
            params["size"] = min(limit, current_max_size)
        if monitor_ids: params["monitor_id"] = monitor_ids
        if include_refs is not None: params["refs"] = str(include_refs).lower()
        if replace_links is not None: params["replace_links"] = str(replace_links).lower()
        if include_monitor_name is not None: params["monitor_name"] = str(include_monitor_name).lower()
        if has_analysis is not None: params["has_analysis"] = str(has_analysis).lower()
        params["buckets"] = "false"
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

    try:
        logger.info(f"Requesting child DTM alerts for bucket {aggregate_id}. Path: {api_path}, Params: {params}")
        api_client = vt_client(ctx)
        response = await api_client.get_async(api_path, params=params)

        api_response_data = None
        headers = response.headers

        if response.status == 200:
            api_response_data = await response.json_async()
        else:
            error_text = await response.text_async()
            logger.error(f"API call to {api_path} failed with status {response.status}: {error_text}")
            raise Exception(f"API Error {response.status}: {error_text}")

        next_page_cursor = _parse_next_link_header(headers)

        data_content = []
        meta_content_from_api = {}

        if isinstance(api_response_data, dict):
            # --- MODIFICATION: Use "alerts" key from API response ---
            # The /aggregates endpoint (when buckets=false) might actually use "data" or "alerts".
            # You'd need to verify this endpoint's actual response structure.
            # For now, I'll assume it's consistent with /dtm/alerts and uses "alerts".
            # If it uses "data", this line should be api_response_data.get("data", [])
            data_content = api_response_data.get("alerts", []) # Changed "data" to "alerts"
            # --- END MODIFICATION ---
            potential_meta = api_response_data.get("meta")
            if isinstance(potential_meta, dict):
                meta_content_from_api = potential_meta
        elif api_response_data is not None:
            logger.warning(
                f"API response data for {api_path} was not a dictionary as expected: {type(api_response_data)}"
            )

        return {
            "data": data_content,
            "meta": {
                "next_cursor": next_page_cursor,
                **meta_content_from_api
            }
        }
    except Exception as e:
        logger.error(f"Error processing child DTM alerts response for bucket {aggregate_id}: {str(e)}", exc_info=True)
        return {"error": f"Failed to list child DTM alerts for bucket {aggregate_id}. Reason: {str(e)}", "data": [], "meta": {"next_cursor": None}}

