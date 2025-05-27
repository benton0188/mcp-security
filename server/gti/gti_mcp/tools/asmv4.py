import typing
import urllib.parse 
import logging
import asyncio # Keep for asyncio.sleep if retries were to be re-added manually

from mcp.server.fastmcp import Context

# Assuming these imports exist based on your example
# from .. import utils # If you have shared utils
from ..server import server, vt_client

# Configure logging
logger = logging.getLogger(__name__) # Each module gets its own logger
logger.setLevel(logging.INFO)

# If fetch_with_retries was causing event loop issues, we are bypassing it.
# If it's fixed / async-compatible, you can re-introduce it.
# async def fetch_with_retries(client_call, max_retries: int = 3, retry_delay: float = 2.0):
#     ...

@server.tool()
async def get_asm_issue_details(
    id: str, 
    ctx: Context
) -> typing.Dict[str, typing.Any]:
    """
    Retrieves the detailed information for a specific Attack Surface Management (ASM) issue
    identified by its unique ID from Google Threat Intelligence (VirusTotal).
    
    Args:
        id (required): The unique identifier of the ASM issue.
    
    Returns:
        A dictionary containing the detailed attributes and data for the requested ASM issue.
    """
    # ASM issue details endpoint typically is /asm/issues/{id}
    # Verify this path from VT documentation if it differs (e.g., /intelligence/asm_issues/{id})
    api_path = f"/asm/issues/{id}" 
    logger.info(f"DEBUG (get_asm_issue_details): Requesting ASM issue details for ID: {id}. Path: {api_path}")
    
    api_client = vt_client(ctx)

    try:
        # Direct async call bypassing fetch_with_retries
        response = await api_client.get_async(api_path) # No params needed for direct ID lookup
        logger.info(f"DEBUG (get_asm_issue_details): Response status for ID {id}: {response.status}")

        if response.status == 200:
            data = await response.json_async()
            logger.info(f"DEBUG (get_asm_issue_details): Successfully fetched details for ASM issue ID {id}.")
            # VT usually returns the object under a "data" key for single entities
            if isinstance(data, dict) and "data" in data:
                return data # Return the full response which includes the "data" wrapper
            else:
                logger.warning(f"DEBUG (get_asm_issue_details): Response for ID {id} is 200 but 'data' key not found or not as expected. Returning raw response.")
                return data # Return raw if "data" key isn't there
        elif response.status == 404:
            error_text = await response.text_async()
            logger.warning(f"DEBUG (get_asm_issue_details): ASM issue ID '{id}' not found (404). Response: {error_text[:300]}")
            return {"error": f"ASM issue with ID '{id}' not found."}
        else:
            error_text = await response.text_async()
            logger.error(f"DEBUG (get_asm_issue_details): API Error fetching ASM issue ID {id}. Status: {response.status}. Response: {error_text[:500]}")
            return {"error": f"Failed to fetch ASM issue details for ID {id}. Status: {response.status}, Reason: {error_text[:200]}"}

    except Exception as e:
        logger.error(f"DEBUG (get_asm_issue_details): Exception fetching ASM issue ID {id}: {type(e).__name__} - {str(e)}", exc_info=True)
        return {"error": f"Failed to fetch ASM issue details for ID {id}. Reason: {str(e)}"}


@server.tool()
async def search_asm_issues(
    query: str,
    ctx: Context,
    limit_per_page: int = 100,
    # For ASM search, 'cursor' is the 'page_token'.
    # If fetch_all_pages is False, this is the token for the *specific page* requested.
    cursor_for_specific_page: typing.Optional[str] = None, 
    fetch_all_pages: bool = False, # Default to False to mimic original behavior
    max_total_pages: typing.Optional[int] = None # Safety break for fetch_all_pages
) -> typing.Dict[str, typing.Any]:
    """
    Searches for Attack Surface Management (ASM) issues in VirusTotal.
    Handles pagination internally if fetch_all_pages is True, using VirusTotal's 
    'page_token' / 'meta.next_page_token' mechanism.

    Args:
        query (required): The search string (filter) used to find ASM issues.
                          (Refer to VT API docs for ASM query syntax). Example: 'status:open severity:>=HIGH'
        ctx: The MCP context.
        limit_per_page (optional): Maximum number of issues per API page request. Defaults to 100. Max is 1000.
        cursor_for_specific_page (optional): If fetch_all_pages is False, this is the pagination cursor 
                                             (page_token) from a previous result's 'meta.next_page_token' 
                                             to fetch a specific page. Ignored if fetch_all_pages is True.
        fetch_all_pages (optional): If True, attempts to fetch all pages of results. Defaults to False.
        max_total_pages (optional): If fetch_all_pages is True, this limits the number of pages fetched.

    Returns:
        A dictionary. 
        If fetch_all_pages=False: Contains 'data' (list of issues for the requested page) 
                                  and 'meta' (including 'next_page_token' if available).
        If fetch_all_pages=True: Contains 'all_data' (list of all issues from all pages) 
                                 and 'meta_summary' (pagination summary).
        On error: {"error": "message", ...}
    
    ASM Search Query Syntax (Example - Verify with current VT Docs):
      - status:open / status:closed
      - severity:HIGH / severity:MEDIUM / severity:LOW / severity:INFO
      - severity_gte:3 (numeric, e.g. if HIGH=4, MEDIUM=3 etc.)
      - entity_type:Domain / entity_type:IpAddress
      - entity_name:"example.com"
      - tag:"my_custom_tag"
      - last_seen_after:YYYY-MM-DD
      Combine with spaces (AND). Example: 'status:open entity_type:Domain severity:HIGH'
    """
    # --- Determine API path and parameters for ASM search ---
    # The VirusTotal API for listing/searching ASM issues might vary.
    # Common patterns:
    # 1. GET /api/v3/asm/issues?filter={query}&limit={limit}&page_token={token}
    # 2. GET /api/v3/intelligence/asm_issues?filter={query}... (if part of full Intelligence suite)
    # 3. Your original example used: GET /api/v3/asm/search/issues/{url_encoded_query}?page_size={limit}&page_token={token}
    # Let's assume option 1 or 2 as it's more standard for filter parameters.
    # IF YOU MUST USE THE QUERY IN PATH, api_path construction will need `urllib.parse.quote_plus(query)`.

    # Using a common pattern: /asm/issues with 'filter' parameter
    api_path_template = "/asm/issues" # VERIFY THIS! This is the most crucial part.
    
    logger.info(f"DEBUG (search_asm_issues): Query: '{query}', LimitPerPage: {limit_per_page}, FetchAll: {fetch_all_pages}, InitialCursor: {cursor_for_specific_page}")

    api_client = vt_client(ctx)
    all_asm_issues = []
    page_count = 0
    
    # `current_page_token` is the token to send FOR THE NEXT REQUEST
    current_page_token_for_next_req: typing.Optional[str] = cursor_for_specific_page if not fetch_all_pages else None

    # `last_response_full_meta` stores the complete 'meta' block from the last successful API call
    last_response_full_meta: typing.Optional[dict] = None 

    while True:
        page_count += 1
        if fetch_all_pages and max_total_pages is not None and page_count > max_total_pages:
            logger.info(f"DEBUG (search_asm_issues): Reached max_total_pages limit: {max_total_pages}")
            break

        # Parameters for the current API call
        current_params = {}
        # The 'filter' parameter is how VT search/list endpoints usually take queries
        current_params["filter"] = query 
        current_params["limit"] = limit_per_page # VT ASM typically uses "limit"
        
        if current_page_token_for_next_req:
            current_params["page_token"] = current_page_token_for_next_req # VT ASM uses "page_token"

        current_params = {k:v for k,v in current_params.items() if v is not None}

        logger.info(f"DEBUG (search_asm_issues): Page {page_count}: Path '{api_path_template}', Params: {current_params}")
        
        try:
            response = await api_client.get_async(api_path_template, params=current_params)
            logger.info(f"DEBUG (search_asm_issues): Page {page_count}: Response status: {response.status}")

            if response.status == 200:
                page_data = await response.json_async()
                
                items_on_page = page_data.get("data", []) # VT standard is "data" key for list items
                if isinstance(items_on_page, list):
                    all_asm_issues.extend(items_on_page)
                    logger.info(f"DEBUG (search_asm_issues): Page {page_count}: Fetched {len(items_on_page)} issues. Total now: {len(all_asm_issues)}")
                else:
                    logger.warning(f"DEBUG (search_asm_issues): Page {page_count}: 'data' key not a list or not found. Type: {type(items_on_page)}")
                
                # Store the meta block from this page's response
                last_response_full_meta = page_data.get("meta", {})
                
                if not fetch_all_pages: # If only one page was requested by the tool's design
                    # Return the raw API response for the single page.
                    # The caller will use `page_data.get("meta", {}).get("next_page_token")` if needed.
                    return page_data 

                # For full pagination, get next token from meta block
                current_page_token_for_next_req = last_response_full_meta.get("next_page_token") # VT ASM uses this
                if not current_page_token_for_next_req:
                    logger.info(f"DEBUG (search_asm_issues): Page {page_count}: No 'meta.next_page_token'. End of results.")
                    break # Exit the loop
            else: # Non-200 status
                error_text = await response.text_async()
                logger.error(f"DEBUG (search_asm_issues): Page {page_count}: API Error Status {response.status}. Query '{query}'. Response: {error_text[:300]}")
                # Return what we have so far if paginating, or just the error
                output_data_key = "all_data" if fetch_all_pages else "data"
                return {"error": f"API Error for ASM search. Status: {response.status}", output_data_key: all_asm_issues, "meta_from_last_success": last_response_full_meta}
        
        except Exception as e:
            logger.error(f"DEBUG (search_asm_issues): Page {page_count}: Exception query '{query}': {type(e).__name__} - {str(e)}", exc_info=True)
            output_data_key = "all_data" if fetch_all_pages else "data"
            return {"error": f"Exception during ASM search. Reason: {str(e)}", output_data_key: all_asm_issues, "meta_from_last_success": last_response_full_meta}

    # This section is reached if fetch_all_pages was True and loop completed
    if fetch_all_pages:
        return {
            "all_data": all_asm_issues,
            "meta_summary": {
                "total_items_retrieved": len(all_asm_issues),
                "pages_fetched": page_count,
                "pagination_complete": not bool(current_page_token_for_next_req) # True if loop ended naturally
            }
        }
    else: 
        # This case is if fetch_all_pages=False but the loop still exited (e.g. first page had no next token)
        # The actual return for single page happened inside the loop.
        # This structure ensures a consistent return type if that inner return was missed somehow.
        # However, the `return page_data` inside the loop for `not fetch_all_pages` is the primary return.
        logger.info(f"DEBUG (search_asm_issues): Single page fetch completed (or no further pages found).")
        return { # Should mostly be covered by the return inside the loop
            "data": all_asm_issues, # Contains data from the one page fetched
            "meta": last_response_full_meta if last_response_full_meta else {"next_page_token": None}
        }
