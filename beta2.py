from flask import Flask, request, render_template, jsonify, Response, send_from_directory, send_file
from flask_cors import CORS
import csv
import json
import re
import io
import logging
import os
from queue import Queue, Empty
import threading
import time
from datetime import datetime
from typing import Dict, List, Tuple
from collections import defaultdict

# Configuration for float validation
# Set to True to accept integers as valid float values (handles JSON serialization quirks)
ACCEPT_INT_AS_FLOAT = False

# Configure logging
logging.basicConfig(
    filename='validation_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app, resources={r"/*": {"origins": "*"}})

# Enable debug mode
app.debug = True

# Live webhook validation storage and SSE clients

@app.route('/download_template', methods=['GET'])
def download_template():
    """Download a sample CSV template"""
    return send_file('sample.csv',
                    mimetype='text/csv',
                    as_attachment=True,
                    download_name='sample_template.csv')

@app.route('/download_sample_log/<mode>', methods=['GET'])
def download_sample_log(mode):
    """Download a sample log file based on validation mode"""
    try:
        if mode == 'regular':
            filename = 'samplelog_android.txt'
        elif mode == 'website':
            filename = 'sample_website_logs.txt'
        elif mode == 'website-v2':
            # Return v2 or multiline based on query parameter
            is_multiline = request.args.get('multiline', 'false').lower() == 'true'
            filename = 'sample_website_logs_v2_multiline.txt' if is_multiline else 'sample_website_logs_v2.txt'
        else:
            return jsonify({"error": "Invalid mode"}), 400
        
        # Get the absolute path to the file
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
        
        if not os.path.exists(file_path):
            app.logger.error(f'Sample file not found: {file_path}')
            return jsonify({"error": f"Sample file {filename} not found"}), 404
            
        app.logger.info(f'Sending sample file: {file_path}')
        return send_file(
            file_path,
            mimetype='text/plain',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        app.logger.error(f'Error sending sample file: {str(e)}')
        return jsonify({"error": str(e)}), 500

@app.before_request
def log_request_info():
    app.logger.info('Headers: %s', request.headers)
    app.logger.info('Body: %s', request.get_data())
    app.logger.info('URL: %s', request.url)
    app.logger.info('Method: %s', request.method)
    app.logger.info('Endpoint: %s', request.endpoint)

@app.after_request
def after_request(response):
    if response.direct_passthrough:
        # For file responses, just log the content type and headers
        app.logger.info('Response: [File Response] Content-Type: %s, Headers: %s', 
                       response.content_type, dict(response.headers))
    else:
        # For regular responses, log the data
        try:
            app.logger.info('Response: %s', response.get_data())
        except Exception as e:
            app.logger.warning('Could not log response data: %s', str(e))
    return response

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error('Page not found: %s', request.url)
    return jsonify({'error': 'Not found', 'url': request.url}), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error('Server Error: %s', error)
    return jsonify({'error': 'Internal server error'}), 500

def log_validation_event(event_type: str, details: Dict):
    """Log validation events for audit purposes"""
    logging.info(f"{event_type}: {json.dumps(details)}")


def get_value_type(value):
    """Determine the actual type of a value"""
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return "boolean"
    elif isinstance(value, int):
        # Check if this int might have been a float originally
        # This is a heuristic - we can't know for sure, but we can provide context
        return "integer"
    elif isinstance(value, float):
        return "float"
    elif isinstance(value, str):
        # Try to determine if it's a date
        try:
            if re.match(r"\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$", value):
                return "date"
        except:
            pass
        return "text"
    elif isinstance(value, (list, tuple)):
        return "array"
    elif isinstance(value, dict):
        return "object"
    return "unknown"

# Utility functions for validation
def validate_text(value):
    return isinstance(value, str) and value.strip() != ""

def validate_date(value, event_name):
    if event_name == "user_profile_push":
        date_pattern = r"\d{4}-\d{2}-\d{2}"  # YYYY-MM-DD format for user_profile_push
    else:
        date_pattern = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"  # YYYY-MM-DD HH:MM:SS for other events
    return isinstance(value, str) and bool(re.fullmatch(date_pattern, value))

def validate_integer(value):
    return isinstance(value, int)

def validate_float(value):
    """Validate float values, handling JSON serialization quirks"""
    if ACCEPT_INT_AS_FLOAT:
        # Accept both float and int for float validation
        # This handles cases where JSON serialization converts 3.00 to 3 (int)
        # but 3.10 stays as 3.1 (float)
        return isinstance(value, (float, int))
    else:
        # Strict float validation - only accept actual float values
        return isinstance(value, float)

def get_formatted_value(value, expected_type):
    """Format value based on its expected type"""
    if expected_type == "float" and isinstance(value, (float)):
        # Convert to string maintaining decimal places
        str_val = str(value)
        if '.' not in str_val:
            str_val += '.00'
        elif len(str_val.split('.')[1]) == 1:
            str_val += '0'
        return str_val
    return value

def validate_value(value, expected_type, event_name=None):
    if value is None or value == "" or value == "":
        return "Null value"
    if expected_type == "text":
        return validate_text(value)
    elif expected_type == "date":
        return validate_date(value, event_name)
    elif expected_type == "integer":
        return validate_integer(value)
    elif expected_type == "float":
        result = validate_float(value)
        # Add special handling for int values that might have been floats
        if result and isinstance(value, int) and ACCEPT_INT_AS_FLOAT:
            return "Valid (JSON serialization converted float to integer)"
        return result
    return False

def normalize_key(key):
    """Normalize key by converting to lowercase and replacing spaces with underscores"""
    return key.replace(" ", "_").lower() if key else None

def parse_csv_with_case_normalization(csv_reader):
    """Parse CSV and normalize event names and field names to lowercase"""
    event_validations = {}
    events_without_payload = set()
    current_event = None
    
    for row in csv_reader:
        event_name = row.get('eventName', '').strip().lower()  # Convert event name to lowercase
        if event_name:
            current_event = event_name
        
        if not current_event:
            continue

        if current_event not in event_validations:
            event_validations[current_event] = []

        raw_key = row.get('eventPayload', '')
        raw_expected_type = row.get('dataType', '')
        key = raw_key.strip().lower()
        expected_type = raw_expected_type.strip()
        required_flag = row.get('required', '').lower() == 'true'
        condition_raw = row.get('condition', '').strip()
        try:
            condition = json.loads(condition_raw) if condition_raw else {}
        except json.JSONDecodeError:
            condition = {}

        # If both key and expected type are missing, this event expects no payload
        if not key and not expected_type:
            events_without_payload.add(current_event)
            # Skip adding validation rules for presence-only events
            continue

        validation = {
            'key': key,
            'expectedType': expected_type,
            'required': required_flag,
            'condition': condition
        }
        event_validations[current_event].append(validation)

        # Once a real validation is found, ensure the event is not marked as payload-less
        if current_event in events_without_payload:
            events_without_payload.remove(current_event)
    
    return event_validations, events_without_payload

def get_array_field_name(key):
    # Match pattern like "field_name[].subfield" or "items[].field_name"
    match = re.match(r"(.+)\[\]\.(.+)", key)
    if match:
        return match.group(1), match.group(2)
    return None, None

def validate_array_of_objects(array_payload, validations, event_name, results):
    # Extract validation rules for array items
    array_validations = {}
    regular_validations = []
    
    for validation in validations:
        key = validation['key']
        array_field, field_name = get_array_field_name(key)
        
        if array_field and field_name:
            if array_field not in array_validations:
                array_validations[array_field] = {}
            array_validations[array_field][normalize_key(field_name)] = {
                'expectedType': validation['expectedType'],
                'originalKey': key
            }
        else:
            regular_validations.append(validation)

    # If no array validations found, return all validations as regular
    if not array_validations:
        return validations

    # Validate each array field
    for array_field, field_validations in array_validations.items():
        array_data = array_payload.get(array_field, [])
        if not isinstance(array_data, list):
            results.append({
                'eventName': event_name,
                'key': array_field,
                'value': array_data,
                'expectedType': 'array',
                'receivedType': get_value_type(array_data),
                'validationStatus': 'Invalid array field'
            })
            continue

        # Validate each object in the array
        for index, obj in enumerate(array_data):
            if not isinstance(obj, dict):
                results.append({
                    'eventName': event_name,
                    'key': f"{array_field}[{index}]",
                    'value': obj,
                    'expectedType': None,
                    'receivedType': get_value_type(obj),
                    'validationStatus': 'Invalid object in array'
                })
                continue

            # Check for required fields and validate them
            for field_name, validation_info in field_validations.items():
                expected_type = validation_info['expectedType']
                original_key = validation_info['originalKey']
                value = obj.get(field_name)

                validation_result = validate_value(value, expected_type, event_name)
                status = 'Valid' if validation_result and validation_result != "Null value" else \
                        'Payload value is Empty' if validation_result == "Null value" else \
                        'Invalid/Wrong datatype/value'
                
                formatted_value = get_formatted_value(value, expected_type)
                
                results.append({
                    'eventName': event_name,
                    'key': f"{array_field}[{index}].{field_name}",
                    'value': formatted_value,
                    'expectedType': expected_type,
                    'receivedType': get_value_type(value),
                    'validationStatus': status
                })

            # Check for unexpected fields in this object
            for key in obj.keys():
                normalized_key = normalize_key(key)
                if normalized_key not in field_validations:
                    value = obj[key]
                    results.append({
                        'eventName': event_name,
                        'key': f"{array_field}[{index}].{key}",
                        'value': value,
                        'expectedType': None,
                        'receivedType': get_value_type(value),
                        'validationStatus': 'Unexpected key in array object'
                    })

    return regular_validations

def validate_conditional_fields(payload: Dict, validation: Dict) -> Tuple[bool, str]:
    """Validate fields based on conditional rules"""
    if 'condition' not in validation:
        return True, ""
    
    condition = validation['condition']
    if_field = condition.get('if_field')
    if_value = condition.get('if_value')
    then_field = condition.get('then_field')
    then_type = condition.get('then_type')
    
    if if_field in payload and payload[if_field] == if_value:
        if then_field not in payload:
            return False, f"Required field '{then_field}' is missing when '{if_field}' is '{if_value}'"
        if not validate_value(payload[then_field], then_type):
            return False, f"Field '{then_field}' has invalid type when '{if_field}' is '{if_value}'"
    
    return True, ""

def validate_required_fields(payload: Dict, validations: List[Dict]) -> List[Dict]:
    """Check for required fields and add validation results"""
    results = []
    required_fields = [v['key'] for v in validations if v.get('required', False)]
    
    for field in required_fields:
        if field not in payload:
            results.append({
                'eventName': payload.get('eventName', 'unknown'),
                'key': field,
                'value': None,
                'expectedType': next((v['expectedType'] for v in validations if v['key'] == field), None),
                'receivedType': 'not present',
                'validationStatus': 'Required field missing',
                'comment': 'Required field is missing in the payload'
            })
    
    return results

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "message": "Validation API is running"}), 200

@app.route('/test')
def test_endpoint():
    return jsonify({"message": "Test endpoint working", "endpoints": ["/upload", "/validate-website-logs", "/validate-website-logs-v2", "/filter", "/download"]}), 200

@app.route('/')
def index():
    return render_template('index.html')

# FCM Service initialization
fcm_service = None
stored_fcm_credentials = None  # Store credentials server-side

@app.route('/push-notification')
def push_notification():
    return render_template('push_notification.html')

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/upload', methods=['POST', 'OPTIONS'])
def upload():
    app.logger.info('Upload endpoint called')
    if request.method == 'OPTIONS':
        return '', 200

    if 'csv_file' not in request.files:
        return jsonify({"error": "CSV file is required"}), 400
    if 'txt_file' not in request.files and 'manual_log' not in request.form:
        return jsonify({"error": "TXT file or manual log input is required"}), 400

    try:
        # Log file upload
        log_details = {
            'csv_file': request.files['csv_file'].filename,
            'timestamp': datetime.now().isoformat()
        }
        if 'txt_file' in request.files:
            log_details['txt_file'] = request.files['txt_file'].filename
        elif 'manual_log' in request.form:
            log_details['manual_log'] = 'manual_log_input'
        log_validation_event('file_upload', log_details)

        # Parse the CSV file
        csv_file = request.files['csv_file']
        csv_file.stream.seek(0)
        csv_reader = csv.DictReader(csv_file.stream.read().decode('utf-8').splitlines())
        
        # Group CSV rows by eventName with case normalization
        event_validations, events_without_payload = parse_csv_with_case_normalization(csv_reader)
        
        # No webhook/SSE logic, just proceed
        # (no-op)

        # Parse the TXT file or manual log
        if 'txt_file' in request.files:
            txt_file = request.files['txt_file']
            txt_file.stream.seek(0)
            txt_content = txt_file.stream.read().decode('utf-8')
        elif 'manual_log' in request.form:
            txt_content = request.form['manual_log']
        else:
            return jsonify({"error": "TXT file or manual log input is required"}), 400

        event_pattern = r"(?:Single Event|Event Payload|Web Event): (\{.*?\})(?=\s*(?:Single Event|Event Payload|Web Event):|$)"

        event_logs = re.findall(event_pattern, txt_content, re.DOTALL)
        parsed_logs = []
        
        # Store original log entries for download feature
        original_logs = {}
        
        for log in event_logs:
            try:
                parsed_log = json.loads(log)
                # Handle Single Event format
                if 'eventName' in parsed_log:
                    # If the log already has eventName, use it directly
                    event_name = parsed_log['eventName'].lower()  # Convert to lowercase
                    parsed_log['eventName'] = event_name
                    parsed_log['payload'] = parsed_log.get('payload', {})
                    # Store the original log entry
                    original_logs[event_name] = f"Event Payload: {log}"
                elif 'event' in parsed_log:
                    # Handle old Single Event format
                    event_name = parsed_log['event'].lower()  # Convert to lowercase
                    parsed_log['eventName'] = event_name
                    parsed_log['payload'] = parsed_log.get('data', {})
                    # Store the original log entry
                    original_logs[event_name] = f"Event Payload: {log}"
                parsed_logs.append(parsed_log)
            except json.JSONDecodeError:
                continue

        # Map event names to payloads
        event_payload_map = {
            log.get("eventName"): log.get("payload", {}) for log in parsed_logs
        }
        
        # Validate the data
        results = []
        for event_name, validations in event_validations.items():
            event_in_logs = event_name in event_payload_map
            payload = event_payload_map.get(event_name, {})
            
            # Check if event name is present in the logs
            if not event_in_logs:
                # Event name from CSV is not present in the logs
                results.append({
                    'eventName': event_name,
                    'key': 'EVENT_NAME',
                    'value': event_name,
                    'expectedType': 'event',
                    'receivedType': 'not present in logs',
                    'validationStatus': 'Event name not present in the logs',
                    'comment': f'Event "{event_name}" from CSV was not found in the uploaded log file'
                })
                # Skip further validation for this event since it's not in the logs
                continue

            # Handle events that are expected to have no payload
            if event_name in events_without_payload:
                is_empty = not payload
                status = 'Valid' if is_empty else 'Unexpected payload present'
                comment = 'Event logged without payload as expected' if is_empty else 'Event should not contain payload data'
                display_key = 'No Payload in the sheet' if is_empty else 'PAYLOAD'
                display_value = 'No Payload in the sheet' if is_empty else json.dumps(payload)
                results.append({
                    'eventName': event_name,
                    'key': display_key,
                    'value': display_value,
                    'expectedType': 'No payload expected',
                    'receivedType': 'empty object' if is_empty else get_value_type(payload),
                    'validationStatus': status,
                    'comment': comment
                })
                continue
            
            # Check required fields first
            required_results = validate_required_fields(payload, validations)
            results.extend(required_results)

            # Check conditional validations
            for validation in validations:
                is_valid, error_msg = validate_conditional_fields(payload, validation)
                if not is_valid:
                    results.append({
                        'eventName': event_name,
                        'key': validation['key'],
                        'value': None,
                        'expectedType': validation['expectedType'],
                        'receivedType': 'invalid',
                        'validationStatus': error_msg
                    })

            # Check for array fields in the payload
            array_fields = {k: v for k, v in payload.items() if isinstance(v, list)}
            if array_fields:
                regular_validations = validate_array_of_objects(payload, validations, event_name, results)
                
                # Validate regular fields (non-array fields)
                normalized_payload = {normalize_key(k): v for k, v in payload.items() if k not in array_fields}
                
                # Check for extra keys in regular fields
                extra_keys = set(normalized_payload.keys()) - set([normalize_key(v['key']) for v in regular_validations])
                for extra_key in extra_keys:
                    value = normalized_payload.get(extra_key)
                    results.append({
                        'eventName': event_name,
                        'key': extra_key,
                        'value': value,
                        'expectedType': 'EXTRA',
                        'receivedType': get_value_type(value),
                        'validationStatus': 'Extra key present in the log'
                    })

                # Validate regular fields
                for validation in regular_validations:
                    key = validation['key']
                    expected_type = validation['expectedType']
                    normalized_key = normalize_key(key)
                    value = normalized_payload.get(normalized_key)

                    if not key or not expected_type:
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': None,
                            'expectedType': expected_type,
                            'receivedType': 'unknown',
                            'validationStatus': 'Invalid CSV row'
                        })
                    elif normalized_key not in normalized_payload:
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': None,
                            'expectedType': expected_type,
                            'receivedType': 'not present',
                            'validationStatus': 'Payload not present in the log'
                        })
                    else:
                        validation_result = validate_value(value, expected_type, event_name)
                        status = 'Valid' if validation_result and validation_result != "Null value" else \
                                'Payload value is Empty' if validation_result == "Null value" else \
                                'Invalid/Wrong datatype/value'
                        formatted_value = get_formatted_value(value, expected_type)
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': formatted_value,
                            'expectedType': expected_type,
                            'receivedType': get_value_type(value),
                            'validationStatus': status
                        })
            else:
                # Regular validation for non-array payloads
                normalized_payload = {normalize_key(k): v for k, v in payload.items()}
                extra_keys = set(normalized_payload.keys()) - set([normalize_key(v['key']) for v in validations])
                for extra_key in extra_keys:
                    value = normalized_payload.get(extra_key)
                    results.append({
                        'eventName': event_name,
                        'key': extra_key,
                        'value': value,
                        'expectedType': 'EXTRA',
                        'receivedType': get_value_type(value),
                        'validationStatus': 'Extra key present in the log'
                    })

                for validation in validations:
                    key = validation['key']
                    expected_type = validation['expectedType']

                    if not key or not expected_type:
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': None,
                            'expectedType': expected_type,
                            'receivedType': 'unknown',
                            'validationStatus': 'Invalid CSV row'
                        })
                        continue

                    normalized_key = normalize_key(key)
                    value = normalized_payload.get(normalized_key)

                    if normalized_key not in normalized_payload:
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': None,
                            'expectedType': expected_type,
                            'receivedType': 'not present',
                            'validationStatus': 'Payload not present in the log'
                        })
                    else:
                        validation_result = validate_value(value, expected_type, event_name)
                        status = 'Valid' if validation_result and validation_result != "Null value" else \
                                'Payload value is Empty' if validation_result == "Null value" else \
                                'Invalid/Wrong datatype/value'
                        formatted_value = get_formatted_value(value, expected_type)
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': formatted_value,
                            'expectedType': expected_type,
                            'receivedType': get_value_type(value),
                            'validationStatus': status
                        })

        # Calculate event counts
        csv_events = set(event_validations.keys())
        log_events = set(event_payload_map.keys())
        
        # Add validation entries for extra events (events in logs but not in CSV)
        extra_events = log_events - csv_events
        for extra_event in extra_events:
            payload = event_payload_map.get(extra_event, {})
            results.append({
                'eventName': extra_event,
                'key': 'EVENT_NAME',
                'value': extra_event,
                'expectedType': 'event',
                'receivedType': 'extra event in logs',
                'validationStatus': 'Extra event present in logs',
                'comment': f'Event "{extra_event}" found in logs but not defined in CSV validation rules'
            })
            
            # Also add entries for all fields in the extra event's payload
            if payload:
                for key, value in payload.items():
                    results.append({
                        'eventName': extra_event,
                        'key': key,
                        'value': value,
                        'expectedType': 'EXTRA_EVENT_FIELD',
                        'receivedType': get_value_type(value),
                        'validationStatus': 'Field from extra event',
                        'comment': f'Field from event "{extra_event}" which is not defined in CSV validation rules'
                    })
        
        # Log validation results
        log_validation_event('validation_complete', {
            'total_validations': len(results),
            'valid_count': sum(1 for r in results if r['validationStatus'] == 'Valid'),
            'invalid_count': sum(1 for r in results if r['validationStatus'] != 'Valid'),
            'csv_events_count': len(csv_events),
            'log_events_count': len(log_events),
            'extra_events_count': len(extra_events)
        })

        # After results are generated, compute fully valid events
        event_payloads = defaultdict(list)
        for r in results:
            event_payloads[r['eventName']].append(r['validationStatus'])
        fully_valid_events = [
            event for event, statuses in event_payloads.items()
            if all(status == 'Valid' for status in statuses)
        ]

        # Return results with event count information
        response_data = {
            'results': results,
            'summary': {
                'csv_events_count': len(csv_events),
                'log_events_count': len(log_events),
                'csv_events': list(csv_events),
                'log_events': list(log_events),
                'extra_events': list(extra_events)
            },
            'fully_valid_events': fully_valid_events,
            'original_logs': original_logs # Add original_logs to the response
        }
        
        return jsonify(response_data)

    except Exception as e:
        app.logger.error(f'Error processing files: {str(e)}')
        return jsonify({"error": str(e)}), 500

@app.route('/filter', methods=['POST', 'OPTIONS'])
def filter_results():
    app.logger.info('Filter endpoint called')
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        app.logger.info(f'Filter data received: {data}')
        
        results = data.get('results', [])
        filters = data.get('filters', {})
        sort_by = data.get('sort_by')
        sort_order = data.get('sort_order', 'asc')
        date_range = data.get('date_range', {})
        search_term = data.get('search_term', '').lower()
        
        # Apply filters
        filtered_results = results
        if filters:
            for field, values in filters.items():
                if values and isinstance(values, list) and len(values) > 0:
                    if field == 'search_term':
                        filtered_results = [
                            r for r in filtered_results 
                            if any(search_term in str(v).lower() for v in r.values())
                        ]
                    else:
                        filtered_results = [
                            r for r in filtered_results 
                            if str(r.get(field, '')).lower() in [str(v).lower() for v in values]
                        ]
        
        # Apply date range filter
        if date_range:
            start_date = datetime.fromisoformat(date_range.get('start', ''))
            end_date = datetime.fromisoformat(date_range.get('end', ''))
            filtered_results = [
                r for r in filtered_results 
                if r.get('expectedType') == 'date' and 
                start_date <= datetime.fromisoformat(r.get('value', '')) <= end_date
            ]
        
        # Apply sorting
        if sort_by:
            filtered_results.sort(
                key=lambda x: str(x.get(sort_by, '')).lower(),
                reverse=(sort_order == 'desc')
            )
        
        app.logger.info(f'Filtered results count: {len(filtered_results)}')
        return jsonify(filtered_results)
    except Exception as e:
        app.logger.error(f'Error in filter endpoint: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/validate-website-logs', methods=['POST', 'OPTIONS'])
def validate_website_logs():
    app.logger.info('Website logs validation endpoint called')
    if request.method == 'OPTIONS':
        return '', 200
        
    if 'csv_file' not in request.files or 'txt_file' not in request.files:
        return jsonify({"error": "Both CSV and TXT files are required"}), 400

    try:
        # Log file upload
        log_validation_event('website_logs_upload', {
            'csv_file': request.files['csv_file'].filename,
            'txt_file': request.files['txt_file'].filename,
            'timestamp': datetime.now().isoformat()
        })

        # Parse the CSV file (same as before)
        csv_file = request.files['csv_file']
        csv_file.stream.seek(0)
        csv_reader = csv.DictReader(csv_file.stream.read().decode('utf-8').splitlines())
        
        # Group CSV rows by eventName with case normalization
        event_validations, events_without_payload = parse_csv_with_case_normalization(csv_reader)

        # Parse the TXT file for website logs format
        txt_file = request.files['txt_file']
        txt_file.stream.seek(0)
        txt_content = txt_file.stream.read().decode('utf-8')
        
        # Parse each line as a separate JSON object
        parsed_logs = []
        lines = txt_content.strip().split('\n')
        
        # Store original log entries for download feature
        original_logs = {}
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                log_entry = json.loads(line)
                
                # Extract event name and payload from website log format
                event_name = log_entry.get('eventname')
                payload = log_entry.get('payload', {})
                
                if event_name:
                    event_name_lower = event_name.lower()  # Convert to lowercase
                    parsed_logs.append({
                        'eventName': event_name_lower,
                        'payload': payload,
                        'line_number': line_num,
                        'full_log': log_entry
                    })
                    # Store the original log line
                    original_logs[event_name_lower] = line
                else:
                    # Log warning for entries without eventname
                    app.logger.warning(f'Line {line_num}: Missing eventname in log entry')
                    
            except json.JSONDecodeError as e:
                app.logger.warning(f'Line {line_num}: Invalid JSON format - {str(e)}')
                continue

        # Map event names to payloads
        event_payload_map = {}
        for log in parsed_logs:
            event_name = log['eventName']
            if event_name not in event_payload_map:
                event_payload_map[event_name] = []
            event_payload_map[event_name].append({
                'payload': log['payload'],
                'line_number': log['line_number'],
                'full_log': log['full_log']
            })

        # Validate the data
        results = []
        for event_name, validations in event_validations.items():
            log_entries = event_payload_map.get(event_name, [])
            
            # Check if event name is present in the logs
            if not log_entries:
                # Event name from CSV is not present in the logs
                results.append({
                    'eventName': event_name,
                    'key': 'EVENT_NAME',
                    'value': event_name,
                    'expectedType': 'event',
                    'receivedType': 'not present in logs',
                    'validationStatus': 'Event name not present in the logs',
                    'comment': f'Event "{event_name}" from CSV was not found in the uploaded log file'
                })
                continue

            # Handle events that are expected to have no payload
            if event_name in events_without_payload:
                for entry in log_entries:
                    payload = entry['payload']
                    line_number = entry['line_number']
                    is_empty = not payload
                    status = 'Valid' if is_empty else 'Unexpected payload present'
                    comment = 'Event logged without payload as expected' if is_empty else 'Event should not contain payload data'
                    display_key = 'No Payload in the sheet' if is_empty else 'PAYLOAD'
                    display_value = 'No Payload in the sheet' if is_empty else json.dumps(payload)
                    results.append({
                        'eventName': event_name,
                        'key': display_key,
                        'value': display_value,
                        'expectedType': 'No payload expected',
                        'receivedType': 'empty object' if is_empty else get_value_type(payload),
                        'validationStatus': status,
                        'line_number': line_number,
                        'comment': comment
                    })
                continue
            
            # Validate each occurrence of this event
            for entry in log_entries:
                payload = entry['payload']
                line_number = entry['line_number']
                
                # Check required fields first
                required_results = validate_required_fields(payload, validations)
                for result in required_results:
                    result['line_number'] = line_number
                results.extend(required_results)

                # Check conditional validations
                for validation in validations:
                    is_valid, error_msg = validate_conditional_fields(payload, validation)
                    if not is_valid:
                        results.append({
                            'eventName': event_name,
                            'key': validation['key'],
                            'value': None,
                            'expectedType': validation['expectedType'],
                            'receivedType': 'invalid',
                            'validationStatus': error_msg,
                            'line_number': line_number
                        })

                # Check for array fields in the payload
                array_fields = {k: v for k, v in payload.items() if isinstance(v, list)}
                if array_fields:
                    regular_validations = validate_array_of_objects(payload, validations, event_name, results)
                    
                    # Validate regular fields (non-array fields)
                    normalized_payload = {normalize_key(k): v for k, v in payload.items() if k not in array_fields}
                    
                    # Check for extra keys in regular fields
                    extra_keys = set(normalized_payload.keys()) - set([normalize_key(v['key']) for v in regular_validations])
                    for extra_key in extra_keys:
                        value = normalized_payload.get(extra_key)
                        results.append({
                            'eventName': event_name,
                            'key': extra_key,
                            'value': value,
                            'expectedType': 'EXTRA',
                            'receivedType': get_value_type(value),
                            'validationStatus': 'Extra key present in the log',
                            'line_number': line_number
                        })

                    # Validate regular fields
                    for validation in regular_validations:
                        key = validation['key']
                        expected_type = validation['expectedType']
                        normalized_key = normalize_key(key)
                        value = normalized_payload.get(normalized_key)

                        if not key or not expected_type:
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': None,
                                'expectedType': expected_type,
                                'receivedType': 'unknown',
                                'validationStatus': 'Invalid CSV row',
                                'line_number': line_number
                            })
                        elif normalized_key not in normalized_payload:
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': None,
                                'expectedType': expected_type,
                                'receivedType': 'not present',
                                'validationStatus': 'Payload not present in the log',
                                'line_number': line_number
                            })
                        else:
                            validation_result = validate_value(value, expected_type, event_name)
                            status = 'Valid' if validation_result and validation_result != "Null value" else \
                                    'Payload value is Empty' if validation_result == "Null value" else \
                                    'Invalid/Wrong datatype/value'
                            formatted_value = get_formatted_value(value, expected_type)
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': formatted_value,
                                'expectedType': expected_type,
                                'receivedType': get_value_type(value),
                                'validationStatus': status,
                                'line_number': line_number
                            })
                else:
                    # Regular validation for non-array payloads
                    normalized_payload = {normalize_key(k): v for k, v in payload.items()}
                    extra_keys = set(normalized_payload.keys()) - set([normalize_key(v['key']) for v in validations])
                    for extra_key in extra_keys:
                        value = normalized_payload.get(extra_key)
                        results.append({
                            'eventName': event_name,
                            'key': extra_key,
                            'value': value,
                            'expectedType': 'EXTRA',
                            'receivedType': get_value_type(value),
                            'validationStatus': 'Extra key present in the log',
                            'line_number': line_number
                        })

                    for validation in validations:
                        key = validation['key']
                        expected_type = validation['expectedType']

                        if not key or not expected_type:
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': None,
                                'expectedType': expected_type,
                                'receivedType': 'unknown',
                                'validationStatus': 'Invalid CSV row',
                                'line_number': line_number
                            })
                            continue

                        normalized_key = normalize_key(key)
                        value = normalized_payload.get(normalized_key)

                        if normalized_key not in normalized_payload:
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': None,
                                'expectedType': expected_type,
                                'receivedType': 'not present',
                                'validationStatus': 'Payload not present in the log',
                                'line_number': line_number
                            })
                        else:
                            validation_result = validate_value(value, expected_type, event_name)
                            status = 'Valid' if validation_result and validation_result != "Null value" else \
                                    'Payload value is Empty' if validation_result == "Null value" else \
                                    'Invalid/Wrong datatype/value'
                            formatted_value = get_formatted_value(value, expected_type)
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': formatted_value,
                                'expectedType': expected_type,
                                'receivedType': get_value_type(value),
                                'validationStatus': status,
                                'line_number': line_number
                            })

        # Calculate event counts
        csv_events = set(event_validations.keys())
        log_events = set(event_payload_map.keys())
        
        # Add validation entries for extra events (events in logs but not in CSV)
        extra_events = log_events - csv_events
        for extra_event in extra_events:
            log_entries = event_payload_map.get(extra_event, [])
            for entry in log_entries:
                payload = entry['payload']
                line_number = entry['line_number']
                
                results.append({
                    'eventName': extra_event,
                    'key': 'EVENT_NAME',
                    'value': extra_event,
                    'expectedType': 'event',
                    'receivedType': 'extra event in logs',
                    'validationStatus': 'Extra event present in logs',
                    'comment': f'Event "{extra_event}" found in logs but not defined in CSV validation rules',
                    'line_number': line_number
                })
                
                # Also add entries for all fields in the extra event's payload
                if payload:
                    for key, value in payload.items():
                        results.append({
                            'eventName': extra_event,
                            'key': key,
                            'value': value,
                            'expectedType': 'EXTRA_EVENT_FIELD',
                            'receivedType': get_value_type(value),
                            'validationStatus': 'Field from extra event',
                            'comment': f'Field from event "{extra_event}" which is not defined in CSV validation rules',
                            'line_number': line_number
                        })
        
        # Log validation results
        log_validation_event('website_logs_validation_complete', {
            'total_validations': len(results),
            'valid_count': sum(1 for r in results if r['validationStatus'] == 'Valid'),
            'invalid_count': sum(1 for r in results if r['validationStatus'] != 'Valid'),
            'csv_events_count': len(csv_events),
            'log_events_count': len(log_events),
            'extra_events_count': len(extra_events),
            'total_log_entries': len(parsed_logs)
        })

        # After results are generated, compute fully valid events
        event_payloads = defaultdict(list)
        for r in results:
            event_payloads[r['eventName']].append(r['validationStatus'])
        fully_valid_events = [
            event for event, statuses in event_payloads.items()
            if all(status == 'Valid' for status in statuses)
        ]
        response_data = {
            'results': results,
            'summary': {
                'csv_events_count': len(csv_events),
                'log_events_count': len(log_events),
                'csv_events': list(csv_events),
                'log_events': list(log_events),
                'extra_events': list(extra_events),
                'total_log_entries': len(parsed_logs)
            },
            'fully_valid_events': fully_valid_events,
            'original_logs': original_logs
        }
        return jsonify(response_data)

    except Exception as e:
        app.logger.error(f'Error processing website log files: {str(e)}')
        return jsonify({"error": str(e)}), 500

@app.route('/validate-website-logs-v2', methods=['POST', 'OPTIONS'])
def validate_website_logs_v2():
    app.logger.info('Website logs v2 validation endpoint called')
    if request.method == 'OPTIONS':
        return '', 200
        
    if 'csv_file' not in request.files or 'txt_file' not in request.files:
        return jsonify({"error": "Both CSV and TXT files are required"}), 400

    try:
        # Log file upload
        log_validation_event('website_logs_v2_upload', {
            'csv_file': request.files['csv_file'].filename,
            'txt_file': request.files['txt_file'].filename,
            'timestamp': datetime.now().isoformat()
        })

        # Parse the CSV file (same as before)
        csv_file = request.files['csv_file']
        csv_file.stream.seek(0)
        csv_reader = csv.DictReader(csv_file.stream.read().decode('utf-8').splitlines())
        
        # Group CSV rows by eventName with case normalization
        event_validations, events_without_payload = parse_csv_with_case_normalization(csv_reader)

        # Parse the TXT file for website logs v2 format
        txt_file = request.files['txt_file']
        txt_file.stream.seek(0)
        txt_content = txt_file.stream.read().decode('utf-8')
        
        # Parse JSON objects from the content
        parsed_logs = []
        
        # Store original log entries for download feature
        original_logs = {}
        
        # Try to parse as single JSON object first (for single object files)
        try:
            single_json = json.loads(txt_content.strip())
            if isinstance(single_json, dict) and single_json.get('event'):
                # Single JSON object with event
                event_name = single_json.get('event')
                system_fields = {'event', 'url', 'purl', 'title', 'npv', 'sts', 'pts', 'timestamp'}
                payload = {k: v for k, v in single_json.items() if k not in system_fields}
                
                event_name_lower = event_name.lower()
                parsed_logs.append({
                    'eventName': event_name_lower,
                    'payload': payload,
                    'line_number': 1,
                    'full_log': single_json
                })
                # Store the original log entry
                original_logs[event_name_lower] = txt_content.strip()
            else:
                # Single JSON object but no event, try to parse as array
                if isinstance(single_json, list):
                    for idx, item in enumerate(single_json, 1):
                        if isinstance(item, dict) and item.get('event'):
                            event_name = item.get('event')
                            system_fields = {'event', 'url', 'purl', 'title', 'npv', 'sts', 'pts', 'timestamp'}
                            payload = {k: v for k, v in item.items() if k not in system_fields}
                            
                            event_name_lower = event_name.lower()
                            parsed_logs.append({
                                'eventName': event_name_lower,
                                'payload': payload,
                                'line_number': idx,
                                'full_log': item
                            })
                            # Store the original log entry
                            original_logs[event_name_lower] = json.dumps(item)
        except json.JSONDecodeError:
            # Not a single JSON object, try line-by-line parsing
            lines = txt_content.strip().split('\n')
            current_json = ""
            line_num = 0
            
            for line in lines:
                line_num += 1
                line = line.strip()
                
                if not line:
                    continue
                
                # Add line to current JSON string
                current_json += line
                
                # Try to parse the accumulated JSON
                try:
                    log_entry = json.loads(current_json)
                    
                    # Extract event name and payload from website log v2 format
                    event_name = log_entry.get('event')
                    
                    if event_name:
                        # Create payload by excluding system fields
                        system_fields = {'event', 'url', 'purl', 'title', 'npv', 'sts', 'pts', 'timestamp'}
                        payload = {k: v for k, v in log_entry.items() if k not in system_fields}
                        
                        event_name_lower = event_name.lower()
                        parsed_logs.append({
                            'eventName': event_name_lower,
                            'payload': payload,
                            'line_number': line_num,
                            'full_log': log_entry
                        })
                        
                        # Store the original log entry
                        original_logs[event_name_lower] = current_json
                        
                        # Reset for next JSON object
                        current_json = ""
                    else:
                        # Log warning for entries without event
                        app.logger.warning(f'Line {line_num}: Missing event in log entry')
                        current_json = ""
                        
                except json.JSONDecodeError:
                    # Incomplete JSON, continue accumulating lines
                    continue

        # Map event names to payloads
        event_payload_map = {}
        for log in parsed_logs:
            event_name = log['eventName']
            if event_name not in event_payload_map:
                event_payload_map[event_name] = []
            event_payload_map[event_name].append({
                'payload': log['payload'],
                'line_number': log['line_number'],
                'full_log': log['full_log']
            })
        
        # Validate the data
        results = []
        for event_name, validations in event_validations.items():
            log_entries = event_payload_map.get(event_name, [])
            
            # Check if event name is present in the logs
            if not log_entries:
                # Event name from CSV is not present in the logs
                results.append({
                    'eventName': event_name,
                    'key': 'EVENT_NAME',
                    'value': event_name,
                    'expectedType': 'event',
                    'receivedType': 'not present in logs',
                    'validationStatus': 'Event name not present in the logs',
                    'comment': f'Event "{event_name}" from CSV was not found in the uploaded log file'
                })
                continue

            # Handle events that are expected to have no payload
            if event_name in events_without_payload:
                for entry in log_entries:
                    payload = entry['payload']
                    line_number = entry['line_number']
                    is_empty = not payload
                    status = 'Valid' if is_empty else 'Unexpected payload present'
                    comment = 'Event logged without payload as expected' if is_empty else 'Event should not contain payload data'
                    display_key = 'No Payload in the sheet' if is_empty else 'PAYLOAD'
                    display_value = 'No Payload in the sheet' if is_empty else json.dumps(payload)
                    results.append({
                        'eventName': event_name,
                        'key': display_key,
                        'value': display_value,
                        'expectedType': 'No payload expected',
                        'receivedType': 'empty object' if is_empty else get_value_type(payload),
                        'validationStatus': status,
                        'line_number': line_number,
                        'comment': comment
                    })
                continue
            
            # Validate each occurrence of this event
            for entry in log_entries:
                payload = entry['payload']
                line_number = entry['line_number']
                
                # Check required fields first
                required_results = validate_required_fields(payload, validations)
                for result in required_results:
                    result['line_number'] = line_number
                results.extend(required_results)

                # Check conditional validations
                for validation in validations:
                    is_valid, error_msg = validate_conditional_fields(payload, validation)
                    if not is_valid:
                        results.append({
                            'eventName': event_name,
                            'key': validation['key'],
                            'value': None,
                            'expectedType': validation['expectedType'],
                            'receivedType': 'invalid',
                            'validationStatus': error_msg,
                            'line_number': line_number
                        })

                # Check for array fields in the payload
                array_fields = {k: v for k, v in payload.items() if isinstance(v, list)}
                if array_fields:
                    regular_validations = validate_array_of_objects(payload, validations, event_name, results)
                    
                    # Validate regular fields (non-array fields)
                    normalized_payload = {normalize_key(k): v for k, v in payload.items() if k not in array_fields}
                    
                    # Check for extra keys in regular fields
                    extra_keys = set(normalized_payload.keys()) - set([normalize_key(v['key']) for v in regular_validations])
                    for extra_key in extra_keys:
                        value = normalized_payload.get(extra_key)
                        results.append({
                            'eventName': event_name,
                            'key': extra_key,
                            'value': value,
                            'expectedType': 'EXTRA',
                            'receivedType': get_value_type(value),
                            'validationStatus': 'Extra key present in the log',
                            'line_number': line_number
                        })

                    # Validate regular fields
                    for validation in regular_validations:
                        key = validation['key']
                        expected_type = validation['expectedType']
                        normalized_key = normalize_key(key)
                        value = normalized_payload.get(normalized_key)

                        if not key or not expected_type:
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': None,
                                'expectedType': expected_type,
                                'receivedType': 'unknown',
                                'validationStatus': 'Invalid CSV row',
                                'line_number': line_number
                            })
                        elif normalized_key not in normalized_payload:
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': None,
                                'expectedType': expected_type,
                                'receivedType': 'not present',
                                'validationStatus': 'Payload not present in the log',
                                'line_number': line_number
                            })
                        else:
                            validation_result = validate_value(value, expected_type, event_name)
                            status = 'Valid' if validation_result and validation_result != "Null value" else \
                                    'Payload value is Empty' if validation_result == "Null value" else \
                                    'Invalid/Wrong datatype/value'
                            formatted_value = get_formatted_value(value, expected_type)
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': formatted_value,
                                'expectedType': expected_type,
                                'receivedType': get_value_type(value),
                                'validationStatus': status,
                                'line_number': line_number
                            })
                else:
                    # Regular validation for non-array payloads
                    normalized_payload = {normalize_key(k): v for k, v in payload.items()}
                    extra_keys = set(normalized_payload.keys()) - set([normalize_key(v['key']) for v in validations])
                    for extra_key in extra_keys:
                        value = normalized_payload.get(extra_key)
                        results.append({
                            'eventName': event_name,
                            'key': extra_key,
                            'value': value,
                            'expectedType': 'EXTRA',
                            'receivedType': get_value_type(value),
                            'validationStatus': 'Extra key present in the log',
                            'line_number': line_number
                        })

                    for validation in validations:
                        key = validation['key']
                        expected_type = validation['expectedType']

                        if not key or not expected_type:
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': None,
                                'expectedType': expected_type,
                                'receivedType': 'unknown',
                                'validationStatus': 'Invalid CSV row',
                                'line_number': line_number
                            })
                            continue

                        normalized_key = normalize_key(key)
                        value = normalized_payload.get(normalized_key)

                        if normalized_key not in normalized_payload:
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': None,
                                'expectedType': expected_type,
                                'receivedType': 'not present',
                                'validationStatus': 'Payload not present in the log',
                                'line_number': line_number
                            })
                        else:
                            validation_result = validate_value(value, expected_type, event_name)
                            status = 'Valid' if validation_result and validation_result != "Null value" else \
                                    'Payload value is Empty' if validation_result == "Null value" else \
                                    'Invalid/Wrong datatype/value'
                            formatted_value = get_formatted_value(value, expected_type)
                            results.append({
                                'eventName': event_name,
                                'key': key,
                                'value': formatted_value,
                                'expectedType': expected_type,
                                'receivedType': get_value_type(value),
                                'validationStatus': status,
                                'line_number': line_number
                            })

        # Calculate event counts
        csv_events = set(event_validations.keys())
        log_events = set(event_payload_map.keys())
        
        # Add validation entries for extra events (events in logs but not in CSV)
        extra_events = log_events - csv_events
        for extra_event in extra_events:
            log_entries = event_payload_map.get(extra_event, [])
            for entry in log_entries:
                payload = entry['payload']
                line_number = entry['line_number']
                
                results.append({
                    'eventName': extra_event,
                    'key': 'EVENT_NAME',
                    'value': extra_event,
                    'expectedType': 'event',
                    'receivedType': 'extra event in logs',
                    'validationStatus': 'Extra event present in logs',
                    'comment': f'Event "{extra_event}" found in logs but not defined in CSV validation rules',
                    'line_number': line_number
                })
                
                # Also add entries for all fields in the extra event's payload
                if payload:
                    for key, value in payload.items():
                        results.append({
                            'eventName': extra_event,
                            'key': key,
                            'value': value,
                            'expectedType': 'EXTRA_EVENT_FIELD',
                            'receivedType': get_value_type(value),
                            'validationStatus': 'Field from extra event',
                            'comment': f'Field from event "{extra_event}" which is not defined in CSV validation rules',
                            'line_number': line_number
                        })
        
        # Log validation results
        log_validation_event('website_logs_v2_validation_complete', {
            'total_validations': len(results),
            'valid_count': sum(1 for r in results if r['validationStatus'] == 'Valid'),
            'invalid_count': sum(1 for r in results if r['validationStatus'] != 'Valid'),
            'csv_events_count': len(csv_events),
            'log_events_count': len(log_events),
            'extra_events_count': len(extra_events),
            'total_log_entries': len(parsed_logs)
        })

        # After results are generated, compute fully valid events
        event_payloads = defaultdict(list)
        for r in results:
            event_payloads[r['eventName']].append(r['validationStatus'])
        fully_valid_events = [
            event for event, statuses in event_payloads.items()
            if all(status == 'Valid' for status in statuses)
        ]
        response_data = {
            'results': results,
            'summary': {
                'csv_events_count': len(csv_events),
                'log_events_count': len(log_events),
                'csv_events': list(csv_events),
                'log_events': list(log_events),
                'extra_events': list(extra_events),
                'total_log_entries': len(parsed_logs)
            },
            'fully_valid_events': fully_valid_events,
            'original_logs': original_logs
        }
        return jsonify(response_data)

    except Exception as e:
        app.logger.error(f'Error processing website log v2 files: {str(e)}')
        return jsonify({"error": str(e)}), 500

@app.route('/download', methods=['POST', 'OPTIONS'])
def download_results():
    app.logger.info('Download endpoint called')
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        app.logger.info('Download data received')
        
        results = data.get('results', [])
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['eventName', 'key', 'value', 'expectedType', 'receivedType', 'validationStatus', 'comment'])
        writer.writeheader()
        
        # Add comments to results if not present and prepare clean results for CSV
        clean_results = []
        for result in results:
            # Create a clean copy without line_number
            clean_result = {
                'eventName': result.get('eventName', ''),
                'key': result.get('key', ''),
                'value': result.get('value', ''),
                'expectedType': result.get('expectedType', ''),
                'receivedType': result.get('receivedType', ''),
                'validationStatus': result.get('validationStatus', ''),
                'comment': result.get('comment', '')
            }
            
            # Add comment if not present
            if not clean_result['comment']:
                if clean_result['validationStatus'] == 'Valid':
                    clean_result['comment'] = 'Field validation passed'
                elif clean_result['validationStatus'] == 'Invalid/Wrong datatype/value':
                    clean_result['comment'] = f"Expected type: {clean_result['expectedType']}, Received type: {clean_result['receivedType']}"
                elif clean_result['validationStatus'] == 'Payload value is Empty':
                    clean_result['comment'] = 'Field value is empty or null'
                elif clean_result['validationStatus'] == 'Extra key present in the log':
                    clean_result['comment'] = 'This is an EXTRA payload or there is a spelling mistake with the required payload'
                elif clean_result['validationStatus'] == 'Payload not present in the log':
                    clean_result['comment'] = 'Field is missing in the payload'
                elif clean_result['validationStatus'] == 'Event name not present in the logs':
                    clean_result['comment'] = f'Event "{clean_result["eventName"]}" from CSV was not found in the uploaded log file'
                elif clean_result['validationStatus'] == 'Extra event present in logs':
                    clean_result['comment'] = f'Event "{clean_result["eventName"]}" found in logs but not defined in CSV validation rules'
                elif clean_result['validationStatus'] == 'Field from extra event':
                    clean_result['comment'] = f'Field from event "{clean_result["eventName"]}" which is not defined in CSV validation rules'
                else:
                    clean_result['comment'] = clean_result['validationStatus']
            
            clean_results.append(clean_result)
        
        writer.writerows(clean_results)
        
        # Create response
        output.seek(0)
        app.logger.info('CSV file generated successfully')
        return Response(
            output,
            mimetype='text/csv',
            headers={
                'Content-Disposition': 'attachment; filename=validation_results.csv',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            }
        )
    except Exception as e:
        app.logger.error(f'Error in download endpoint: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/download-valid-events', methods=['POST', 'OPTIONS'])
def download_valid_events():
    app.logger.info('Download valid events endpoint called')
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        app.logger.info('Download valid events data received')
        
        results = data.get('results', [])
        logs_data = data.get('logs_data', {})  # This should contain the original log entries
        
        app.logger.info(f'Number of results: {len(results)}')
        app.logger.info(f'Number of log entries: {len(logs_data)}')
        app.logger.info(f'Log entries keys: {list(logs_data.keys())}')
        
        # Filter only valid events
        valid_results = [r for r in results if r['validationStatus'] == 'Valid']
        app.logger.info(f'Number of valid results: {len(valid_results)}')
        
        # Group ALL results by eventName to check if ALL payloads for each event are valid
        event_payloads = defaultdict(list)
        for r in results:
            event_payloads[r['eventName']].append(r['validationStatus'])
        
        # Only include events where ALL payloads are valid
        fully_valid_events = [
            event for event, statuses in event_payloads.items()
            if all(status == 'Valid' for status in statuses)
        ]
        
        app.logger.info(f'Fully valid events: {fully_valid_events}')
        
        # Include ALL events in the report (both valid and invalid)
        all_events = list(event_payloads.keys())
        app.logger.info(f'All events: {all_events}')
        
        # Group by eventName to get all events
        event_groups = {}
        for result in results:
            event_name = result['eventName']
            if event_name not in event_groups:
                event_groups[event_name] = []
            event_groups[event_name].append(result)
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output, delimiter='\t')  # Use tab delimiter as shown in example
        
        # Write header
        writer.writerow(['eventName', 'eventPayload', 'dataType', 'Logs'])
        
        # Write data rows for all events
        for event_name in all_events:
            event_results = event_groups.get(event_name, [])
            
            # Check if this event is fully valid
            is_fully_valid = event_name in fully_valid_events
            
            # Get the original log entry for this event
            log_entry = logs_data.get(event_name, '')
            
            # Write first row with event name and first field
            if event_results:
                first_result = event_results[0]
                
                # Determine what to put in the Logs column
                if is_fully_valid:
                    logs_content = log_entry if log_entry else ""
                else:
                    logs_content = "need to validate further"
                
                writer.writerow([
                    first_result['eventName'],
                    first_result['key'],
                    first_result['expectedType'],
                    logs_content
                ])
                
                # Write remaining rows for this event (without event name and log entry)
                for result in event_results[1:]:
                    writer.writerow([
                        "",  # Empty eventName for subsequent rows
                        result['key'],
                        result['expectedType'],
                        ""  # Empty Logs for subsequent rows
                    ])
        
        # Create response
        output.seek(0)
        app.logger.info('Valid events CSV file generated successfully')
        return Response(
            output,
            mimetype='text/csv',
            headers={
                'Content-Disposition': 'attachment; filename=valid_events_report.csv',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            }
        )
    except Exception as e:
        app.logger.error(f'Error in download valid events endpoint: {str(e)}')
        return jsonify({'error': str(e)}), 500

# ==================== FCM Push Notification Endpoints ====================

# Global FCM Service instance
fcm_service = None

@app.route('/validate-fcm-credentials', methods=['POST', 'OPTIONS'])
def validate_fcm_credentials():
    """Validate and store FCM credentials server-side"""
    if request.method == 'OPTIONS':
        return '', 200
    
    global fcm_service, stored_fcm_credentials
    
    try:
        data = request.get_json()
        credentials_json = data.get('credentials', '')
        
        if not credentials_json:
            return jsonify({"valid": False, "message": "No credentials provided"}), 400
        
        # Parse to validate it's valid JSON
        try:
            creds_obj = json.loads(credentials_json)
            if not creds_obj.get('private_key'):
                return jsonify({"valid": False, "message": "Invalid Firebase credentials format"}), 400
        except json.JSONDecodeError:
            return jsonify({"valid": False, "message": "Credentials must be valid JSON"}), 400
        
        # Save credentials to temporary file for validation
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(credentials_json)
            temp_creds_path = f.name
        
        # Initialize FCM service to validate
        from fcm_service import FCMService
        if fcm_service is None:
            fcm_service = FCMService()
        
        success, message = fcm_service.initialize(temp_creds_path)
        
        if success:
            # Clean up temp file
            try:
                os.remove(temp_creds_path)
            except:
                pass
            
            # Store credentials server-side for later use
            stored_fcm_credentials = credentials_json
            
            app.logger.info("FCM credentials validated and stored server-side")
            return jsonify({"valid": True, "message": "Credentials validated and stored"}), 200
        else:
            try:
                os.remove(temp_creds_path)
            except:
                pass
            return jsonify({"valid": False, "message": message}), 400
            
    except Exception as e:
        app.logger.error(f'Error validating FCM credentials: {str(e)}')
        return jsonify({"valid": False, "message": str(e)}), 500

@app.route('/send-push-notification', methods=['POST', 'OPTIONS'])
def send_push_notification():
    """Send push notification via FCM using stored credentials"""
    if request.method == 'OPTIONS':
        return '', 200
    
    global fcm_service, stored_fcm_credentials
    
    try:
        data = request.get_json()
        
        template_type = data.get('template_type')
        fcm_token = data.get('fcm_token')
        deeplink = data.get('deeplink', '')
        image_link = data.get('image_link', '')
        custom_payload_str = data.get('custom_payload', '')
        
        # Validate input
        if not template_type or not fcm_token:
            return jsonify({"success": False, "error": "Missing required fields"}), 400
        
        # Use stored credentials
        if not stored_fcm_credentials:
            return jsonify({"success": False, "error": "Firebase credentials not loaded. Please upload credentials file first."}), 400
        
        # Parse custom payload if provided
        custom_payload = {}
        if custom_payload_str:
            try:
                custom_payload = json.loads(custom_payload_str)
            except json.JSONDecodeError:
                return jsonify({"success": False, "error": "Invalid JSON in custom payload"}), 400
        
        # Initialize or reinitialize FCM service with stored credentials
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(stored_fcm_credentials)
            temp_creds_path = f.name
        
        # Initialize FCM service
        from fcm_service import FCMService
        fcm_service = FCMService()
        
        success, message = fcm_service.initialize(temp_creds_path)
        if not success:
            return jsonify({"success": False, "error": f"Failed to initialize FCM: {message}"}), 400
        
        # Import template factory
        from fcm_service import FCMTemplateFactory
        
        # Create payload based on template type
        if template_type == 'rating':
            payload = FCMTemplateFactory.create_rating_template(deeplink, custom_payload, image_link)
        elif template_type == 'simple':
            title = data.get('title', 'Simple Notification')
            message = data.get('message', '')
            payload = FCMTemplateFactory.create_simple_template(title, message, deeplink, custom_payload, image_link)
        else:
            return jsonify({"success": False, "error": "Unknown template type"}), 400
        
        # Send notification
        success, result = fcm_service.send_notification(fcm_token, payload, template_type)
        
        if success:
            log_validation_event('push_notification_sent', {
                'template': template_type,
                'device': fcm_token[:20] + '...',
                'message_id': result,
                'timestamp': datetime.now().isoformat()
            })
            
            return jsonify({
                "success": True,
                "message_id": result,
                "template_type": template_type,
                "device_token": fcm_token,
                "status": "Sent Successfully",
                "status_color": "bg-success",
                "timestamp": datetime.now().isoformat(),
                "message": "Push notification sent successfully"
            }), 200
        else:
            log_validation_event('push_notification_failed', {
                'template': template_type,
                'device': fcm_token[:20] + '...',
                'error': result,
                'timestamp': datetime.now().isoformat()
            })
            
            return jsonify({
                "success": False,
                "status": "Failed",
                "status_color": "bg-danger",
                "timestamp": datetime.now().isoformat(),
                "error": result
            }), 400
            
    except Exception as e:
        app.logger.error(f'Error sending push notification: {str(e)}')
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=True)